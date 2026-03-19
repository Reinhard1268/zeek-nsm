#!/usr/bin/env python3
# =============================================================
# File: dga_detector.py
# =============================================================
"""
DGA Detector — reads Zeek dns.log and identifies Domain Generation
Algorithm (DGA) domains using ML (RandomForest) + statistical features.

Usage:
  python3 dga_detector.py --input dns.log
  python3 dga_detector.py --input dns.log --model dga_model.pkl --threshold 0.7
  python3 dga_detector.py --input dns.log --train --legit-domains domain-wordlists/legitimate-domains.txt
                                                  --dga-domains domain-wordlists/known-dga-domains.txt
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from rich.console import Console
from rich.table import Table
from rich.progress import track
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

console = Console()

# ─── Feature Extraction ───────────────────────────────────────────────────────

ENGLISH_LETTER_FREQ = {
    'a': 0.0817, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
    'f': 0.0223, 'g': 0.0202, 'h': 0.0609, 'i': 0.0697, 'j': 0.0015,
    'k': 0.0077, 'l': 0.0403, 'm': 0.0241, 'n': 0.0675, 'o': 0.0751,
    'p': 0.0193, 'q': 0.0010, 'r': 0.0599, 's': 0.0633, 't': 0.0906,
    'u': 0.0276, 'v': 0.0098, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
    'z': 0.0007
}

VOWELS = set("aeiou")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def consonant_vowel_ratio(s: str) -> float:
    s = s.lower()
    vowels = sum(1 for c in s if c in VOWELS)
    consonants = sum(1 for c in s if c.isalpha() and c not in VOWELS)
    total = vowels + consonants
    if total == 0:
        return 0.0
    return consonants / total


def ngram_score(s: str, n: int = 2) -> float:
    """
    Compare n-gram frequency to typical English text.
    Lower score = more English-like.
    """
    s = s.lower()
    if len(s) < n:
        return 1.0
    ngrams = [s[i:i+n] for i in range(len(s) - n + 1)]
    # Simple heuristic: ratio of digit-containing ngrams
    non_alpha_count = sum(1 for ng in ngrams if not ng.isalpha())
    return non_alpha_count / len(ngrams) if ngrams else 0.0


def digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)


def hex_ratio(s: str) -> float:
    """Ratio of hex-compatible characters."""
    if not s:
        return 0.0
    hex_chars = set("0123456789abcdef")
    return sum(1 for c in s.lower() if c in hex_chars) / len(s)


def char_frequency_deviation(s: str) -> float:
    """
    Compare character frequencies to English.
    High deviation = less English-like = DGA indicator.
    """
    s = s.lower()
    if not s:
        return 0.0
    freq = Counter(c for c in s if c.isalpha())
    total = sum(freq.values())
    if total == 0:
        return 0.0
    deviation = 0.0
    for char, expected_freq in ENGLISH_LETTER_FREQ.items():
        observed = freq.get(char, 0) / total
        deviation += abs(observed - expected_freq)
    return deviation


def get_subdomain(fqdn: str) -> str:
    """Extract registrable domain label (subdomain part)."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) > 2:
        return parts[0]
    elif len(parts) == 2:
        return parts[0]
    return fqdn


def extract_features(domain: str) -> dict:
    """Extract all ML features from a domain name."""
    sub = get_subdomain(domain)
    full = domain.rstrip(".")

    return {
        "domain_length":        len(full),
        "subdomain_length":     len(sub),
        "entropy":              shannon_entropy(sub),
        "cv_ratio":             consonant_vowel_ratio(sub),
        "digit_ratio":          digit_ratio(sub),
        "hex_ratio":            hex_ratio(sub),
        "ngram_score":          ngram_score(sub, n=2),
        "char_freq_deviation":  char_frequency_deviation(sub),
        "dot_count":            full.count("."),
        "hyphen_count":         full.count("-"),
        "has_digits":           int(any(c.isdigit() for c in sub)),
        "max_run_length":       max((len(m.group()) for m in re.finditer(r'(.)\1+', sub)), default=0),
        "unique_char_ratio":    len(set(sub)) / len(sub) if sub else 0,
    }


# ─── Zeek DNS Log Parser ──────────────────────────────────────────────────────

def parse_zeek_dns_log(filepath: str) -> pd.DataFrame:
    fields = []
    rows   = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                parts = line.split("\t")
                if len(parts) == len(fields):
                    rows.append(parts)

    if not fields:
        raise ValueError("No #fields header found")

    df = pd.DataFrame(rows, columns=fields)
    df = df[df["query"].notna() & (df["query"] != "-")]
    return df


# ─── Model Training ───────────────────────────────────────────────────────────

def train_model(legit_path: str, dga_path: str, model_path: str = "dga_model.pkl"):
    """Train a RandomForest classifier on labeled domain lists."""
    console.print("[blue]Loading training data...[/blue]")

    legit_domains = Path(legit_path).read_text().strip().splitlines()
    dga_domains   = Path(dga_path).read_text().strip().splitlines()

    console.print(f"  Legitimate: {len(legit_domains):,} domains")
    console.print(f"  DGA:        {len(dga_domains):,} domains")

    records = []
    for d in track(legit_domains, description="Extracting legit features..."):
        d = d.strip()
        if d:
            feat = extract_features(d)
            feat["label"] = 0
            feat["domain"] = d
            records.append(feat)

    for d in track(dga_domains, description="Extracting DGA features..."):
        d = d.strip()
        if d:
            feat = extract_features(d)
            feat["label"] = 1
            feat["domain"] = d
            records.append(feat)

    df = pd.DataFrame(records)
    feature_cols = [c for c in df.columns if c not in ["label", "domain"]]

    X = df[feature_cols].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    console.print("\n[green]Model Training Complete[/green]")
    console.print(classification_report(y_test, y_pred, target_names=["Legitimate", "DGA"]))
    console.print(f"ROC AUC Score: {roc_auc_score(y_test, y_prob):.4f}")

    # Feature importances
    importances = sorted(zip(feature_cols, clf.feature_importances_), key=lambda x: -x[1])
    console.print("\nTop Feature Importances:")
    for feat, imp in importances[:5]:
        console.print(f"  {feat}: {imp:.4f}")

    # Save model + feature column names
    joblib.dump({"model": clf, "features": feature_cols}, model_path)
    console.print(f"\n[green]Model saved:[/green] {model_path}")

    return clf, feature_cols


# ─── Detection ────────────────────────────────────────────────────────────────

def detect_dga(dns_df: pd.DataFrame, model_path: str, threshold: float) -> pd.DataFrame:
    """Score all unique queried domains against the DGA model."""
    if not os.path.exists(model_path):
        console.print(f"[red]Model not found: {model_path}[/red]")
        console.print("[yellow]Run with --train to build model first.[/yellow]")
        sys.exit(1)

    saved = joblib.load(model_path)
    clf   = saved["model"]
    feature_cols = saved["features"]

    # Unique domains only
    query_col = "query" if "query" in dns_df.columns else "dns.question.name"
    domains = dns_df[query_col].dropna().unique()

    console.print(f"[blue]Scoring {len(domains):,} unique domains...[/blue]")

    records = []
    for d in track(domains, description="Scoring domains..."):
        d = str(d).strip().lower()
        if not d or d == "-":
            continue
        feat = extract_features(d)
        records.append({"domain": d, **feat})

    feat_df = pd.DataFrame(records)
    X = feat_df[[c for c in feature_cols if c in feat_df.columns]].fillna(0).values

    probs = clf.predict_proba(X)[:, 1]
    feat_df["dga_probability"] = probs
    feat_df["is_dga"] = probs >= threshold

    # Merge with query counts
    query_counts = dns_df.groupby(query_col).size().reset_index(name="query_count")
    query_counts.rename(columns={query_col: "domain"}, inplace=True)
    feat_df = feat_df.merge(query_counts, on="domain", how="left")

    suspects = feat_df[feat_df["is_dga"]].sort_values("dga_probability", ascending=False)
    return suspects


# ─── Reporting ────────────────────────────────────────────────────────────────

def print_dga_table(suspects: pd.DataFrame):
    table = Table(title="🔍 Suspected DGA Domains", show_lines=True)
    table.add_column("Rank",        style="bold white")
    table.add_column("Domain",      style="cyan", max_width=50)
    table.add_column("DGA Prob",    style="red")
    table.add_column("Entropy",     style="yellow")
    table.add_column("CV Ratio",    style="blue")
    table.add_column("Digit Ratio", style="magenta")
    table.add_column("Query Count", style="green")

    for i, (_, row) in enumerate(suspects.head(30).iterrows(), 1):
        table.add_row(
            str(i),
            str(row["domain"])[:50],
            f"{row['dga_probability']:.3f}",
            f"{row.get('entropy', 0):.2f}",
            f"{row.get('cv_ratio', 0):.2f}",
            f"{row.get('digit_ratio', 0):.2f}",
            str(int(row.get("query_count", 0)))
        )
    console.print(table)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Zeek DNS DGA Detector")
    parser.add_argument("--input",          default="dns.log",
                        help="Path to Zeek dns.log")
    parser.add_argument("--threshold",      type=float, default=0.65,
                        help="DGA probability threshold (default: 0.65)")
    parser.add_argument("--model",          default="dga_model.pkl",
                        help="Path to saved model (default: dga_model.pkl)")
    parser.add_argument("--output",         default="dga-results/",
                        help="Output directory")
    parser.add_argument("--train",          action="store_true",
                        help="Train model before detection")
    parser.add_argument("--legit-domains",  default="domain-wordlists/legitimate-domains.txt")
    parser.add_argument("--dga-domains",    default="domain-wordlists/known-dga-domains.txt")
    args = parser.parse_args()

    console.print("[bold cyan]╔══════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║   Zeek DGA Detector v1.0     ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════╝[/bold cyan]\n")

    if args.train:
        train_model(args.legit_domains, args.dga_domains, args.model)

    if not os.path.exists(args.input):
        console.print(f"[red]File not found:[/red] {args.input}")
        sys.exit(1)

    console.print(f"[blue]Loading:[/blue] {args.input}")
    dns_df = parse_zeek_dns_log(args.input)
    console.print(f"[green]Loaded {len(dns_df):,} DNS records[/green]\n")

    suspects = detect_dga(dns_df, args.model, args.threshold)
    console.print(f"\n[bold]Found [red]{len(suspects)}[/red] suspected DGA domain(s)[/bold]\n")

    if not suspects.empty:
        print_dga_table(suspects)
        Path(args.output).mkdir(parents=True, exist_ok=True)
        out_json = os.path.join(args.output, "dga-results.json")
        suspects.to_json(out_json, orient="records", indent=2)
        console.print(f"[green]Results saved:[/green] {out_json}")
    else:
        console.print("[green]No DGA domains detected.[/green]")


if __name__ == "__main__":
    main()
