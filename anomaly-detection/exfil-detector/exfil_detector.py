#!/usr/bin/env python3
# =============================================================
# File: exfil_detector.py
# =============================================================
"""
Exfiltration Detector — reads Zeek conn.log, http.log, and dns.log
to detect volume-based, DNS-based, and HTTP-based data exfiltration.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

import pandas as pd
import numpy as np
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from dotenv import load_dotenv

load_dotenv()
console = Console()

# ─────────────────────────────────────────────
# Zeek log parser helpers
# ─────────────────────────────────────────────

def parse_zeek_log(filepath: str) -> pd.DataFrame:
    """Parse a Zeek TSV log file into a DataFrame."""
    if not os.path.exists(filepath):
        console.print(f"[yellow]Warning: {filepath} not found, skipping.[/yellow]")
        return pd.DataFrame()

    fields, types = [], []
    rows = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#types"):
                types = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                values = line.split("\t")
                if len(values) == len(fields):
                    rows.append(values)

    if not fields or not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows, columns=fields)

    # Type coercions
    for i, (col, t) in enumerate(zip(fields, types)):
        if t in ("time", "interval"):
            df[col] = pd.to_numeric(df[col], errors="coerce")
        elif t in ("count", "int", "port"):
            df[col] = pd.to_numeric(df[col], errors="coerce")
        elif t in ("double",):
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace Zeek unset marker
    df.replace("-", pd.NA, inplace=True)

    # Convert ts to datetime
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")

    return df


# ─────────────────────────────────────────────
# Volume-based exfiltration
# ─────────────────────────────────────────────

def detect_volume_exfil(conn_df: pd.DataFrame, threshold_mb: float, local_nets: list) -> list:
    """Detect high-volume outbound data transfers per src→dst per hour."""
    alerts = []
    if conn_df.empty:
        return alerts

    required = {"ts", "id.orig_h", "id.resp_h", "orig_bytes"}
    if not required.issubset(conn_df.columns):
        return alerts

    df = conn_df.dropna(subset=["id.orig_h", "id.resp_h", "orig_bytes"]).copy()
    df["orig_bytes"] = pd.to_numeric(df["orig_bytes"], errors="coerce").fillna(0)

    # Filter: only outbound to external IPs
    def is_local(ip: str) -> bool:
        for net in local_nets:
            if ip.startswith(net):
                return True
        return False

    df["is_local_dst"] = df["id.resp_h"].apply(is_local)
    df = df[~df["is_local_dst"]]

    # Group by src → dst, hourly buckets
    df["hour"] = df["ts"].dt.floor("1h")
    grouped = df.groupby(["id.orig_h", "id.resp_h", "hour"])["orig_bytes"].sum().reset_index()
    grouped.columns = ["src", "dst", "hour", "bytes_out"]
    grouped["mb_out"] = grouped["bytes_out"] / 1_048_576

    suspects = grouped[grouped["mb_out"] >= threshold_mb].copy()
    suspects = suspects.sort_values("mb_out", ascending=False)

    for _, row in suspects.iterrows():
        alerts.append({
            "type":       "VOLUME_EXFIL",
            "severity":   "HIGH",
            "src":        row["src"],
            "dst":        row["dst"],
            "bytes_out":  int(row["bytes_out"]),
            "mb_out":     round(row["mb_out"], 2),
            "hour":       str(row["hour"]),
            "detail":     f"{row['mb_out']:.1f} MB sent from {row['src']} → {row['dst']} in 1 hour"
        })

    return alerts


# ─────────────────────────────────────────────
# DNS exfiltration detection
# ─────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    n = len(s)
    for count in freq.values():
        p = count / n
        ent -= p * np.log2(p)
    return round(ent, 3)


def detect_dns_exfil(dns_df: pd.DataFrame,
                     nxdomain_threshold: float = 0.7,
                     subdomain_len_threshold: int = 40,
                     query_rate_threshold: int = 100,
                     min_queries: int = 20) -> list:
    """Detect DNS tunneling and subdomain-based exfiltration."""
    alerts = []
    if dns_df.empty:
        return alerts

    if "query" not in dns_df.columns:
        return alerts

    df = dns_df.dropna(subset=["query"]).copy()

    # ── High NXDOMAIN ratio ──
    if "rcode_name" in df.columns and "id.orig_h" in df.columns:
        src_groups = df.groupby("id.orig_h")
        for src, grp in src_groups:
            if len(grp) < min_queries:
                continue
            nx_count = (grp["rcode_name"] == "NXDOMAIN").sum()
            ratio = nx_count / len(grp)
            if ratio >= nxdomain_threshold:
                alerts.append({
                    "type":     "DNS_HIGH_NXDOMAIN",
                    "severity": "HIGH",
                    "src":      src,
                    "detail":   f"NXDOMAIN ratio {ratio*100:.1f}% ({nx_count}/{len(grp)}) from {src}"
                })

    # ── Long subdomains (encoding indicator) ──
    def get_first_label(query: str) -> str:
        parts = query.split(".")
        return parts[0] if parts else ""

    df["first_label"] = df["query"].apply(get_first_label)
    df["label_len"] = df["first_label"].str.len()
    df["entropy"] = df["first_label"].apply(shannon_entropy)

    long_sub = df[df["label_len"] >= subdomain_len_threshold]
    for _, row in long_sub.iterrows():
        src = row.get("id.orig_h", "unknown")
        alerts.append({
            "type":     "DNS_LONG_SUBDOMAIN",
            "severity": "HIGH",
            "src":      src,
            "query":    row["query"],
            "detail":   f"Long subdomain ({row['label_len']} chars, entropy={row['entropy']:.2f}): {row['query']}"
        })

    # ── High entropy domains ──
    high_entropy = df[(df["entropy"] > 3.5) & (df["label_len"] > 10)]
    for _, row in high_entropy.iterrows():
        src = row.get("id.orig_h", "unknown")
        alerts.append({
            "type":     "DNS_HIGH_ENTROPY",
            "severity": "MEDIUM",
            "src":      src,
            "query":    row["query"],
            "detail":   f"High entropy domain (entropy={row['entropy']:.2f}): {row['query']}"
        })

    # ── High query rate to single domain ──
    if "ts" in df.columns and "id.orig_h" in df.columns:
        df["base_domain"] = df["query"].apply(
            lambda q: ".".join(q.split(".")[-2:]) if len(q.split(".")) >= 2 else q
        )
        df["minute"] = df["ts"].dt.floor("1min")
        rate_group = df.groupby(["id.orig_h", "base_domain", "minute"]).size().reset_index(name="count")
        high_rate = rate_group[rate_group["count"] >= query_rate_threshold]
        for _, row in high_rate.iterrows():
            alerts.append({
                "type":     "DNS_HIGH_QUERY_RATE",
                "severity": "HIGH",
                "src":      row["id.orig_h"],
                "domain":   row["base_domain"],
                "detail":   f"{row['count']} queries/min from {row['id.orig_h']} to {row['base_domain']}"
            })

    return alerts


# ─────────────────────────────────────────────
# HTTP exfiltration detection
# ─────────────────────────────────────────────

def detect_http_exfil(http_df: pd.DataFrame,
                      post_threshold_bytes: int = 5_242_880,
                      local_nets: list = None) -> list:
    """Detect large HTTP POST bodies and unusual response ratios."""
    alerts = []
    if http_df.empty:
        return alerts

    local_nets = local_nets or ["10.", "172.16.", "192.168."]

    def is_local(ip: str) -> bool:
        return any(ip.startswith(n) for n in local_nets)

    # Large POST bodies
    if "method" in http_df.columns and "request_body_len" in http_df.columns:
        http_df["request_body_len"] = pd.to_numeric(
            http_df.get("request_body_len", 0), errors="coerce").fillna(0)

        posts = http_df[http_df["method"].isin(["POST", "PUT"])].copy()
        large = posts[posts["request_body_len"] >= post_threshold_bytes]

        for _, row in large.iterrows():
            src = row.get("id.orig_h", "unknown")
            dst = row.get("id.resp_h", "unknown")
            if is_local(dst):
                continue
            mb = row["request_body_len"] / 1_048_576
            alerts.append({
                "type":     "HTTP_LARGE_POST",
                "severity": "HIGH",
                "src":      src,
                "dst":      dst,
                "bytes":    int(row["request_body_len"]),
                "mb":       round(mb, 2),
                "uri":      row.get("uri", "-"),
                "detail":   f"Large HTTP {row['method']} from {src} → {dst}{row.get('uri','')} ({mb:.1f} MB)"
            })

    return alerts


# ─────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────

def print_alerts(alerts: list) -> None:
    if not alerts:
        console.print("[green]No exfiltration indicators detected.[/green]")
        return

    table = Table(title=f"Exfiltration Alerts ({len(alerts)} total)", show_lines=True)
    table.add_column("Type",     style="bold red",    no_wrap=True)
    table.add_column("Severity", style="bold yellow", no_wrap=True)
    table.add_column("Source IP", style="cyan")
    table.add_column("Detail",   style="white", overflow="fold")

    for a in sorted(alerts, key=lambda x: x.get("severity", ""), reverse=True):
        table.add_row(
            a.get("type", "-"),
            a.get("severity", "-"),
            a.get("src", "-"),
            a.get("detail", "-")
        )

    console.print(table)


def save_results(alerts: list, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"exfil_alerts_{ts}.json")
    md_path   = os.path.join(output_dir, f"exfil_report_{ts}.md")

    with open(json_path, "w") as f:
        json.dump(alerts, f, indent=2, default=str)

    with open(md_path, "w") as f:
        f.write(f"# Exfiltration Detection Report\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}  \n")
        f.write(f"**Total Alerts:** {len(alerts)}\n\n")
        f.write("| # | Type | Severity | Source | Detail |\n")
        f.write("|---|------|----------|--------|--------|\n")
        for i, a in enumerate(alerts, 1):
            f.write(f"| {i} | {a.get('type','-')} | {a.get('severity','-')} "
                    f"| {a.get('src','-')} | {a.get('detail','-')} |\n")

    console.print(f"[green]Results saved:[/green] {json_path}")
    console.print(f"[green]Report saved:[/green]  {md_path}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Zeek Exfiltration Detector — detects volume, DNS, and HTTP exfil"
    )
    parser.add_argument("--input-dir",       default=".", help="Directory containing Zeek log files")
    parser.add_argument("--threshold-mb",    type=float, default=100.0,
                        help="Outbound volume threshold in MB per hour (default: 100)")
    parser.add_argument("--post-threshold",  type=int,   default=5_242_880,
                        help="HTTP POST body size threshold in bytes (default: 5MB)")
    parser.add_argument("--nxdomain-ratio",  type=float, default=0.7,
                        help="NXDOMAIN ratio threshold (default: 0.7)")
    parser.add_argument("--subdomain-len",   type=int,   default=40,
                        help="Subdomain length threshold (default: 40)")
    parser.add_argument("--query-rate",      type=int,   default=100,
                        help="DNS query rate threshold per minute (default: 100)")
    parser.add_argument("--output",          default="exfil-results",
                        help="Output directory for results")
    parser.add_argument("--local-nets",      default="10.,172.16.,192.168.",
                        help="Comma-separated local network prefixes")
    args = parser.parse_args()

    local_nets = [n.strip() for n in args.local_nets.split(",")]

    console.print(Panel.fit(
        "[bold red]Zeek Exfiltration Detector[/bold red]\n"
        f"Input dir: [cyan]{args.input_dir}[/cyan]  |  "
        f"Volume threshold: [yellow]{args.threshold_mb} MB[/yellow]  |  "
        f"DNS NXDOMAIN threshold: [yellow]{args.nxdomain_ratio*100:.0f}%[/yellow]",
        title="05-zeek-nsm"
    ))

    # Load logs
    conn_path = os.path.join(args.input_dir, "conn.log")
    http_path = os.path.join(args.input_dir, "http.log")
    dns_path  = os.path.join(args.input_dir, "dns.log")

    console.print("[bold]Loading Zeek logs...[/bold]")
    conn_df = parse_zeek_log(conn_path)
    http_df = parse_zeek_log(http_path)
    dns_df  = parse_zeek_log(dns_path)

    console.print(f"  conn.log: [cyan]{len(conn_df):,}[/cyan] rows")
    console.print(f"  http.log: [cyan]{len(http_df):,}[/cyan] rows")
    console.print(f"  dns.log:  [cyan]{len(dns_df):,}[/cyan] rows")

    all_alerts = []

    # Volume exfil
    console.print("\n[bold]Running volume exfil detection...[/bold]")
    vol_alerts = detect_volume_exfil(conn_df, args.threshold_mb, local_nets)
    console.print(f"  → [yellow]{len(vol_alerts)}[/yellow] volume exfil alerts")
    all_alerts.extend(vol_alerts)

    # DNS exfil
    console.print("[bold]Running DNS exfil detection...[/bold]")
    dns_alerts = detect_dns_exfil(
        dns_df,
        nxdomain_threshold=args.nxdomain_ratio,
        subdomain_len_threshold=args.subdomain_len,
        query_rate_threshold=args.query_rate
    )
    console.print(f"  → [yellow]{len(dns_alerts)}[/yellow] DNS exfil alerts")
    all_alerts.extend(dns_alerts)

    # HTTP exfil
    console.print("[bold]Running HTTP exfil detection...[/bold]")
    http_alerts = detect_http_exfil(http_df, args.post_threshold, local_nets)
    console.print(f"  → [yellow]{len(http_alerts)}[/yellow] HTTP exfil alerts")
    all_alerts.extend(http_alerts)

    console.print(f"\n[bold]Total alerts: [red]{len(all_alerts)}[/red][/bold]\n")

    print_alerts(all_alerts)
    save_results(all_alerts, args.output)


if __name__ == "__main__":
    main()
