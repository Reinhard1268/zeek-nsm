#!/usr/bin/env python3
# =============================================================
# File: beaconing_detector.py
# =============================================================
"""
Beacon Detector — reads Zeek conn.log and identifies C2 beaconing
by statistical analysis of connection intervals per src->dst pair.

Usage:
  python3 beaconing_detector.py --input conn.log --output results/
  python3 beaconing_detector.py --input conn.log --threshold 0.2 --min-connections 15
  python3 beaconing_detector.py --elastic --index zeek-* --timeframe 24
"""

import argparse
import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import numpy as np
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()


# ─── Zeek Log Parser ──────────────────────────────────────────────────────────

def parse_zeek_conn_log(filepath: str) -> pd.DataFrame:
    """Parse Zeek conn.log (TSV format) into a DataFrame."""
    fields = []
    types  = []
    rows   = []

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
                parts = line.split("\t")
                if len(parts) == len(fields):
                    rows.append(parts)

    if not fields:
        raise ValueError(f"No #fields header found in {filepath}")

    df = pd.DataFrame(rows, columns=fields)

    # Convert timestamp
    if "ts" in df.columns:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        df.dropna(subset=["ts"], inplace=True)
        df["datetime"] = pd.to_datetime(df["ts"], unit="s", utc=True)

    # Convert numeric columns
    for col in ["orig_bytes", "resp_bytes", "duration", "orig_pkts", "resp_pkts"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    return df


def load_from_elastic(index: str, timeframe_hours: int) -> pd.DataFrame:
    """Load conn data from Elasticsearch (requires ELASTIC_HOST env var)."""
    try:
        from elasticsearch import Elasticsearch
        from dotenv import load_dotenv
        load_dotenv()

        host = os.getenv("ELASTIC_HOST", "http://localhost:9200")
        user = os.getenv("ELASTIC_USERNAME", "elastic")
        pwd  = os.getenv("ELASTIC_PASSWORD", "")

        es = Elasticsearch(host, basic_auth=(user, pwd), verify_certs=False)
        since = datetime.utcnow() - timedelta(hours=timeframe_hours)

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                        {"exists": {"field": "source.ip"}},
                        {"exists": {"field": "destination.ip"}}
                    ]
                }
            },
            "size": 10000,
            "_source": ["@timestamp", "source.ip", "source.port",
                        "destination.ip", "destination.port",
                        "network.transport", "source.bytes", "destination.bytes",
                        "event.duration"]
        }

        resp = es.search(index=index, body=query)
        hits = resp["hits"]["hits"]

        rows = []
        for h in hits:
            s = h["_source"]
            rows.append({
                "ts":         pd.to_datetime(s.get("@timestamp")).timestamp(),
                "id.orig_h":  s.get("source.ip", ""),
                "id.resp_h":  s.get("destination.ip", ""),
                "id.resp_p":  str(s.get("destination.port", "")),
                "proto":      s.get("network.transport", ""),
                "orig_bytes": s.get("source.bytes", 0),
                "resp_bytes": s.get("destination.bytes", 0),
                "duration":   s.get("event.duration", 0),
            })

        df = pd.DataFrame(rows)
        df["datetime"] = pd.to_datetime(df["ts"], unit="s", utc=True)
        return df

    except ImportError:
        console.print("[red]elasticsearch-py not installed. Run: pip install elasticsearch[/red]")
        sys.exit(1)


# ─── Beacon Analysis ──────────────────────────────────────────────────────────

def compute_beacon_score(timestamps: list) -> dict:
    """
    Compute beaconing statistics for a sorted list of Unix timestamps.
    Returns a dict with interval stats and confidence score.
    """
    if len(timestamps) < 2:
        return None

    intervals = np.diff(sorted(timestamps))
    if len(intervals) == 0:
        return None

    mean_iv = float(np.mean(intervals))
    std_iv  = float(np.std(intervals))
    cv      = std_iv / mean_iv if mean_iv > 0 else 999.0
    median  = float(np.median(intervals))
    mad     = float(np.median(np.abs(intervals - median)))  # Median Absolute Deviation
    jitter  = mad / median if median > 0 else 999.0

    # Confidence: penalize high CV, reward high count
    base_conf = max(0.0, 1.0 - cv) * 100.0
    count_bonus = min(10.0, (len(timestamps) - 10) * 0.5)
    confidence = min(100.0, base_conf + count_bonus)

    return {
        "connection_count": len(timestamps),
        "interval_mean":    round(mean_iv, 3),
        "interval_std":     round(std_iv, 3),
        "interval_median":  round(median, 3),
        "interval_mad":     round(mad, 3),
        "cv":               round(cv, 4),
        "jitter_score":     round(jitter, 4),
        "confidence":       round(confidence, 1),
        "first_seen":       datetime.utcfromtimestamp(min(timestamps)).isoformat(),
        "last_seen":        datetime.utcfromtimestamp(max(timestamps)).isoformat(),
    }


def detect_beacons(df: pd.DataFrame, cv_threshold: float, min_connections: int,
                   min_interval: float = 5.0, max_interval: float = 7200.0) -> list:
    """
    Group connections by src->dst->port and score each group for beaconing.
    Returns a sorted list of suspected beacons.
    """
    # Determine column names (Zeek raw vs ECS-mapped)
    src_col  = "id.orig_h" if "id.orig_h" in df.columns else "source.ip"
    dst_col  = "id.resp_h" if "id.resp_h" in df.columns else "destination.ip"
    port_col = "id.resp_p" if "id.resp_p" in df.columns else "destination.port"

    groups = df.groupby([src_col, dst_col, port_col])
    beacons = []

    for (src, dst, port), group in track(groups, description="Analyzing connections..."):
        timestamps = sorted(group["ts"].tolist())
        if len(timestamps) < min_connections:
            continue

        stats = compute_beacon_score(timestamps)
        if stats is None:
            continue

        # Filter by interval range
        if stats["interval_mean"] < min_interval or stats["interval_mean"] > max_interval:
            continue

        # Apply CV threshold
        if stats["cv"] > cv_threshold:
            continue

        beacons.append({
            "src_ip":           src,
            "dst_ip":           dst,
            "dst_port":         port,
            **stats
        })

    # Sort by confidence descending
    beacons.sort(key=lambda x: x["confidence"], reverse=True)
    return beacons


# ─── Reporting ────────────────────────────────────────────────────────────────

def print_results_table(beacons: list):
    """Print results as a Rich table."""
    table = Table(title="🎯 Suspected C2 Beacons", show_lines=True)
    table.add_column("Rank",        style="bold white")
    table.add_column("Source IP",   style="cyan")
    table.add_column("Destination", style="red")
    table.add_column("Port",        style="yellow")
    table.add_column("Count",       style="green")
    table.add_column("Avg Interval",style="blue")
    table.add_column("CV (jitter)", style="magenta")
    table.add_column("Confidence",  style="bold green")

    for i, b in enumerate(beacons[:25], 1):
        conf = b["confidence"]
        conf_str = f"{conf:.1f}%"
        if conf >= 90:
            conf_str = f"[bold red]{conf_str}[/bold red]"
        elif conf >= 70:
            conf_str = f"[yellow]{conf_str}[/yellow]"

        table.add_row(
            str(i),
            b["src_ip"],
            b["dst_ip"],
            str(b["dst_port"]),
            str(b["connection_count"]),
            f"{b['interval_mean']:.1f}s",
            f"{b['cv']:.4f}",
            conf_str
        )

    console.print(table)


def save_json(beacons: list, output_dir: str):
    """Save results to JSON."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_file = os.path.join(output_dir, "beacon-results.json")
    with open(out_file, "w") as f:
        json.dump(beacons, f, indent=2, default=str)
    console.print(f"[green]JSON saved:[/green] {out_file}")


def save_markdown_report(beacons: list, output_dir: str):
    """Save a Markdown analysis report."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_file = os.path.join(output_dir, "beacon-analysis-results.md")

    with open(out_file, "w") as f:
        f.write("# Beacon Detection Analysis Results\n\n")
        f.write(f"**Generated:** {datetime.utcnow().isoformat()} UTC\n")
        f.write(f"**Total Suspected Beacons:** {len(beacons)}\n\n")
        f.write("---\n\n")

        if not beacons:
            f.write("No beaconing activity detected.\n")
            return

        f.write("## Top Suspected Beacons\n\n")
        f.write("| Rank | Source IP | Destination IP | Port | Count | Avg Interval | CV | Confidence |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")

        for i, b in enumerate(beacons[:20], 1):
            f.write(f"| {i} | {b['src_ip']} | {b['dst_ip']} | {b['dst_port']} | "
                    f"{b['connection_count']} | {b['interval_mean']:.1f}s | "
                    f"{b['cv']:.4f} | **{b['confidence']:.1f}%** |\n")

        f.write("\n\n## Detailed Findings\n\n")
        for i, b in enumerate(beacons[:10], 1):
            f.write(f"### {i}. {b['src_ip']} → {b['dst_ip']}:{b['dst_port']}\n\n")
            f.write(f"- **Connections:** {b['connection_count']}\n")
            f.write(f"- **Average Interval:** {b['interval_mean']:.2f} seconds "
                    f"({b['interval_mean']/60:.1f} minutes)\n")
            f.write(f"- **Std Deviation:** {b['interval_std']:.2f}s\n")
            f.write(f"- **Coefficient of Variation:** {b['cv']:.4f}\n")
            f.write(f"- **Confidence Score:** {b['confidence']:.1f}%\n")
            f.write(f"- **First Seen:** {b['first_seen']}\n")
            f.write(f"- **Last Seen:** {b['last_seen']}\n\n")

    console.print(f"[green]Markdown report saved:[/green] {out_file}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Zeek conn.log beacon detector",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--input",           default="conn.log",
                        help="Path to Zeek conn.log (default: conn.log)")
    parser.add_argument("--elastic",         action="store_true",
                        help="Load from Elasticsearch instead of file")
    parser.add_argument("--index",           default="zeek-*",
                        help="Elastic index pattern (default: zeek-*)")
    parser.add_argument("--timeframe",       type=int, default=24,
                        help="Hours to look back in Elastic (default: 24)")
    parser.add_argument("--threshold",       type=float, default=0.3,
                        help="Max CV (jitter) to flag as beacon (default: 0.3)")
    parser.add_argument("--min-connections", type=int,   default=10,
                        help="Minimum connections to analyze (default: 10)")
    parser.add_argument("--min-interval",    type=float, default=5.0,
                        help="Minimum average interval in seconds (default: 5)")
    parser.add_argument("--max-interval",    type=float, default=7200.0,
                        help="Maximum average interval in seconds (default: 7200)")
    parser.add_argument("--output",          default="results/",
                        help="Output directory for reports (default: results/)")
    args = parser.parse_args()

    console.print("[bold cyan]╔══════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║   Zeek Beacon Detector v1.0      ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════╝[/bold cyan]\n")

    # Load data
    if args.elastic:
        console.print(f"[blue]Loading from Elasticsearch:[/blue] {args.index} (last {args.timeframe}h)")
        df = load_from_elastic(args.index, args.timeframe)
    else:
        if not os.path.exists(args.input):
            console.print(f"[red]File not found:[/red] {args.input}")
            sys.exit(1)
        console.print(f"[blue]Loading:[/blue] {args.input}")
        df = parse_zeek_conn_log(args.input)

    console.print(f"[green]Loaded {len(df):,} connections[/green]\n")

    # Detect beacons
    console.print(f"[yellow]Parameters:[/yellow] threshold={args.threshold}, "
                  f"min_connections={args.min_connections}, "
                  f"interval=[{args.min_interval}s, {args.max_interval}s]\n")

    beacons = detect_beacons(
        df,
        cv_threshold    = args.threshold,
        min_connections = args.min_connections,
        min_interval    = args.min_interval,
        max_interval    = args.max_interval
    )

    console.print(f"\n[bold]Found [red]{len(beacons)}[/red] suspected beacon(s)[/bold]\n")

    if beacons:
        print_results_table(beacons)
        save_json(beacons, args.output)
        save_markdown_report(beacons, args.output)
    else:
        console.print("[green]No beaconing activity detected with current thresholds.[/green]")


if __name__ == "__main__":
    main()
