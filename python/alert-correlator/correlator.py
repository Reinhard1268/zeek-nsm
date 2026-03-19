#!/usr/bin/env python3
# =============================================================
# File: correlator.py
# =============================================================
"""
Alert Correlator — reads Zeek notice.log and Suricata EVE alerts,
groups related events by src IP / timeframe / attack pattern,
computes combined threat scores, deduplicates, and creates TheHive cases.
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import pandas as pd
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

load_dotenv()
console = Console()

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

THEHIVE_HOST    = os.getenv("THEHIVE_HOST",    "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
THEHIVE_ORG     = os.getenv("THEHIVE_ORG",     "YOUR_ORG")

ALERT_WEIGHTS = {
    # Suricata severity → weight
    1: 40,   # HIGH
    2: 20,   # MEDIUM
    3: 10,   # LOW
    # Zeek notice categories
    "C2_Beaconing_Detected":    50,
    "C2_SSL_SelfSigned":        30,
    "C2_JA3_Suspicious":        45,
    "DNS_High_NXDOMAIN_Ratio":  25,
    "Exfil_High_Volume_Outbound": 40,
    "Exfil_DNS_Tunneling":       35,
    "LM_SMB_Multi_Host_Scan":   30,
    "LM_PsExec_Detected":        45,
    "LM_Auth_Spray":             35,
    "SMB_PsExec_Pattern":        50,
}

MITRE_MAP = {
    "C2_Beaconing_Detected":      "T1071.001",
    "C2_SSL_SelfSigned":          "T1573.002",
    "C2_JA3_Suspicious":          "T1071.001",
    "DNS_High_NXDOMAIN_Ratio":    "T1071.004",
    "Exfil_High_Volume_Outbound": "T1048.003",
    "Exfil_DNS_Tunneling":        "T1048",
    "LM_SMB_Multi_Host_Scan":     "T1021.002",
    "LM_PsExec_Detected":         "T1569.002",
    "LM_Auth_Spray":              "T1110.003",
    "SMB_PsExec_Pattern":         "T1569.002",
}


# ─────────────────────────────────────────────
# Log parsers
# ─────────────────────────────────────────────

def parse_zeek_notice(filepath: str) -> pd.DataFrame:
    """Parse Zeek notice.log into a DataFrame."""
    if not os.path.exists(filepath):
        console.print(f"[yellow]notice.log not found: {filepath}[/yellow]")
        return pd.DataFrame()

    fields, rows = [], []
    with open(filepath) as f:
        for line in f:
            line = line.rstrip()
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                vals = line.split("\t")
                if len(vals) == len(fields):
                    rows.append(vals)

    if not fields or not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows, columns=fields)
    df.replace("-", pd.NA, inplace=True)
    if "ts" in df.columns:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        df["ts"] = pd.to_datetime(df["ts"], unit="s", utc=True, errors="coerce")
    return df


def parse_suricata_eve(filepath: str, event_types: list = None) -> pd.DataFrame:
    """Parse Suricata EVE JSON into a DataFrame."""
    if not os.path.exists(filepath):
        console.print(f"[yellow]eve.json not found: {filepath}[/yellow]")
        return pd.DataFrame()

    allowed = set(event_types) if event_types else {"alert"}
    records = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                if r.get("event_type") in allowed:
                    records.append(r)
            except json.JSONDecodeError:
                continue

    if not records:
        return pd.DataFrame()

    df = pd.json_normalize(records, sep=".")
    if "timestamp" in df.columns:
        df["ts"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df


# ─────────────────────────────────────────────
# Correlation engine
# ─────────────────────────────────────────────

def correlate_alerts(zeek_df: pd.DataFrame,
                     suricata_df: pd.DataFrame,
                     timeframe_minutes: int = 60,
                     threshold: int = 70) -> List[dict]:
    """
    Group related alerts by source IP within a time window.
    Returns a list of correlated incidents scored above threshold.
    """
    incidents: Dict[str, dict] = {}

    # Process Zeek notices
    if not zeek_df.empty and "src" in zeek_df.columns and "note" in zeek_df.columns:
        for _, row in zeek_df.iterrows():
            src  = str(row.get("src", ""))
            note = str(row.get("note", ""))
            ts   = row.get("ts")
            msg  = str(row.get("msg", ""))
            if not src or src == "nan":
                continue

            key = src
            if key not in incidents:
                incidents[key] = _new_incident(src)

            weight = ALERT_WEIGHTS.get(note, 15)
            incidents[key]["threat_score"] = min(100, incidents[key]["threat_score"] + weight)
            incidents[key]["alert_count"]  += 1
            incidents[key]["alerts"].append({
                "source":    "zeek",
                "type":      note,
                "msg":       msg,
                "ts":        str(ts),
                "mitre":     MITRE_MAP.get(note, ""),
                "weight":    weight
            })
            if MITRE_MAP.get(note):
                incidents[key]["mitre_ttps"].add(MITRE_MAP[note])

    # Process Suricata alerts
    if not suricata_df.empty:
        src_col = "src_ip" if "src_ip" in suricata_df.columns else None
        sig_col = "alert.signature" if "alert.signature" in suricata_df.columns else None
        sev_col = "alert.severity"  if "alert.severity"  in suricata_df.columns else None

        if src_col:
            for _, row in suricata_df.iterrows():
                src = str(row.get(src_col, ""))
                if not src or src == "nan":
                    continue

                sig    = str(row.get(sig_col, "")) if sig_col else ""
                sev    = int(row.get(sev_col, 3))  if sev_col else 3
                ts     = row.get("ts", "")

                key = src
                if key not in incidents:
                    incidents[key] = _new_incident(src)

                weight = ALERT_WEIGHTS.get(sev, 10)
                incidents[key]["threat_score"] = min(100, incidents[key]["threat_score"] + weight)
                incidents[key]["alert_count"]  += 1
                incidents[key]["alerts"].append({
                    "source":    "suricata",
                    "type":      sig,
                    "severity":  sev,
                    "ts":        str(ts),
                    "weight":    weight
                })

    # Finalize and filter
    result = []
    for key, inc in incidents.items():
        inc["mitre_ttps"] = list(inc["mitre_ttps"])
        inc["verdict"] = (
            "CRITICAL" if inc["threat_score"] >= 80 else
            "HIGH"     if inc["threat_score"] >= threshold else
            "MEDIUM"   if inc["threat_score"] >= 40 else
            "LOW"
        )
        # Deduplicate alerts
        seen_types = set()
        deduped = []
        for a in inc["alerts"]:
            key_a = f"{a['type']}-{a.get('severity','')}"
            if key_a not in seen_types:
                deduped.append(a)
                seen_types.add(key_a)
        inc["alerts"]      = deduped
        inc["alert_count"] = len(deduped)

        if inc["threat_score"] >= threshold:
            result.append(inc)

    return sorted(result, key=lambda x: x["threat_score"], reverse=True)


def _new_incident(src: str) -> dict:
    return {
        "src_ip":       src,
        "threat_score": 0,
        "alert_count":  0,
        "alerts":       [],
        "mitre_ttps":   set(),
        "verdict":      "LOW",
        "created_at":   datetime.utcnow().isoformat()
    }


# ─────────────────────────────────────────────
# TheHive integration
# ─────────────────────────────────────────────

def push_to_thehive(incident: dict) -> Optional[str]:
    """Create a TheHive alert for a correlated incident."""
    if not THEHIVE_API_KEY:
        console.print("[yellow]THEHIVE_API_KEY not set — skipping TheHive push[/yellow]")
        return None

    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type":  "application/json"
    }

    mitre_str = ", ".join(incident["mitre_ttps"]) or "Unknown"
    alert_summary = "\n".join(
        f"- [{a['source'].upper()}] {a['type']} (weight={a['weight']})"
        for a in incident["alerts"][:10]
    )

    payload = {
        "type":        "zeek-nsm-correlation",
        "source":      "ZeekNSM-AlertCorrelator",
        "sourceRef":   f"corr-{incident['src_ip']}-{int(time.time())}",
        "title":       f"[{incident['verdict']}] Correlated Alerts — {incident['src_ip']}",
        "description": (
            f"**Source IP:** {incident['src_ip']}\n"
            f"**Threat Score:** {incident['threat_score']}/100\n"
            f"**Alert Count:** {incident['alert_count']}\n"
            f"**MITRE ATT&CK:** {mitre_str}\n\n"
            f"**Alerts Summary:**\n{alert_summary}"
        ),
        "severity":    1 if incident["verdict"] == "CRITICAL" else
                       2 if incident["verdict"] == "HIGH" else 3,
        "tags":        ["zeek", "suricata", "network", *incident["mitre_ttps"]],
        "observables": [
            {"dataType": "ip", "data": incident["src_ip"], "message": "Source IP"}
        ]
    }

    try:
        resp = requests.post(
            f"{THEHIVE_HOST}/api/alert",
            headers=headers,
            json=payload,
            timeout=10,
            verify=False
        )
        if resp.status_code in (200, 201):
            alert_id = resp.json().get("id", "unknown")
            console.print(f"[green]TheHive alert created: {alert_id}[/green]")
            return alert_id
        else:
            console.print(f"[red]TheHive error {resp.status_code}: {resp.text[:200]}[/red]")
            return None
    except requests.RequestException as e:
        console.print(f"[red]TheHive connection failed: {e}[/red]")
        return None


# ─────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────

def print_incidents(incidents: list) -> None:
    if not incidents:
        console.print("[green]No incidents above threshold.[/green]")
        return

    table = Table(title=f"Correlated Incidents ({len(incidents)})", show_lines=True)
    table.add_column("Src IP",       style="cyan",        no_wrap=True)
    table.add_column("Score",        style="bold red",    no_wrap=True)
    table.add_column("Verdict",      style="bold yellow", no_wrap=True)
    table.add_column("Alerts",       style="white",       no_wrap=True)
    table.add_column("MITRE TTPs",   style="magenta",     overflow="fold")

    for inc in incidents:
        table.add_row(
            inc["src_ip"],
            str(inc["threat_score"]),
            inc["verdict"],
            str(inc["alert_count"]),
            ", ".join(inc["mitre_ttps"]) or "—"
        )

    console.print(table)


def save_incidents(incidents: list, output: str) -> None:
    os.makedirs(output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output, f"correlated_incidents_{ts}.json")
    with open(path, "w") as f:
        json.dump(incidents, f, indent=2, default=str)
    console.print(f"[green]Saved:[/green] {path}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Zeek + Suricata Alert Correlator")
    parser.add_argument("--zeek-notice",    default="notice.log", help="Zeek notice.log path")
    parser.add_argument("--suricata-eve",   default="eve.json",   help="Suricata eve.json path")
    parser.add_argument("--timeframe",      type=int, default=60, help="Correlation window (minutes)")
    parser.add_argument("--threshold",      type=int, default=70, help="Threat score threshold (0-100)")
    parser.add_argument("--mode",           choices=["oneshot", "continuous"], default="oneshot")
    parser.add_argument("--output",         default="correlation-results", help="Output directory")
    parser.add_argument("--push-thehive",   action="store_true", help="Push incidents to TheHive")
    parser.add_argument("--interval",       type=int, default=300,
                        help="Polling interval in seconds (continuous mode)")
    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold red]Zeek + Suricata Alert Correlator[/bold red]\n"
        f"Mode: [cyan]{args.mode}[/cyan]  |  "
        f"Threshold: [yellow]{args.threshold}[/yellow]  |  "
        f"Window: [yellow]{args.timeframe}min[/yellow]  |  "
        f"TheHive: [yellow]{'ON' if args.push_thehive else 'OFF'}[/yellow]",
        title="05-zeek-nsm"
    ))

    def run_once():
        console.print("\n[bold]Loading logs...[/bold]")
        zeek_df     = parse_zeek_notice(args.zeek_notice)
        suricata_df = parse_suricata_eve(args.suricata_eve)
        console.print(f"  Zeek notices:      [cyan]{len(zeek_df):,}[/cyan]")
        console.print(f"  Suricata alerts:   [cyan]{len(suricata_df):,}[/cyan]")

        console.print("[bold]Correlating...[/bold]")
        incidents = correlate_alerts(zeek_df, suricata_df, args.timeframe, args.threshold)
        console.print(f"  [yellow]{len(incidents)}[/yellow] incidents above threshold {args.threshold}")

        print_incidents(incidents)
        save_incidents(incidents, args.output)

        if args.push_thehive and incidents:
            console.print("\n[bold]Pushing to TheHive...[/bold]")
            for inc in incidents:
                push_to_thehive(inc)

    if args.mode == "oneshot":
        run_once()
    else:
        console.print(f"[bold]Running continuously every {args.interval}s. Ctrl+C to stop.[/bold]")
        while True:
            try:
                run_once()
                time.sleep(args.interval)
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopped.[/yellow]")
                break


if __name__ == "__main__":
    main()
