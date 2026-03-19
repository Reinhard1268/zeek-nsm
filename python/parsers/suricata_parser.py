#!/usr/bin/env python3
# =============================================================
# File: suricata_parser.py
# Location: 05-zeek-nsm/python/parsers/suricata_parser.py
# =============================================================
"""
SuricataParser — parses Suricata EVE JSON logs into clean pandas DataFrames.
Supports alert, dns, http, tls, and flow event types.
Includes filter methods by signature, severity, and category.
"""

import json
import os
from datetime import datetime, timedelta
from typing import Optional, Union

import pandas as pd
from dotenv import load_dotenv

load_dotenv()


class SuricataParser:
    """
    Parses Suricata EVE JSON (eve.json) into pandas DataFrames.

    Usage:
        parser = SuricataParser()
        df = parser.parse("eve.json")
        alerts = parser.alerts(df)
        high = parser.by_severity(alerts, max_severity=2)
    """

    SUPPORTED_EVENT_TYPES = {"alert", "dns", "http", "tls", "flow", "fileinfo", "stats"}

    def __init__(self,
                 elastic_host: Optional[str] = None,
                 elastic_user: str = "elastic",
                 elastic_password: str = ""):
        self._elastic_host = elastic_host or os.getenv("ELASTIC_HOST", "http://localhost:9200")
        self._elastic_user = elastic_user or os.getenv("ELASTIC_USERNAME", "elastic")
        self._elastic_pass = elastic_password or os.getenv("ELASTIC_PASSWORD", "")
        self._es = None

    # ─────────────────────────────────────────────
    # Core parsing
    # ─────────────────────────────────────────────

    def parse(self, filepath: str,
              event_types: Optional[list] = None,
              max_rows: int = 500_000) -> pd.DataFrame:
        """
        Parse a Suricata EVE JSON file into a DataFrame.

        Args:
            filepath:    Path to eve.json
            event_types: List of event types to include (None = all)
            max_rows:    Max rows to load

        Returns:
            Flattened DataFrame with dot-notation columns
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"EVE JSON file not found: {filepath}")

        allowed = set(event_types) if event_types else self.SUPPORTED_EVENT_TYPES
        records = []
        count = 0

        with open(filepath, "r") as f:
            for line in f:
                if count >= max_rows:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if record.get("event_type") in allowed:
                        records.append(record)
                        count += 1
                except json.JSONDecodeError:
                    continue

        if not records:
            return pd.DataFrame()

        df = pd.json_normalize(records, sep=".")
        return self._coerce_types(df)

    def _coerce_types(self, df: pd.DataFrame) -> pd.DataFrame:
        # Timestamp
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
            df.rename(columns={"timestamp": "@timestamp"}, inplace=True)

        # Numeric fields
        numeric_cols = [
            "src_port", "dest_port",
            "alert.severity", "alert.gid", "alert.rev", "alert.signature_id",
            "http.status", "http.length",
            "flow.pkts_toserver", "flow.pkts_toclient",
            "flow.bytes_toserver", "flow.bytes_toclient",
            "dns.id",
        ]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        return df

    # ─────────────────────────────────────────────
    # Event-type filters
    # ─────────────────────────────────────────────

    def alerts(self, df: pd.DataFrame) -> pd.DataFrame:
        return df[df["event_type"] == "alert"].copy() if "event_type" in df.columns else df

    def dns_events(self, df: pd.DataFrame) -> pd.DataFrame:
        return df[df["event_type"] == "dns"].copy() if "event_type" in df.columns else df

    def http_events(self, df: pd.DataFrame) -> pd.DataFrame:
        return df[df["event_type"] == "http"].copy() if "event_type" in df.columns else df

    def tls_events(self, df: pd.DataFrame) -> pd.DataFrame:
        return df[df["event_type"] == "tls"].copy() if "event_type" in df.columns else df

    def flow_events(self, df: pd.DataFrame) -> pd.DataFrame:
        return df[df["event_type"] == "flow"].copy() if "event_type" in df.columns else df

    # ─────────────────────────────────────────────
    # Alert filter methods
    # ─────────────────────────────────────────────

    def by_signature(self, df: pd.DataFrame, pattern: str,
                     case_sensitive: bool = False) -> pd.DataFrame:
        """Filter alerts by signature name (substring or regex)."""
        col = "alert.signature"
        if col not in df.columns:
            return df
        flags = 0 if case_sensitive else pd.Series.str.contains.__code__.co_varnames
        return df[df[col].str.contains(pattern, case=case_sensitive, na=False)]

    def by_severity(self, df: pd.DataFrame,
                    max_severity: int = 1,
                    min_severity: int = 1) -> pd.DataFrame:
        """
        Filter alerts by Suricata severity (1=HIGH, 2=MEDIUM, 3=LOW).
        Default returns only severity 1 (critical/high).
        """
        col = "alert.severity"
        if col not in df.columns:
            return df
        sev = pd.to_numeric(df[col], errors="coerce")
        return df[(sev >= min_severity) & (sev <= max_severity)]

    def by_category(self, df: pd.DataFrame, category: str,
                    case_sensitive: bool = False) -> pd.DataFrame:
        """Filter alerts by rule category (e.g. 'Trojan Activity')."""
        col = "alert.category"
        if col not in df.columns:
            return df
        return df[df[col].str.contains(category, case=case_sensitive, na=False)]

    def by_sid(self, df: pd.DataFrame, sid: int) -> pd.DataFrame:
        """Filter alerts by Suricata signature ID."""
        col = "alert.signature_id"
        if col not in df.columns:
            return df
        return df[pd.to_numeric(df[col], errors="coerce") == sid]

    def by_src_ip(self, df: pd.DataFrame, ip: str) -> pd.DataFrame:
        col = "src_ip"
        return df[df[col] == ip] if col in df.columns else df

    def by_dst_ip(self, df: pd.DataFrame, ip: str) -> pd.DataFrame:
        col = "dest_ip"
        return df[df[col] == ip] if col in df.columns else df

    def by_timeframe(self, df: pd.DataFrame,
                     start: Union[str, datetime],
                     end: Union[str, datetime]) -> pd.DataFrame:
        col = "@timestamp"
        if col not in df.columns:
            return df
        if isinstance(start, str):
            start = pd.to_datetime(start, utc=True)
        if isinstance(end, str):
            end = pd.to_datetime(end, utc=True)
        return df[(df[col] >= start) & (df[col] <= end)]

    # ─────────────────────────────────────────────
    # Summary helpers
    # ─────────────────────────────────────────────

    def top_signatures(self, df: pd.DataFrame, n: int = 20) -> pd.DataFrame:
        """Return top N alert signatures by count."""
        col = "alert.signature"
        if col not in df.columns:
            return pd.DataFrame()
        return df[col].value_counts().head(n).reset_index(
            ).rename(columns={"index": "signature", col: "count"})

    def top_src_ips(self, df: pd.DataFrame, n: int = 20) -> pd.DataFrame:
        col = "src_ip"
        if col not in df.columns:
            return pd.DataFrame()
        return df[col].value_counts().head(n).reset_index(
            ).rename(columns={"index": "src_ip", col: "count"})

    def severity_summary(self, df: pd.DataFrame) -> pd.DataFrame:
        col = "alert.severity"
        if col not in df.columns:
            return pd.DataFrame()
        label_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
        summary = df[col].value_counts().reset_index()
        summary.columns = ["severity_int", "count"]
        summary["severity_label"] = summary["severity_int"].map(label_map)
        return summary.sort_values("severity_int")

    # ─────────────────────────────────────────────
    # Elastic source
    # ─────────────────────────────────────────────

    def from_elastic(self, index: str = "suricata-*",
                     timeframe_hours: int = 1,
                     event_types: Optional[list] = None,
                     max_hits: int = 10000) -> pd.DataFrame:
        """Read Suricata events from Elasticsearch."""
        from elasticsearch import Elasticsearch
        if self._es is None:
            self._es = Elasticsearch(
                self._elastic_host,
                basic_auth=(self._elastic_user, self._elastic_pass),
                verify_certs=False
            )

        since = (datetime.utcnow() - timedelta(hours=timeframe_hours)).isoformat()
        filters = [{"range": {"@timestamp": {"gte": since}}}]

        if event_types:
            filters.append({"terms": {"event_type": event_types}})

        body = {
            "query": {"bool": {"filter": filters}},
            "size": max_hits,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        resp = self._es.search(index=index, body=body)
        hits = [h["_source"] for h in resp["hits"]["hits"]]
        if not hits:
            return pd.DataFrame()

        df = pd.json_normalize(hits, sep=".")
        return self._coerce_types(df)


# ─────────────────────────────────────────────
# CLI demo
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="SuricataParser demo")
    p.add_argument("--eve",        required=True, help="Path to Suricata eve.json")
    p.add_argument("--type",       default="alert", help="Event type filter")
    p.add_argument("--severity",   type=int, default=None, help="Max severity (1=HIGH)")
    p.add_argument("--category",   default=None, help="Filter by category")
    p.add_argument("--signature",  default=None, help="Filter by signature substring")
    p.add_argument("--top-sigs",   action="store_true", help="Show top signatures")
    p.add_argument("--head",       type=int, default=20)
    args = p.parse_args()

    parser = SuricataParser()
    df = parser.parse(args.eve, event_types=[args.type])
    print(f"Loaded {len(df)} {args.type} events")

    if args.severity:
        df = parser.by_severity(df, max_severity=args.severity)
        print(f"Filtered to {len(df)} rows (severity <= {args.severity})")

    if args.category:
        df = parser.by_category(df, args.category)
        print(f"Filtered to {len(df)} rows (category ~ '{args.category}')")

    if args.signature:
        df = parser.by_signature(df, args.signature)
        print(f"Filtered to {len(df)} rows (signature ~ '{args.signature}')")

    if args.top_sigs:
        print("\nTop Signatures:")
        print(parser.top_signatures(df).to_string(index=False))
    else:
        print(df.head(args.head).to_string())
