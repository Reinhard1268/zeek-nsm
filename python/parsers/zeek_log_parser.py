#!/usr/bin/env python3
# =============================================================
# File: zeek_log_parser.py
# =============================================================
"""
ZeekLogParser — parses all Zeek log formats (TSV and JSON) into
clean pandas DataFrames with type coercion and filter methods.
Supports reading from file or from an Elasticsearch index.
"""

import json
import os
from datetime import datetime, timedelta
from typing import Optional, Union

import pandas as pd
import numpy as np
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# Field type maps per log type
# ─────────────────────────────────────────────

ZEEK_TYPE_MAP = {
    "time":     "float",
    "interval": "float",
    "count":    "int",
    "int":      "int",
    "double":   "float",
    "port":     "int",
    "bool":     "bool",
    "addr":     "str",
    "string":   "str",
    "enum":     "str",
}

ZEEK_LOG_SCHEMAS = {
    "conn": {
        "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
        "id.resp_h": "addr", "id.resp_p": "port", "proto": "enum",
        "service": "string", "duration": "interval", "orig_bytes": "count",
        "resp_bytes": "count", "conn_state": "string", "local_orig": "bool",
        "local_resp": "bool", "missed_bytes": "count", "history": "string",
        "orig_pkts": "count", "orig_ip_bytes": "count",
        "resp_pkts": "count", "resp_ip_bytes": "count",
    },
    "dns": {
        "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
        "id.resp_h": "addr", "id.resp_p": "port", "proto": "enum",
        "trans_id": "count", "rtt": "interval", "query": "string",
        "qclass": "count", "qclass_name": "string", "qtype": "count",
        "qtype_name": "string", "rcode": "count", "rcode_name": "string",
        "AA": "bool", "TC": "bool", "RD": "bool", "RA": "bool",
        "Z": "count", "rejected": "bool",
    },
    "http": {
        "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
        "id.resp_h": "addr", "id.resp_p": "port",
        "trans_depth": "count", "method": "string", "host": "string",
        "uri": "string", "referrer": "string", "version": "string",
        "user_agent": "string", "origin": "string",
        "request_body_len": "count", "response_body_len": "count",
        "status_code": "count", "status_msg": "string",
    },
    "ssl": {
        "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
        "id.resp_h": "addr", "id.resp_p": "port",
        "version": "string", "cipher": "string", "curve": "string",
        "server_name": "string", "resumed": "bool", "established": "bool",
        "subject": "string", "issuer": "string",
        "not_valid_before": "time", "not_valid_after": "time",
        "ja3": "string", "ja3s": "string",
    },
    "notice": {
        "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
        "id.resp_h": "addr", "id.resp_p": "port",
        "note": "enum", "msg": "string", "sub": "string",
        "src": "addr", "dst": "addr", "p": "port",
        "actions": "string", "suppress_for": "interval",
        "identifier": "string",
    },
    "files": {
        "ts": "time", "fuid": "string", "uid": "string",
        "id.orig_h": "addr", "id.resp_h": "addr",
        "source": "string", "depth": "count",
        "analyzers": "string", "mime_type": "string",
        "filename": "string", "duration": "interval",
        "seen_bytes": "count", "total_bytes": "count",
        "missing_bytes": "count", "overflow_bytes": "count",
        "timedout": "bool", "md5": "string", "sha1": "string", "sha256": "string",
    },
    "weird": {
        "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
        "id.resp_h": "addr", "id.resp_p": "port",
        "name": "string", "addl": "string", "notice": "bool", "peer": "string",
    },
}


# ─────────────────────────────────────────────
# Main parser class
# ─────────────────────────────────────────────

class ZeekLogParser:
    """
    Parses Zeek log files (TSV or JSON) into pandas DataFrames.

    Usage:
        parser = ZeekLogParser()
        df = parser.parse("conn.log")
        filtered = parser.by_src(df, "192.168.1.55")
    """

    UNSET_MARKER = "-"

    def __init__(self, elastic_host: Optional[str] = None,
                 elastic_user: str = "elastic",
                 elastic_password: str = ""):
        self._elastic_host = elastic_host or os.getenv("ELASTIC_HOST", "http://localhost:9200")
        self._elastic_user = elastic_user or os.getenv("ELASTIC_USERNAME", "elastic")
        self._elastic_pass = elastic_password or os.getenv("ELASTIC_PASSWORD", "")
        self._es = None

    def _get_es_client(self):
        if self._es is None:
            from elasticsearch import Elasticsearch
            self._es = Elasticsearch(
                self._elastic_host,
                basic_auth=(self._elastic_user, self._elastic_pass),
                verify_certs=False
            )
        return self._es

    # ── File parsing ──

    def parse(self, filepath: str, log_type: Optional[str] = None) -> pd.DataFrame:
        """
        Parse a Zeek log file. Autodetects TSV vs JSON format.
        log_type is optional (auto-detected from filename if not provided).
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        if log_type is None:
            log_type = os.path.basename(filepath).split(".")[0]

        with open(filepath, "r") as f:
            first_line = f.readline().strip()

        if first_line.startswith("{"):
            return self._parse_json(filepath, log_type)
        else:
            return self._parse_tsv(filepath, log_type)

    def _parse_tsv(self, filepath: str, log_type: str) -> pd.DataFrame:
        fields, types, rows = [], [], []

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
                    vals = line.split("\t")
                    if len(vals) == len(fields):
                        rows.append(vals)

        if not fields:
            return pd.DataFrame()

        df = pd.DataFrame(rows, columns=fields)
        df.replace(self.UNSET_MARKER, pd.NA, inplace=True)
        return self._coerce_types(df, log_type, types)

    def _parse_json(self, filepath: str, log_type: str) -> pd.DataFrame:
        records = []
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not records:
            return pd.DataFrame()

        df = pd.json_normalize(records)
        return self._coerce_types(df, log_type)

    def _coerce_types(self, df: pd.DataFrame, log_type: str,
                      zeek_types: Optional[list] = None) -> pd.DataFrame:
        schema = ZEEK_LOG_SCHEMAS.get(log_type, {})

        for col in df.columns:
            if col in schema:
                ztype = schema[col]
            else:
                ztype = "string"

            if ztype in ("time", "interval", "double", "float"):
                df[col] = pd.to_numeric(df[col], errors="coerce")
                if ztype == "time" and col == "ts":
                    df[col] = pd.to_datetime(df[col], unit="s", errors="coerce")
            elif ztype in ("count", "int", "port"):
                df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
            elif ztype == "bool":
                df[col] = df[col].map({"T": True, "F": False, True: True, False: False})

        return df

    # ── Elastic source ──

    def from_elastic(self, index: str, log_type: str,
                     timeframe_hours: int = 1,
                     query: Optional[dict] = None,
                     max_hits: int = 10000) -> pd.DataFrame:
        """Read Zeek events from Elasticsearch."""
        es = self._get_es_client()
        since = (datetime.utcnow() - timedelta(hours=timeframe_hours)).isoformat()

        body = query or {
            "query": {
                "bool": {
                    "filter": [
                        {"term":  {"event.dataset": f"zeek.{log_type}"}},
                        {"range": {"@timestamp": {"gte": since}}}
                    ]
                }
            },
            "size": max_hits
        }

        resp = es.search(index=index, body=body)
        hits = [h["_source"] for h in resp["hits"]["hits"]]

        if not hits:
            return pd.DataFrame()

        df = pd.json_normalize(hits)
        return df

    # ── Filter methods ──

    def by_src(self, df: pd.DataFrame, src_ip: str) -> pd.DataFrame:
        col = "id.orig_h" if "id.orig_h" in df.columns else "source.ip"
        return df[df[col] == src_ip] if col in df.columns else df

    def by_dst(self, df: pd.DataFrame, dst_ip: str) -> pd.DataFrame:
        col = "id.resp_h" if "id.resp_h" in df.columns else "destination.ip"
        return df[df[col] == dst_ip] if col in df.columns else df

    def by_proto(self, df: pd.DataFrame, proto: str) -> pd.DataFrame:
        col = "proto" if "proto" in df.columns else "network.transport"
        return df[df[col].str.lower() == proto.lower()] if col in df.columns else df

    def by_timeframe(self, df: pd.DataFrame,
                     start: Union[str, datetime],
                     end: Union[str, datetime]) -> pd.DataFrame:
        col = "ts" if "ts" in df.columns else "@timestamp"
        if col not in df.columns:
            return df
        if isinstance(start, str):
            start = pd.to_datetime(start)
        if isinstance(end, str):
            end = pd.to_datetime(end)
        return df[(df[col] >= start) & (df[col] <= end)]

    def by_bytes(self, df: pd.DataFrame,
                 min_bytes: Optional[int] = None,
                 max_bytes: Optional[int] = None) -> pd.DataFrame:
        col = "orig_bytes" if "orig_bytes" in df.columns else "source.bytes"
        if col not in df.columns:
            return df
        result = df.copy()
        if min_bytes is not None:
            result = result[pd.to_numeric(result[col], errors="coerce") >= min_bytes]
        if max_bytes is not None:
            result = result[pd.to_numeric(result[col], errors="coerce") <= max_bytes]
        return result

    def by_port(self, df: pd.DataFrame, port: int, direction: str = "dst") -> pd.DataFrame:
        col = "id.resp_p" if direction == "dst" else "id.orig_p"
        if col not in df.columns:
            col = "destination.port" if direction == "dst" else "source.port"
        if col not in df.columns:
            return df
        return df[pd.to_numeric(df[col], errors="coerce") == port]

    # ── Convenience loaders ──

    def conn(self, path: str) -> pd.DataFrame:
        return self.parse(path, "conn")

    def dns(self, path: str) -> pd.DataFrame:
        return self.parse(path, "dns")

    def http(self, path: str) -> pd.DataFrame:
        return self.parse(path, "http")

    def ssl(self, path: str) -> pd.DataFrame:
        return self.parse(path, "ssl")

    def notice(self, path: str) -> pd.DataFrame:
        return self.parse(path, "notice")

    def files(self, path: str) -> pd.DataFrame:
        return self.parse(path, "files")

    def weird(self, path: str) -> pd.DataFrame:
        return self.parse(path, "weird")


# ─────────────────────────────────────────────
# Quick CLI demo
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="ZeekLogParser demo")
    p.add_argument("--log",  required=True, help="Path to Zeek log file")
    p.add_argument("--type", default=None,  help="Log type (conn/dns/http/ssl/notice/files/weird)")
    p.add_argument("--src",  default=None,  help="Filter by source IP")
    p.add_argument("--dst",  default=None,  help="Filter by destination IP")
    p.add_argument("--head", type=int, default=20, help="Rows to display")
    args = p.parse_args()

    parser = ZeekLogParser()
    df = parser.parse(args.log, args.type)
    print(f"Loaded {len(df)} rows from {args.log}")

    if args.src:
        df = parser.by_src(df, args.src)
        print(f"Filtered to {len(df)} rows for src={args.src}")

    if args.dst:
        df = parser.by_dst(df, args.dst)
        print(f"Filtered to {len(df)} rows for dst={args.dst}")

    print(df.head(args.head).to_string())
