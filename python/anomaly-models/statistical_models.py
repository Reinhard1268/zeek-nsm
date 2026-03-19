#!/usr/bin/env python3
# =============================================================
# File: statistical_models.py
# =============================================================
"""
Statistical anomaly detection models for network security.
All models follow a sklearn-compatible fit/predict/score interface.

Classes:
    IntervalAnalyzer   — Beaconing detection via interval statistics
    EntropyCalculator  — DGA / encoding detection via Shannon entropy
    VolumeAnalyzer     — Exfiltration detection via volume thresholds
    AnomalyScorer      — Unified multi-signal anomaly scorer
"""

import math
from collections import Counter
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats


# ─────────────────────────────────────────────
# IntervalAnalyzer — Beaconing Detection
# ─────────────────────────────────────────────

class IntervalAnalyzer:
    """
    Detects C2 beaconing by analyzing connection interval regularity.
    Uses Coefficient of Variation (CV) as primary signal.

    Attributes:
        cv_threshold:         Max CV to classify as beacon (default 0.3)
        min_connections:      Min data points required (default 10)
        jitter_tolerance:     Expected jitter ± percentage (default 0.15)
    """

    def __init__(self, cv_threshold: float = 0.3,
                 min_connections: int = 10,
                 jitter_tolerance: float = 0.15):
        self.cv_threshold      = cv_threshold
        self.min_connections   = min_connections
        self.jitter_tolerance  = jitter_tolerance
        self._fitted_pairs: Dict[Tuple, dict] = {}

    def fit(self, timestamps: List[float]) -> "IntervalAnalyzer":
        """Fit on a list of Unix timestamps (one connection series)."""
        if len(timestamps) < 2:
            return self
        ts = sorted(timestamps)
        intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
        self._last_fit = self._compute_stats(intervals)
        return self

    def predict(self, timestamps: List[float]) -> bool:
        """Return True if the timestamp series looks like beaconing."""
        if len(timestamps) < self.min_connections:
            return False
        ts = sorted(timestamps)
        intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
        s = self._compute_stats(intervals)
        return s["cv"] < self.cv_threshold and s["count"] >= self.min_connections

    def score(self, timestamps: List[float]) -> float:
        """Return a 0–100 confidence score for beaconing."""
        if len(timestamps) < self.min_connections:
            return 0.0
        ts = sorted(timestamps)
        intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
        s = self._compute_stats(intervals)

        # CV component (lower CV = higher score)
        cv_score = max(0.0, (self.cv_threshold - s["cv"]) / self.cv_threshold) * 50
        # Count component (more connections = higher score)
        count_score = min(50.0, s["count"] / 1.0)
        return round(cv_score + count_score, 2)

    @staticmethod
    def _compute_stats(intervals: List[float]) -> dict:
        arr = np.array(intervals)
        mean = float(np.mean(arr))
        std  = float(np.std(arr))
        cv   = std / mean if mean > 0 else 9999.0
        return {
            "mean":     round(mean, 4),
            "std":      round(std,  4),
            "cv":       round(cv,   4),
            "count":    len(intervals),
            "min":      round(float(np.min(arr)), 4),
            "max":      round(float(np.max(arr)), 4),
            "variance": round(float(np.var(arr)), 4),
        }

    def analyze_dataframe(self, df: pd.DataFrame,
                          src_col: str = "id.orig_h",
                          dst_col: str = "id.resp_h",
                          ts_col: str  = "ts") -> pd.DataFrame:
        """
        Analyze a conn.log DataFrame for beaconing.
        Returns a DataFrame of suspected beacons sorted by confidence.
        """
        if df.empty:
            return pd.DataFrame()

        results = []
        grouped = df.groupby([src_col, dst_col])

        for (src, dst), grp in grouped:
            ts_vals = pd.to_numeric(grp[ts_col], errors="coerce").dropna().tolist()
            if len(ts_vals) < self.min_connections:
                continue
            ts_vals.sort()
            intervals = [ts_vals[i+1] - ts_vals[i] for i in range(len(ts_vals)-1)]
            s = self._compute_stats(intervals)
            conf = self.score(ts_vals)
            if s["cv"] < self.cv_threshold:
                results.append({
                    "src":              src,
                    "dst":              dst,
                    "interval_mean_s":  s["mean"],
                    "interval_std_s":   s["std"],
                    "cv":               s["cv"],
                    "connection_count": len(ts_vals),
                    "confidence_score": conf,
                    "verdict":          "BEACON_HIGH" if conf > 70 else "BEACON_MEDIUM"
                })

        if not results:
            return pd.DataFrame()

        return pd.DataFrame(results).sort_values("confidence_score", ascending=False)


# ─────────────────────────────────────────────
# EntropyCalculator — DGA / Encoding Detection
# ─────────────────────────────────────────────

class EntropyCalculator:
    """
    Calculates Shannon entropy and related metrics for domain/string analysis.
    Used to detect DGA domains and Base64-encoded data in network traffic.

    Attributes:
        entropy_threshold:   Min entropy to flag (default 3.5)
        min_length:          Min string length to analyze (default 6)
    """

    def __init__(self, entropy_threshold: float = 3.5, min_length: int = 6):
        self.entropy_threshold = entropy_threshold
        self.min_length        = min_length

    def fit(self, benign_samples: List[str]) -> "EntropyCalculator":
        """Fit baseline entropy distribution on known-benign strings."""
        entropies = [self.shannon_entropy(s) for s in benign_samples if len(s) >= self.min_length]
        self._baseline_mean = np.mean(entropies) if entropies else 2.5
        self._baseline_std  = np.std(entropies)  if entropies else 0.5
        return self

    def predict(self, value: str) -> bool:
        """Return True if entropy exceeds threshold (suspicious)."""
        return self.shannon_entropy(value) >= self.entropy_threshold

    def score(self, value: str) -> float:
        """Return normalized anomaly score 0–100."""
        ent = self.shannon_entropy(value)
        if not hasattr(self, "_baseline_mean"):
            raw = max(0.0, (ent - self.entropy_threshold) / self.entropy_threshold)
        else:
            z = (ent - self._baseline_mean) / max(self._baseline_std, 0.01)
            raw = min(1.0, max(0.0, z / 3.0))
        return round(raw * 100, 2)

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s)
        n = len(s)
        return round(-sum((c/n) * math.log2(c/n) for c in freq.values()), 4)

    @staticmethod
    def consonant_vowel_ratio(s: str) -> float:
        s = s.lower()
        vowels     = sum(1 for c in s if c in "aeiou")
        consonants = sum(1 for c in s if c.isalpha() and c not in "aeiou")
        return round(consonants / vowels, 3) if vowels > 0 else float(consonants)

    @staticmethod
    def is_base64_like(s: str) -> bool:
        import re
        return bool(re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s))

    def analyze_domains(self, domains: List[str]) -> pd.DataFrame:
        """Analyze a list of domain names and return scored results."""
        results = []
        for domain in domains:
            label = domain.split(".")[0]
            if len(label) < self.min_length:
                continue
            ent = self.shannon_entropy(label)
            cv_ratio = self.consonant_vowel_ratio(label)
            score = self.score(label)
            if ent >= self.entropy_threshold:
                results.append({
                    "domain":     domain,
                    "label":      label,
                    "entropy":    ent,
                    "cv_ratio":   cv_ratio,
                    "length":     len(label),
                    "base64":     self.is_base64_like(label),
                    "score":      score,
                    "verdict":    "DGA_SUSPECT" if score > 50 else "REVIEW"
                })
        return pd.DataFrame(results).sort_values("score", ascending=False) if results else pd.DataFrame()


# ─────────────────────────────────────────────
# VolumeAnalyzer — Exfiltration Detection
# ─────────────────────────────────────────────

class VolumeAnalyzer:
    """
    Detects volume-based data exfiltration by monitoring outbound bytes.

    Attributes:
        threshold_bytes:   Per-hour outbound threshold (default 100 MB)
        window_seconds:    Analysis window in seconds (default 3600)
        local_prefixes:    List of local network prefixes to ignore
    """

    def __init__(self, threshold_bytes: int = 104_857_600,
                 window_seconds: int = 3600,
                 local_prefixes: Optional[List[str]] = None):
        self.threshold_bytes = threshold_bytes
        self.window_seconds  = window_seconds
        self.local_prefixes  = local_prefixes or ["10.", "172.16.", "192.168."]
        self._baseline: Optional[dict] = None

    def fit(self, conn_df: pd.DataFrame) -> "VolumeAnalyzer":
        """Learn baseline outbound byte distribution."""
        if conn_df.empty:
            return self
        src_col, bytes_col = "id.orig_h", "orig_bytes"
        if src_col in conn_df.columns and bytes_col in conn_df.columns:
            stats_per_src = conn_df.groupby(src_col)[bytes_col].agg(["mean","std","max"])
            self._baseline = stats_per_src.to_dict()
        return self

    def predict(self, src: str, bytes_out: int) -> bool:
        return bytes_out >= self.threshold_bytes

    def score(self, bytes_out: int) -> float:
        ratio = bytes_out / self.threshold_bytes
        return round(min(100.0, ratio * 50), 2)

    def _is_local(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.local_prefixes)

    def analyze_dataframe(self, df: pd.DataFrame,
                          src_col: str = "id.orig_h",
                          dst_col: str = "id.resp_h",
                          bytes_col: str = "orig_bytes",
                          ts_col: str = "ts") -> pd.DataFrame:
        """Analyze conn.log for exfiltration. Returns ranked suspects."""
        if df.empty:
            return pd.DataFrame()

        df = df.copy()
        df[bytes_col] = pd.to_numeric(df[bytes_col], errors="coerce").fillna(0)

        # Filter internal destinations
        df = df[~df[dst_col].apply(self._is_local)]

        df["window"] = df[ts_col].dt.floor("1h") if hasattr(df[ts_col], "dt") else df[ts_col]
        grouped = df.groupby([src_col, dst_col, "window"])[bytes_col].sum().reset_index()
        grouped.columns = ["src", "dst", "window", "bytes_out"]
        grouped["mb_out"] = grouped["bytes_out"] / 1_048_576
        grouped["score"]  = grouped["bytes_out"].apply(self.score)
        suspects = grouped[grouped["bytes_out"] >= self.threshold_bytes]
        return suspects.sort_values("bytes_out", ascending=False)


# ─────────────────────────────────────────────
# AnomalyScorer — Unified Multi-Signal Scorer
# ─────────────────────────────────────────────

class AnomalyScorer:
    """
    Combines signals from IntervalAnalyzer, EntropyCalculator, and VolumeAnalyzer
    into a single unified anomaly score per src→dst pair.

    Weights are configurable; defaults are calibrated for typical SOC workloads.
    """

    DEFAULT_WEIGHTS = {
        "beacon_score":  0.40,
        "entropy_score": 0.30,
        "volume_score":  0.30,
    }

    def __init__(self,
                 weights: Optional[Dict[str, float]] = None,
                 cv_threshold: float = 0.3,
                 entropy_threshold: float = 3.5,
                 volume_threshold_bytes: int = 104_857_600):
        self.weights  = weights or self.DEFAULT_WEIGHTS
        self.interval = IntervalAnalyzer(cv_threshold=cv_threshold)
        self.entropy  = EntropyCalculator(entropy_threshold=entropy_threshold)
        self.volume   = VolumeAnalyzer(threshold_bytes=volume_threshold_bytes)

    def fit(self, conn_df: pd.DataFrame,
            benign_domains: Optional[List[str]] = None) -> "AnomalyScorer":
        self.volume.fit(conn_df)
        if benign_domains:
            self.entropy.fit(benign_domains)
        return self

    def score_pair(self,
                   src: str, dst: str,
                   timestamps: Optional[List[float]] = None,
                   bytes_out: Optional[int] = None,
                   domain: Optional[str] = None) -> dict:
        """Compute a unified anomaly score for a src→dst pair."""

        beacon_score  = self.interval.score(timestamps) if timestamps else 0.0
        entropy_score = self.entropy.score(domain.split(".")[0]) if domain else 0.0
        volume_score  = self.volume.score(bytes_out) if bytes_out else 0.0

        unified = (
            beacon_score  * self.weights.get("beacon_score", 0.4) +
            entropy_score * self.weights.get("entropy_score", 0.3) +
            volume_score  * self.weights.get("volume_score", 0.3)
        )

        return {
            "src":           src,
            "dst":           dst,
            "beacon_score":  round(beacon_score,  2),
            "entropy_score": round(entropy_score, 2),
            "volume_score":  round(volume_score,  2),
            "unified_score": round(unified,        2),
            "verdict": (
                "CRITICAL" if unified > 80 else
                "HIGH"     if unified > 60 else
                "MEDIUM"   if unified > 40 else
                "LOW"
            )
        }

    def predict(self, *args, **kwargs) -> bool:
        """Return True if unified score exceeds 60."""
        result = self.score_pair(*args, **kwargs)
        return result["unified_score"] >= 60
