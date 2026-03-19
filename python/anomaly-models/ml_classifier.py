#!/usr/bin/env python3
# =============================================================
# File: ml_classifier.py
# =============================================================
"""
ML-based classifiers for network anomaly detection.

Classes:
    DGAClassifier    — RandomForest trained on domain string features
    BeaconClassifier — IsolationForest for unsupervised beacon detection
"""

import json
import math
import os
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import (classification_report, roc_auc_score,
                             confusion_matrix, precision_recall_fscore_support)
from sklearn.preprocessing import LabelEncoder


# ─────────────────────────────────────────────
# Feature extraction helpers
# ─────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


def consonant_vowel_ratio(s: str) -> float:
    s = s.lower()
    vowels     = sum(1 for c in s if c in "aeiou")
    consonants = sum(1 for c in s if c.isalpha() and c not in "aeiou")
    return consonants / vowels if vowels > 0 else float(consonants)


def bigram_score(s: str, bigram_freq: Optional[dict] = None) -> float:
    """Score domain against English bigram frequencies (lower = more random)."""
    english_bigrams = bigram_freq or {
        "th":0.0356,"he":0.0307,"in":0.0243,"er":0.0205,"an":0.0199,
        "re":0.0185,"on":0.0176,"en":0.0175,"at":0.0149,"es":0.0145,
        "ed":0.0141,"nd":0.0135,"to":0.0134,"or":0.0128,"ea":0.0127,
        "ti":0.0126,"hi":0.0123,"as":0.0120,"te":0.0120,"et":0.0105,
    }
    if len(s) < 2:
        return 0.0
    total = 0.0
    for i in range(len(s)-1):
        bg = s[i:i+2].lower()
        total += english_bigrams.get(bg, 0.0)
    return total / (len(s)-1)


def extract_domain_features(domain: str) -> dict:
    """Extract numeric features from a domain label for ML input."""
    label = domain.split(".")[0].lower()
    n = len(label)

    digits  = sum(1 for c in label if c.isdigit())
    hyphens = label.count("-")
    vowels  = sum(1 for c in label if c in "aeiou")
    consonants = sum(1 for c in label if c.isalpha() and c not in "aeiou")

    return {
        "length":           n,
        "entropy":          round(shannon_entropy(label), 4),
        "cv_ratio":         round(consonant_vowel_ratio(label), 4),
        "bigram_score":     round(bigram_score(label), 4),
        "digit_ratio":      round(digits / n, 4)       if n > 0 else 0.0,
        "hyphen_ratio":     round(hyphens / n, 4)      if n > 0 else 0.0,
        "vowel_ratio":      round(vowels / n, 4)        if n > 0 else 0.0,
        "unique_char_ratio":round(len(set(label)) / n, 4) if n > 0 else 0.0,
        "has_digits":       int(digits > 0),
        "has_hyphens":      int(hyphens > 0),
        "num_dots":         domain.count("."),
        "tld_risk":         _tld_risk_score(domain),
    }


def _tld_risk_score(domain: str) -> float:
    """Assign a risk score to TLD (higher = riskier)."""
    high_risk  = {".xyz", ".top", ".tk", ".pw", ".cc", ".biz", ".info", ".club"}
    medium_risk = {".net", ".org", ".co", ".io", ".me"}
    low_risk   = {".com", ".gov", ".edu", ".mil"}
    tld = "." + domain.split(".")[-1].lower()
    if tld in high_risk:   return 1.0
    if tld in medium_risk: return 0.5
    if tld in low_risk:    return 0.1
    return 0.7  # Unknown TLD


# ─────────────────────────────────────────────
# DGAClassifier
# ─────────────────────────────────────────────

class DGAClassifier:
    """
    RandomForest-based DGA domain classifier.

    Usage:
        clf = DGAClassifier()
        clf.train(legit_domains, dga_domains)
        predictions = clf.predict(test_domains)
        clf.save("models/dga_classifier.joblib")
    """

    def __init__(self, n_estimators: int = 200, random_state: int = 42):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=None,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=random_state
        )
        self._fitted   = False
        self._features = list(extract_domain_features("test.com").keys())

    def _domains_to_features(self, domains: List[str]) -> pd.DataFrame:
        rows = [extract_domain_features(d) for d in domains]
        return pd.DataFrame(rows, columns=self._features)

    def train(self, legit_domains: List[str], dga_domains: List[str],
              test_size: float = 0.2) -> dict:
        """Train on labeled domain lists. Returns performance metrics."""
        domains = legit_domains + dga_domains
        labels  = [0]*len(legit_domains) + [1]*len(dga_domains)

        X = self._domains_to_features(domains)
        y = np.array(labels)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y)

        self.model.fit(X_train, y_train)
        self._fitted = True

        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]

        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
        auc = roc_auc_score(y_test, y_prob)

        metrics = {
            "precision": round(prec, 4),
            "recall":    round(rec,  4),
            "f1_score":  round(f1,   4),
            "auc_roc":   round(auc,  4),
            "train_size": len(X_train),
            "test_size":  len(X_test),
        }

        # Feature importances
        self.feature_importances_ = dict(zip(
            self._features,
            [round(v, 4) for v in self.model.feature_importances_]
        ))

        return metrics

    def predict(self, domains: List[str]) -> List[dict]:
        """Predict DGA probability for a list of domains."""
        if not self._fitted:
            raise RuntimeError("Model not trained. Call train() or load() first.")

        X = self._domains_to_features(domains)
        probs = self.model.predict_proba(X)[:, 1]

        results = []
        for domain, prob in zip(domains, probs):
            results.append({
                "domain":      domain,
                "dga_prob":    round(float(prob), 4),
                "verdict":     "DGA" if prob >= 0.5 else "BENIGN",
                "confidence":  "HIGH" if abs(prob - 0.5) > 0.3 else "LOW",
            })

        return sorted(results, key=lambda x: x["dga_prob"], reverse=True)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self.model, "features": self._features}, path)
        print(f"DGAClassifier saved to {path}")

    def load(self, path: str) -> "DGAClassifier":
        obj = joblib.load(path)
        self.model     = obj["model"]
        self._features = obj["features"]
        self._fitted   = True
        return self

    def feature_importance_report(self) -> pd.DataFrame:
        if not hasattr(self, "feature_importances_"):
            return pd.DataFrame()
        return pd.DataFrame(
            list(self.feature_importances_.items()),
            columns=["feature", "importance"]
        ).sort_values("importance", ascending=False)


# ─────────────────────────────────────────────
# BeaconClassifier
# ─────────────────────────────────────────────

class BeaconClassifier:
    """
    IsolationForest-based unsupervised beacon detector.
    Learns normal connection interval patterns and flags anomalies.

    Usage:
        clf = BeaconClassifier()
        clf.train(normal_conn_df)
        results = clf.predict(test_conn_df)
    """

    FEATURE_COLS = [
        "interval_mean", "interval_std", "interval_cv",
        "interval_min",  "interval_max", "connection_count",
        "bytes_mean",    "bytes_std",    "duration_mean"
    ]

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self._fitted = False

    def _extract_pair_features(self, conn_df: pd.DataFrame) -> pd.DataFrame:
        """Group conn.log by src→dst and extract interval features."""
        rows = []

        src_col   = "id.orig_h" if "id.orig_h" in conn_df.columns else "source.ip"
        dst_col   = "id.resp_h" if "id.resp_h" in conn_df.columns else "destination.ip"
        ts_col    = "ts"
        bytes_col = "orig_bytes" if "orig_bytes" in conn_df.columns else "source.bytes"
        dur_col   = "duration" if "duration" in conn_df.columns else None

        for (src, dst), grp in conn_df.groupby([src_col, dst_col]):
            if len(grp) < 5:
                continue

            ts_vals = pd.to_numeric(grp[ts_col], errors="coerce").dropna().sort_values().tolist()
            if len(ts_vals) < 5:
                continue

            intervals = [ts_vals[i+1] - ts_vals[i] for i in range(len(ts_vals)-1)]
            arr = np.array(intervals)
            mean_i = float(np.mean(arr))
            std_i  = float(np.std(arr))
            cv_i   = std_i / mean_i if mean_i > 0 else 9999.0

            bytes_vals = pd.to_numeric(grp[bytes_col], errors="coerce").dropna()
            dur_vals   = pd.to_numeric(grp[dur_col], errors="coerce").dropna() if dur_col else pd.Series([0])

            rows.append({
                "src":              src,
                "dst":              dst,
                "interval_mean":    round(mean_i, 4),
                "interval_std":     round(std_i, 4),
                "interval_cv":      round(cv_i, 4),
                "interval_min":     round(float(np.min(arr)), 4),
                "interval_max":     round(float(np.max(arr)), 4),
                "connection_count": len(ts_vals),
                "bytes_mean":       round(float(bytes_vals.mean()) if len(bytes_vals) else 0, 2),
                "bytes_std":        round(float(bytes_vals.std())  if len(bytes_vals) > 1 else 0, 2),
                "duration_mean":    round(float(dur_vals.mean())   if len(dur_vals) else 0, 4),
            })

        return pd.DataFrame(rows)

    def train(self, conn_df: pd.DataFrame) -> "BeaconClassifier":
        """Train IsolationForest on normal connection patterns."""
        features_df = self._extract_pair_features(conn_df)
        if features_df.empty:
            raise ValueError("No valid connection pairs found for training.")
        X = features_df[self.FEATURE_COLS].fillna(0)
        self.model.fit(X)
        self._fitted = True
        print(f"BeaconClassifier trained on {len(X)} connection pairs.")
        return self

    def predict(self, conn_df: pd.DataFrame) -> pd.DataFrame:
        """Predict anomalous (beacon) connection pairs."""
        if not self._fitted:
            raise RuntimeError("Call train() or load() first.")

        features_df = self._extract_pair_features(conn_df)
        if features_df.empty:
            return pd.DataFrame()

        X = features_df[self.FEATURE_COLS].fillna(0)
        predictions  = self.model.predict(X)          # -1 = anomaly, 1 = normal
        anomaly_scores = self.model.score_samples(X)  # More negative = more anomalous

        features_df["isolation_pred"]  = predictions
        features_df["anomaly_score"]   = anomaly_scores
        features_df["is_beacon"]       = predictions == -1
        features_df["confidence"]      = ((-anomaly_scores - 0.1) * 100).clip(0, 100).round(2)

        beacons = features_df[features_df["is_beacon"]].sort_values("confidence", ascending=False)
        return beacons

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)
        print(f"BeaconClassifier saved to {path}")

    def load(self, path: str) -> "BeaconClassifier":
        self.model   = joblib.load(path)
        self._fitted = True
        return self
