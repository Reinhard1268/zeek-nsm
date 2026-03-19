# =============================================================
# File: dga-detection-results.md
# =============================================================

# DGA Detection Results Report

**Script:** dga_detector.py  
**Input:** Zeek dns.log (simulated — 6 hours of traffic, 18,432 unique domains)  
**Run Date:** 2026-03-11  
**Analyst:** Amoah Reinhard  

---

## Summary

| Metric | Value |
|--------|-------|
| Total domains analyzed | 18,432 |
| DGA suspects flagged | 47 |
| High confidence (prob > 0.80) | 12 |
| Medium confidence (0.60–0.80) | 23 |
| Low confidence (0.50–0.60) | 12 |
| Known good (whitelisted) | 16,890 |
| Unknown/uncategorized | 1,495 |

---

## Top Flagged Domains (High Confidence DGA)

| Rank | Domain | DGA Prob | Entropy | CV Ratio | Length | TLD | Verdict |
|------|--------|----------|---------|----------|--------|-----|---------|
| 1 | `xjnwabpfbqwmdhe.com` | 0.97 | 3.98 | 0.21 | 15 | .com | DGA — Conficker family |
| 2 | `aGVsbG8td29ybGQ.exfil.c2ops.net` | 0.96 | 4.21 | 0.09 | 32 | .net | DNS Tunnel |
| 3 | `kqlmhptwrfcnisd.net` | 0.95 | 3.91 | 0.19 | 15 | .net | DGA — Conficker family |
| 4 | `dGhpcyBpcyBhIHNlY3JldA.exfil-domain.net` | 0.95 | 4.18 | 0.08 | 38 | .net | DNS Tunnel |
| 5 | `qzxvrlmkpjbnftd.com` | 0.93 | 3.87 | 0.22 | 15 | .com | DGA — Zeus family |
| 6 | `mjrcvdspkxlntbz.org` | 0.92 | 3.82 | 0.23 | 15 | .org | DGA — Conficker family |
| 7 | `fpxqjzkmvbrltnsd.com` | 0.91 | 3.79 | 0.25 | 16 | .com | DGA — generic |
| 8 | `bqhwvxdltmzspkr.com` | 0.90 | 3.76 | 0.24 | 15 | .com | DGA — Sefnit family |
| 9 | `zkqvxtblmrkpfnsw.com` | 0.89 | 3.74 | 0.26 | 16 | .com | DGA — Locky family |
| 10 | `hfqvbzxwnrtmkdp.com` | 0.88 | 3.72 | 0.27 | 15 | .com | DGA — Murofet |
| 11 | `xvztqlmrbkpfnswj.com` | 0.87 | 3.71 | 0.28 | 16 | .com | DGA — Dyre |
| 12 | `yzxvqplmkrbjthf.com` | 0.85 | 3.68 | 0.29 | 15 | .com | DGA — Torpig |

---

## Source IP Correlation

| Source IP | Hostname | DGA Domains Queried | Malware Suspicion |
|-----------|----------|--------------------|--------------------|
| 192.168.1.55 | WORKSTATION-7 | 18 | Emotet/Conficker DGA |
| 192.168.1.33 | LAPTOP-SALES-08 | 12 | DNS Tunnel (Base64 encoded) |
| 192.168.1.78 | OFFICE-PC-12 | 8 | Possible AsyncRAT fallback DGA |
| 192.168.1.42 | DEV-LAPTOP-3 | 5 | Cobalt Strike fallback DGA |
| 192.168.1.90 | UNKNOWN | 4 | Unknown — investigate |

---

## Feature Breakdown for Top Domain

```
Domain: xjnwabpfbqwmdhe.com
──────────────────────────────────────────
Shannon Entropy:         3.98 bits   (threshold: 3.5) ← ABOVE
Label Length:            15 chars    (avg legit: 8.2)  ← ABOVE
Consonant/Vowel Ratio:   3.75        (avg legit: 1.8)  ← ABOVE
N-gram Score (2-gram):   0.041       (avg legit: 0.31) ← BELOW (unusual bigrams)
N-gram Score (3-gram):   0.012       (avg legit: 0.19) ← BELOW
TLD:                     .com        (common)
Has numbers:             No
Has hyphens:             No
DGA Probability:         0.97        ← HIGH CONFIDENCE DGA
```

---

## False Positive Analysis

| Domain | DGA Score | Reason for FP | Action |
|--------|-----------|--------------|--------|
| `cdn.jsdelivr.net` | 0.62 | CDN subdomain with unusual chars | Whitelist |
| `r.cloudflare.com` | 0.58 | Short random-looking subdomain | Whitelist |
| `s3.us-west-2.amazonaws.com` | 0.55 | AWS region subdomain pattern | Whitelist |
| `fonts.gstatic.com` | 0.52 | Short label, high entropy | Whitelist |
| `1e100.net` | 0.61 | Google internal hostname | Whitelist |

**False Positive Rate (estimated):** 5/47 = 10.6%  
**True Positive Rate (estimated):** 42/47 = 89.4%

---

## Model Performance (Cross-validation)

```
Training set:  1,500 domains (1,000 legitimate + 500 DGA)
Test set:      500 domains

Accuracy:      94.2%
Precision:     91.8%
Recall:        96.3%
F1-Score:      94.0%
AUC-ROC:       0.978

Top Feature Importances:
  1. Shannon entropy          (0.31)
  2. N-gram frequency score   (0.28)
  3. Consonant/vowel ratio    (0.19)
  4. Domain length            (0.14)
  5. TLD risk score           (0.08)
```

---

## How to Run

```bash
# Basic run against Zeek dns.log
python3 dga_detector.py --input /opt/zeek/logs/current/dns.log --output results/

# With custom threshold and saved model
python3 dga_detector.py \
  --input dns.log \
  --threshold 0.70 \
  --model models/dga_classifier.joblib \
  --output dga-detection-results/

# Read from Elasticsearch index
python3 dga_detector.py \
  --source elastic \
  --elastic-host http://localhost:9200 \
  --index zeek-* \
  --timeframe 6h \
  --output results/
```
