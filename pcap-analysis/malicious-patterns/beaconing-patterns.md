# =============================================================
# File: beaconing-patterns.md
# =============================================================

# C2 Beaconing Patterns Reference

## What is Beaconing?

C2 beaconing is the regular, periodic communication between an infected host and its
Command and Control server. Malware checks in at fixed intervals to receive instructions
and report back status. The key indicator is **regularity** — machine-generated intervals
have far less variance than human-generated traffic.

## Key Metrics

| Metric | Formula | Beacon Indicator |
|--------|---------|-----------------|
| Mean interval | sum(intervals) / count | Any fixed value (30s, 60s, 300s common) |
| Standard deviation | sqrt(variance) | Low = regular |
| Coefficient of Variation (CV) | std_dev / mean | CV < 0.3 = suspicious, CV < 0.1 = beacon |
| Jitter score | max_interval - min_interval | Low = machine-generated |
| Confidence score | blend of CV + count | > 70 = high confidence beacon |

---

## Pattern 1: Standard Cobalt Strike Beacon (60s default)

**Profile:** Default Cobalt Strike malleable C2, sleep=60s, jitter=10%

**Zeek conn.log example:**
```
ts           id.orig_h      id.resp_h      duration  orig_bytes  conn_state
1718437391   192.168.1.42   185.220.101.45  0.8s     1,024       SF
1718437451   192.168.1.42   185.220.101.45  0.9s     1,022       SF   ← +60s
1718437511   192.168.1.42   185.220.101.45  0.8s     1,025       SF   ← +60s
1718437572   192.168.1.42   185.220.101.45  0.9s     1,021       SF   ← +61s (jitter)
```

**Statistical Profile:**
```
Mean interval:  60.3 seconds
Std deviation:  1.2 seconds
CV:             0.020     ← FAR below 0.3 threshold
Jitter:         ±5%       ← 10% configured jitter
Confidence:     96/100
```

**Zeek Notice Output:**
```
C2_Beaconing_Detected: 192.168.1.42 -> 185.220.101.45
  avg_interval=60.3s  cv=0.020  count=18  confidence=96.1
```

**Detection Rule (beaconing_detector.py output):**
```json
{
  "src": "192.168.1.42",
  "dst": "185.220.101.45",
  "port": 443,
  "interval_mean_s": 60.3,
  "interval_std_s": 1.2,
  "cv": 0.020,
  "connection_count": 18,
  "confidence_score": 96.1,
  "verdict": "BEACON_HIGH_CONFIDENCE"
}
```

---

## Pattern 2: Emotet Beacon (60s ±0.5%)

**Profile:** Emotet Epoch 4-5, nearly perfect regularity

**Zeek conn.log example:**
```
ts           id.orig_h      id.resp_h      duration  orig_bytes
1718437391   192.168.1.55   45.33.32.156   0.4s      45,231
1718437451   192.168.1.55   45.33.32.156   0.4s      44,981   ← +60s
1718437511   192.168.1.55   45.33.32.156   0.4s      45,102   ← +60s
```

**Statistical Profile:**
```
Mean interval:  60.0 seconds
Std deviation:  0.3 seconds
CV:             0.005     ← Extremely regular — machine-generated
Confidence:     99/100
```

**Key Differentiator:** Emotet uses POST requests with ~45 KB body (encoded system data).
Cobalt Strike uses much smaller check-ins (~1 KB).

---

## Pattern 3: AsyncRAT Heartbeat (5s interval)

**Profile:** AsyncRAT default keep-alive, 5 second heartbeat

**Zeek conn.log example:**
```
ts           id.orig_h      id.resp_h         port  duration  orig_bytes
1718445720   192.168.1.78   91.92.241.103     6606  0.1s      512
1718445725   192.168.1.78   91.92.241.103     6606  0.1s      511   ← +5s
1718445730   192.168.1.78   91.92.241.103     6606  0.1s      512   ← +5s
```

**Statistical Profile:**
```
Mean interval:  5.0 seconds
CV:             0.04
Confidence:     88/100
Note: Non-standard port (6606) is additional indicator
```

---

## Pattern 4: Slow Beacon (300s / 5 min)

**Profile:** Stealth-focused malware using long sleep intervals to avoid detection

**Statistical Profile:**
```
Mean interval:  300.4 seconds
CV:             0.08
Note: Harder to detect due to fewer data points per hour
Recommendation: Lower min_connections threshold to 6 for slow beacons
```

---

## Pattern 5: Jittered Beacon (harder to detect)

**Profile:** Advanced implant with randomized sleep + jitter to evade statistical analysis

**Statistical Profile:**
```
Mean interval:  240 seconds
CV:             0.28    ← Near threshold — borderline detection
Note: Random jitter in range 0-40% makes CV approach 0.3 limit
```

**Approach:** Combine with other signals (JA3, no PTR record, small fixed packet size)
for higher confidence.

---

## False Positive Mitigation

Common legitimate beaconing sources to whitelist:
```
Windows Update:          Every 22 hours to windowsupdate.com
NTP sync:               Every 64-1024 seconds to time.*.com
Browser telemetry:       Variable intervals to google.com, microsoft.com
Antivirus updates:       Periodic intervals to vendor domains
DHCP renewals:          Every ~12 hours (broadcast only)
```

**Whitelisting approach in beaconing_detector.py:**
```bash
python3 beaconing_detector.py --input conn.log \
  --whitelist-domains windowsupdate.com,microsoft.com,google.com \
  --min-connections 10 --threshold 0.3
```
