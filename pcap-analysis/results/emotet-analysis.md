# =============================================================
# File: emotet-analysis.md
# =============================================================

# Emotet C2 PCAP Analysis Report

**Analyst:** Amoah Reinhard | **Date:** 2025-12-15 | **Threat Level:** CRITICAL

---

## Executive Summary

Analysis of a captured Emotet infection traffic sample revealed active C2 communication
between infected Windows host `192.168.1.55` and three external C2 servers. Emotet used
HTTP POST requests with encoded payloads to check in, download a TrickBot secondary payload,
and exfiltrate system recon data. Beaconing was detected at a 60-second interval with
CV=0.023 — a near-perfect machine-generated pattern.

**MITRE Techniques:** T1071.001, T1027, T1041, T1082, T1059.001

---

## Network Indicators

### Infected Host
| Field | Value |
|-------|-------|
| IP | 192.168.1.55 |
| Hostname | WORKSTATION-7 |
| OS | Windows 10 x64 |

### C2 Servers
| IP | Port | Country | Role |
|----|------|---------|------|
| 45.33.32.156 | 80 | US | Emotet primary C2 |
| 185.220.101.10 | 8080 | DE | TrickBot C2 |
| 103.75.190.11 | 443 | SG | Payload delivery |

---

## Zeek Log Findings

### conn.log — Beaconing
```
src_ip          dst_ip          interval   orig_bytes  conn_state
192.168.1.55    45.33.32.156    60.3s avg  45,231      SF (12 connections)
  → CV = 0.023 | Confidence Score = 94.5/100 | BEACON CONFIRMED
```

### http.log — C2 Check-ins
```
method  host            uri                   status  resp_bytes
POST    45.33.32.156    /bqkV2/Kx9m/          200     8,192    ← Emotet epoch pattern
POST    185.220.101.10  /images/abcd1234efgh/ 200     102,400  ← TrickBot C2
GET     103.75.190.11   /update.exe           200     512,000  ← Payload download
```

### ssl.log — Suspicious Certificate
```
dst_ip          subject                   issuer                    JA3
103.75.190.11   CN=lab.example.com        CN=lab.example.com        a0e9f5d64349fb13191bc781f81f42e1
                ↑ Self-signed                                        ↑ Cobalt Strike fingerprint
```

---

## Suricata Alerts

| SID | Signature | Hits |
|-----|-----------|------|
| 9003001 | MALWARE EMOTET HTTP C2 Check-in | 12 |
| 9000001 | C2 COBALT STRIKE Default HTTP Beacon | 1 |
| 9002001 | EXFIL Large HTTP POST to External | 1 |
| 9000007 | C2 BEACON Regular HTTP GET Pattern | 1 |

---

## IOCs Extracted

**IP Addresses:**
```
45.33.32.156        # Emotet C2 Epoch 4
185.220.101.10      # TrickBot C2
103.75.190.11       # Payload delivery server
```

**URLs:**
```
http://45.33.32.156/bqkV2/Kx9m/
http://185.220.101.10/images/abcd1234efgh/
http://103.75.190.11/update.exe
```

**File Hash (update.exe — TrickBot dropper):**
```
MD5:  d41d8cd98f00b204e9800998ecf8427e
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
```

**JA3:** `a0e9f5d64349fb13191bc781f81f42e1`

---

## Attack Timeline

```
08:23:11  Emotet C2 check-in → 45.33.32.156:80 POST /bqkV2/Kx9m/ (45 KB recon data)
08:24:11  Beacon #2 (60s interval)
08:25:12  Beacon #3 (+61s — 1s jitter)
08:45:00  C2 instructs infected host to download secondary payload
08:47:22  TrickBot C2 contact → 185.220.101.10:8080 (100 KB module download)
09:15:44  Third C2 contacted → 103.75.190.11:443 (SSL self-signed)
09:16:02  update.exe downloaded (512 KB — TrickBot dropper)
09:17:00  Infection chain complete
```

---

## Detection Recommendations

1. Block all 3 C2 IPs at the perimeter firewall immediately
2. Isolate WORKSTATION-7 — reimage required
3. Hunt for lateral movement (Emotet + TrickBot both spread internally via SMB)
4. Add Suricata rules for the `/[a-z]{4,8}/[a-z]{4,8}/` Emotet URL pattern
5. Update EDR signatures for TrickBot dropper hash
6. Review all internal hosts that contacted these IPs in the past 30 days
