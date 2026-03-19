# =============================================================
# File: dns-tunneling-analysis.md
# =============================================================

# DNS Tunneling / Exfiltration PCAP Analysis Report

**Analyst:** Amoah Reinhard | **Date:** 2025-06-18 | **Threat Level:** HIGH

---

## Executive Summary

DNS-based data exfiltration was detected from host `192.168.1.33`. The attacker used
DNS TXT and A record queries to encode and exfiltrate data through the DNS protocol,
bypassing traditional network controls. The technique encoded data as Base64 subdomains
of an attacker-controlled domain (`exfil.c2ops.net`). A total of ~850 KB of data was
exfiltrated over 22 minutes using 4,200+ DNS queries.

**MITRE Techniques:** T1048, T1071.004, T1132.001

---

## Network Indicators

### Exfiltrating Host
| Field | Value |
|-------|-------|
| IP | 192.168.1.33 |
| Hostname | LAPTOP-SALES-08 |
| OS | Windows 10 |

### DNS Tunneling Infrastructure
| Domain | IP | Role |
|--------|-----|------|
| exfil.c2ops.net | 185.180.143.44 | Attacker NS + data receiver |
| c2ops.net | 185.180.143.44 | Attacker-registered domain |

---

## Zeek Log Findings

### dns.log — Anomalous Query Patterns

**Query volume spike:**
```
Time window: 10:15:00 – 10:37:00 (22 minutes)
Total DNS queries from 192.168.1.33: 4,218
Normal baseline: ~30 queries/minute
Observed rate: 191 queries/minute — 6.4x baseline
```

**Sample exfiltration queries (Base64-encoded data as subdomains):**
```
aGVsbG8td29ybGQtZWFzdHNpZGUtcHJvamVjdC01.exfil.c2ops.net      (46 chars)
dGhpcy1pcy1leGZpbHRyYXRlZC1kYXRhLWVuY29kZWQ.exfil.c2ops.net  (48 chars)
c2Vuc2l0aXZlLWRvY3VtZW50LWNvbnRlbnRzLWhlcmU.exfil.c2ops.net  (47 chars)
```

**Decoded Base64 samples:**
```
"hello-world-eastside-project-5"
"this-is-exfiltrated-data-encoded"
"sensitive-document-contents-here"
```

**DNS query type breakdown:**
```
A records:    3,814 (90.5%) — used for data encoding in subdomain
TXT queries:    312 (7.4%) — used for C2 commands (attacker to victim)
MX queries:      92 (2.1%) — used for synchronization
```

**NXDOMAIN ratio:**
```
NXDOMAIN responses: 3,814 / 4,218 = 90.4% (normal < 5%)
→ Expected: attacker domain returns NXDOMAIN to acknowledge receipt
```

### notice.log — Zeek Detections
```
DNS_High_Query_Volume    192.168.1.33  191 queries/min (threshold: 100)
DNS_Long_Subdomain       192.168.1.33  48 chars (threshold: 50) — near-miss
Exfil_DNS_Tunneling      192.168.1.33  subdomain length 46-48 chars
DNS_High_NXDOMAIN_Ratio  192.168.1.33  90.4% NXDOMAIN ratio (threshold: 70%)
```

### Entropy Analysis (from DGA detector)
```
Domain: aGVsbG8td29ybGQtZWFzdHNpZGUtcHJvamVjdC01.exfil.c2ops.net
First label entropy: 4.21 bits (threshold: 3.5) — HIGH ENTROPY CONFIRMED

Normal domain entropy range: 2.0 – 3.2 bits
Base64 domain entropy range: 3.8 – 4.5 bits
```

---

## Suricata Alerts

| SID | Signature | Hits |
|-----|-----------|------|
| 9000006 | C2 DNS Long Query Possible Tunneling | 127 |
| 9002002 | EXFIL DNS TXT Record Large Response | 18 |
| 9002003 | EXFIL DNS Subdomain Tunneling High Rate | 8 |

---

## Data Volume Estimation

```
Average subdomain length: 47 Base64 chars
Base64 decodes to: ~35 bytes of raw data per query
Total A record queries: 3,814
Estimated total exfiltrated: 3,814 × 35 = ~133 KB (raw)

TXT record responses (C2 commands back): 312 × avg 50 bytes = ~15 KB
Total bi-directional DNS tunnel traffic: ~148 KB DNS payload
```

---

## IOCs Extracted

**Domains:**
```
exfil.c2ops.net    # DNS tunneling receiver
c2ops.net          # Attacker-registered domain
```

**IP Addresses:**
```
185.180.143.44    # Attacker nameserver / data receiver
```

**DNS Patterns:**
```
/^[A-Za-z0-9+\/]{30,}={0,2}\.exfil\./    # Base64 subdomain pattern
```

**Query Rate Threshold Exceeded:**
```
191 queries/minute from 192.168.1.33 (6.4× normal)
```

---

## Attack Timeline

```
10:15:00  First anomalous DNS query to exfil.c2ops.net
10:15:01  Rapid-fire Base64-encoded A record queries begin
10:15:00  10:15:01  192.168.1.33 queries: 200/min
10:20:00  TXT responses begin — C2 acknowledging data receipt
10:30:00  Brief 2-minute pause (possible chunk boundary)
10:32:00  Second burst of queries begins
10:37:00  DNS tunneling session ends — total 22 minutes
```

---

## Detection Recommendations

1. Block domain `c2ops.net` and IP `185.180.143.44` in DNS firewall
2. Implement DNS rate limiting — alert on >50 queries/minute per host
3. Enable DNS TXT record inspection — log all TXT responses > 50 chars
4. Deploy DNS entropy analysis (dga_detector.py) against dns.log daily
5. Use DNS RPZ (Response Policy Zone) to block suspicious new domains
6. Alert on NXDOMAIN ratio > 50% over any 5-minute window per source
7. Consider DNS-over-HTTPS blocking to prevent bypassing DNS monitoring
