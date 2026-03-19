# =============================================================
# File: cobalt-strike-analysis.md
# =============================================================

# Cobalt Strike Beacon PCAP Analysis Report

**Analyst:** Amoah Reinhard | **Date:** 2025-09-16 | **Threat Level:** CRITICAL

---

## Executive Summary

Analysis of a Cobalt Strike beacon infection revealed a compromised internal host
(`192.168.1.42`) maintaining persistent HTTPS C2 communication with an attacker-controlled
server. The malleable C2 profile mimicked legitimate jQuery CDN traffic.
JA3 fingerprinting positively identified the Cobalt Strike default TLS fingerprint.
Post-exploitation activity included credential harvesting, internal reconnaissance,
and lateral movement via SMB.

**MITRE Techniques:** T1071.001, T1573.002, T1055, T1003.001, T1021.002, T1569.002

---

## Network Indicators

### Compromised Host
| Field | Value |
|-------|-------|
| IP | 192.168.1.42 |
| Hostname | DEV-LAPTOP-3 |
| OS | Windows 11 x64 |
| User | jsmith |

### Cobalt Strike Team Server
| IP | Port | Protocol | Notes |
|----|------|----------|-------|
| 185.220.101.45 | 443 | HTTPS | CS Team Server — jQuery profile |
| 185.220.101.45 | 80 | HTTP | Fallback channel |

---

## Zeek Log Findings

### conn.log — Beacon Pattern
```
src_ip          dst_ip            port  interval    connections  CV      confidence
192.168.1.42    185.220.101.45    443   58.7s avg   18           0.019   96.1/100
→ COBALT STRIKE BEACON CONFIRMED (default sleep=60s with ±5% jitter)
```

### http.log — Malleable C2 Profile (jQuery)
```
method  uri                                          user_agent                                     status
GET     /jquery-3.3.1.min.js                         Mozilla/5.0 (Windows NT 10.0; Win64; x64)     200
POST    /jquery-3.3.1.min.js                         Mozilla/5.0 (Windows NT 10.0; Win64; x64)     200
GET     /____cldct____/__init__.js                   Mozilla/5.0 (Windows NT 10.0; Win64; x64)     404
```

**Profile Analysis:**
- GET requests load the decoy jQuery file
- POST requests carry encrypted beacon check-in data
- Response body contains encoded C2 tasks
- Content-Type spoofed as `application/javascript`

### ssl.log — TLS Fingerprint Match
```
dst_ip            port  subject                      issuer                      JA3
185.220.101.45    443   CN=jquery-cdn.net            CN=jquery-cdn.net           a0e9f5d64349fb13191bc781f81f42e1
                        ↑ Fake jQuery CDN domain      ↑ Self-signed cert          ↑ CS default JA3 MATCH
```

**SSL Certificate Details:**
- Not Before: 2024-05-01
- Not After: 2025-05-01
- Unusual: Self-signed cert for "CDN" domain — legitimate CDNs use CA-signed certs

### files.log — Staged Payload
```
filename      mime_type              md5                               size    source
beacon.exe    application/x-dosexec  5f4dcc3b5aa765d61d8327deb882cf99  512000  192.168.1.42
```

---

## Post-Exploitation Activity Observed

### Internal Reconnaissance (from conn.log)
```
08:45:00  192.168.1.42 → 192.168.1.0/24  port 445   (SMB scan — 24 hosts in 30s)
08:45:30  192.168.1.42 → 192.168.1.20    port 135   (WMI DCOM)
08:46:00  192.168.1.42 → 192.168.1.20    port 445   (Lateral movement attempt)
```

### Credential Harvesting (from notice.log)
```
NOTICE: LM_SMB_Multi_Host_Scan — 192.168.1.42 scanned 24 SMB hosts
NOTICE: LM_WMI_Remote_Exec    — 192.168.1.42 → 192.168.1.20 port 135
NOTICE: SMB_PsExec_Pattern    — PSEXESVC.exe written to \\192.168.1.20\ADMIN$
```

---

## Suricata Alerts

| SID | Signature | Hits |
|-----|-----------|------|
| 9000002 | C2 COBALT STRIKE TLS JA3 Fingerprint | 18 |
| 9000001 | C2 COBALT STRIKE Default HTTP Beacon | 3 |
| 9001001 | LATERAL MOVEMENT SMB Multi-Host Scan | 1 |
| 9001002 | LATERAL MOVEMENT PsExec Service Binary | 1 |
| 9001004 | LATERAL MOVEMENT WMI Remote Execution | 1 |

---

## IOCs Extracted

**IP Addresses:**
```
185.220.101.45    # Cobalt Strike Team Server
192.168.1.20      # Laterally compromised host
```

**Domains:**
```
jquery-cdn.net    # Attacker-controlled fake CDN domain
```

**JA3 Hash:**
```
a0e9f5d64349fb13191bc781f81f42e1    # Cobalt Strike default TLS fingerprint
```

**URLs:**
```
https://185.220.101.45/jquery-3.3.1.min.js
https://185.220.101.45/jquery-3.3.1.min.js  (POST — beacon check-in)
```

**SSL Certificate:**
```
CN=jquery-cdn.net  (self-signed, suspicious CA, issued 2024-05-01)
```

---

## Attack Timeline

```
07:00:00  Initial compromise (phishing email — assumed, not in PCAP)
08:12:30  First Cobalt Strike beacon → 185.220.101.45:443
08:13:28  Beacon #2 (+58s)
...
08:44:00  Operator sends commands via C2 channel
08:45:00  Internal SMB scan begins — 24 hosts in 30 seconds
08:45:30  WMI DCOM connection to 192.168.1.20
08:46:00  SMB connection to 192.168.1.20 ADMIN$ share
08:46:05  PSEXESVC.exe written to \\192.168.1.20\ADMIN$
08:46:15  Lateral movement to 192.168.1.20 — second beacon established
```

---

## Detection Recommendations

1. Block JA3 hash `a0e9f5d64349fb13191bc781f81f42e1` at TLS inspection points
2. Block domain `jquery-cdn.net` and IP `185.220.101.45`
3. Isolate both `192.168.1.42` and `192.168.1.20` — full IR required
4. Hunt all internal hosts for PSEXESVC.exe presence
5. Review all HTTPS sessions with 58-62 second intervals to external IPs
6. Implement PowerShell ScriptBlock logging and review jsmith's activity
7. Reset credentials for user `jsmith` — likely harvested by CS Mimikatz module
