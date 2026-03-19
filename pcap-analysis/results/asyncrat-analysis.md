# =============================================================
# File: asyncrat-analysis.md
# =============================================================

# AsyncRAT PCAP Analysis Report

**Analyst:** Amoah Reinhard | **Date:** 2025-11-17 | **Threat Level:** HIGH

---

## Executive Summary

AsyncRAT (Asynchronous Remote Access Trojan) traffic was identified from host `192.168.1.78`.
AsyncRAT communicates over TCP with TLS encryption using a distinctive self-signed certificate
with `CN=AsyncRAT Server`. The malware establishes a persistent reverse TCP connection
to the attacker's server, enabling full remote control including keylogging, screen capture,
file transfer, and remote shell execution.

**MITRE Techniques:** T1219, T1573.002, T1071.001, T1083, T1113

---

## Network Indicators

### Infected Host
| Field | Value |
|-------|-------|
| IP | 192.168.1.78 |
| Hostname | OFFICE-PC-12 |
| OS | Windows 10 Home |

### AsyncRAT C2 Server
| IP | Port | Protocol | Notes |
|----|------|----------|-------|
| 91.92.241.103 | 6606 | TCP/TLS | Primary C2 |
| 91.92.241.103 | 7707 | TCP/TLS | Secondary port |

---

## Zeek Log Findings

### conn.log
```
src_ip          dst_ip          port  duration   orig_bytes  resp_bytes  conn_state
192.168.1.78    91.92.241.103   6606  00:08:42   284,521     1,204,800   SF
192.168.1.78    91.92.241.103   6606  00:00:05   512         256         SF (heartbeat)
192.168.1.78    91.92.241.103   6606  00:00:05   511         255         SF (heartbeat)
```

**Beaconing Analysis:**
- Heartbeat interval: 5.0 seconds (±0.2s)
- CV = 0.04 — HIGHLY REGULAR
- Confidence Score: 88.3/100 — BEACON CONFIRMED

### ssl.log — AsyncRAT Certificate Fingerprint
```
dst_ip          port  subject              issuer               JA3
91.92.241.103   6606  CN=AsyncRAT Server   CN=AsyncRAT Server   de9f2c7fd25e1b3afad3e85a0bd17d9b
                      ↑ Hardcoded default   ↑ Self-signed        ↑ AsyncRAT JA3 MATCH
```

**Certificate Red Flags:**
- Subject = Issuer (self-signed)
- CN is literally `AsyncRAT Server` — hardcoded in malware source
- No SAN (Subject Alternative Name) extension
- Validity: 365 days from infection date

### notice.log — Zeek Detections
```
C2_Beaconing_Detected  192.168.1.78 → 91.92.241.103  interval=5.0s  CV=0.04  count=104
C2_SSL_SelfSigned      192.168.1.78 → 91.92.241.103  CN=AsyncRAT Server
C2_JA3_Suspicious      192.168.1.78 → 91.92.241.103  JA3=de9f2c7fd25e1b3afad3e85a0bd17d9b
C2_No_PTR_Record       192.168.1.78 → 91.92.241.103  no reverse DNS
```

---

## Suricata Alerts

| SID | Signature | Hits |
|-----|-----------|------|
| 9000009 | C2 ASYNCRAT TLS JA3 Fingerprint | 104 |
| 9000008 | C2 TLS Non-Standard Port Suspicious Cert | 104 |

---

## IOCs Extracted

**IP Addresses:**
```
91.92.241.103    # AsyncRAT C2 server
```

**Ports:**
```
6606    # AsyncRAT default primary port
7707    # AsyncRAT default secondary port
```

**SSL Certificate:**
```
CN=AsyncRAT Server (self-signed)
```

**JA3 Hash:**
```
de9f2c7fd25e1b3afad3e85a0bd17d9b    # AsyncRAT TLS fingerprint
```

**File Hash (dropper from files.log):**
```
MD5: aefb9ef5b7a4d55b67d6f1b5fe6e4f91    # AsyncRAT.exe
```

---

## Attack Timeline

```
14:02:00  AsyncRAT initial connection → 91.92.241.103:6606
14:02:01  TLS handshake with self-signed AsyncRAT Server cert
14:02:02  Heartbeat begins (5s interval)
14:02:10  Attacker sends keylogger module
14:05:22  First screenshot captured (inferred from 200KB upload spike)
14:07:44  Directory listing requested (T1083)
14:09:00  Large data transfer — likely screen capture stream (1.2 MB to attacker)
14:10:42  Session ends (possible manual disconnect or AV detection)
```

---

## Detection Recommendations

1. Block IP `91.92.241.103` and ports 6606/7707 at the firewall
2. Add SSL inspection rule for `CN=AsyncRAT Server`
3. Block JA3 hash `de9f2c7fd25e1b3afad3e85a0bd17d9b` at perimeter
4. Isolate OFFICE-PC-12 and perform forensic imaging
5. Scan all hosts for AsyncRAT dropper hash
6. Implement outbound TLS inspection to catch non-standard ports
7. Hunt for similar 5-second beacon patterns on other hosts
