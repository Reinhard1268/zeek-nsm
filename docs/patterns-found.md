# Malicious Patterns Found — Project 5 Zeek NSM

**Compiled from:** PCAP analyses, live testing, and anomaly detection runs  
**Author:** Amoah Reinhard
**Last Updated:** 2026-03-11

All patterns below were detected using the Zeek scripts and Python tools built in this project.
Each entry includes the pattern name, detection method, expected detections, confidence level,
and false positive risk.

---

## Category 1: C2 Beaconing

### Pattern 1.1 — Emotet 60-Second HTTP Beacon

| Field | Value |
|-------|-------|
| **Pattern Name** | Emotet Epoch 4 HTTP Beacon |
| **Description** | Infected host POSTs ~45KB encoded system data to C2 server every 60 seconds |
| **Zeek Fields** | `conn.log`: id.orig_h, id.resp_h, ts, orig_bytes; `http.log`: method=POST, uri=/[a-z]{4-8}/[a-z]{4-8}/ |
| **Statistical Signature** | CV < 0.01, mean_interval ≈ 60s, orig_bytes ≈ 45,000 per connection |
| **Zeek Detection** | `C2_Beaconing_Detected` (BeaconingDetect module) |
| **Suricata Rule** | SID 9003001 — MALWARE EMOTET HTTP C2 Check-in |
| **Python Detection** | `beaconing_detector.py` — confidence score 94-99/100 |
| **Confidence** | VERY HIGH |
| **False Positive Risk** | LOW — no legitimate app POSTs 45KB to bare IP every 60s |
| **Mitigation** | Block C2 IP, isolate host, hunt internal SMB spread |

---

### Pattern 1.2 — Cobalt Strike HTTPS Beacon (jQuery Profile)

| Field | Value |
|-------|-------|
| **Pattern Name** | Cobalt Strike Malleable C2 jQuery Profile |
| **Description** | Beacon GETs a fake jQuery file then POSTs encoded check-in data at ~60s intervals |
| **Zeek Fields** | `ssl.log`: ja3, subject, issuer; `http.log`: uri=/jquery-*.min.js, method=GET/POST |
| **Statistical Signature** | CV ≈ 0.02, JA3=a0e9f5d64349fb13191bc781f81f42e1, self-signed cert, no PTR |
| **Zeek Detection** | `C2_Beaconing_Detected`, `C2_JA3_Suspicious`, `C2_SSL_SelfSigned` |
| **Suricata Rule** | SID 9000001, 9000002 — CS HTTP Beacon + JA3 |
| **Python Detection** | `beaconing_detector.py` confidence 96/100; `ml_classifier.py` BeaconClassifier |
| **Confidence** | VERY HIGH |
| **False Positive Risk** | VERY LOW — JA3 match is definitive |
| **Mitigation** | Block JA3 hash, TLS inspect outbound, isolate host |

---

### Pattern 1.3 — AsyncRAT 5-Second Heartbeat

| Field | Value |
|-------|-------|
| **Pattern Name** | AsyncRAT TCP Heartbeat |
| **Description** | 512-byte encrypted heartbeat every 5 seconds to non-standard port 6606 |
| **Zeek Fields** | `ssl.log`: subject=CN=AsyncRAT Server, port=6606, ja3=de9f2c7... |
| **Statistical Signature** | CV ≈ 0.04, interval=5s, port=6606/7707, self-signed AsyncRAT cert |
| **Zeek Detection** | `C2_Beaconing_Detected`, `C2_SSL_SelfSigned`, `C2_JA3_Suspicious` |
| **Suricata Rule** | SID 9000009, 9003004 |
| **Python Detection** | `beaconing_detector.py` confidence 88/100 |
| **Confidence** | VERY HIGH |
| **False Positive Risk** | VERY LOW — CN=AsyncRAT Server is hardcoded malware string |
| **Mitigation** | Block port 6606/7707, hunt dropper hash on endpoint |

---

## Category 2: DNS Anomalies

### Pattern 2.1 — DNS Subdomain Exfiltration (Base64 Encoding)

| Field | Value |
|-------|-------|
| **Pattern Name** | DNS Base64 Subdomain Exfiltration |
| **Description** | Stolen data encoded as Base64 subdomain labels, sent to attacker nameserver |
| **Zeek Fields** | `dns.log`: query (label length >40, entropy >3.8), rcode=NXDOMAIN, qtype=A |
| **Statistical Signature** | NXDOMAIN ratio >90%, query rate >100/min, entropy >3.8 bits |
| **Zeek Detection** | `Exfil_DNS_Tunneling`, `DNS_High_NXDOMAIN_Ratio`, `DNS_High_Entropy_Domain` |
| **Suricata Rule** | SID 9000006, 9002002, 9002003 |
| **Python Detection** | `dga_detector.py` flags base64 labels; `exfil_detector.py` volume+NXDOMAIN |
| **Confidence** | HIGH |
| **False Positive Risk** | LOW — NXDOMAIN 90%+ with Base64 labels is nearly definitive |
| **Mitigation** | DNS firewall block on attacker domain, rate-limit DNS, deploy DNS RPZ |

---

### Pattern 2.2 — DGA Domain Querying

| Field | Value |
|-------|-------|
| **Pattern Name** | DGA Domain Generation Algorithm |
| **Description** | Malware queries algorithmically-generated random-looking domains to find active C2 |
| **Zeek Fields** | `dns.log`: query (high entropy, low bigram score, length 12-20), NXDOMAIN |
| **Statistical Signature** | Shannon entropy >3.5, consonant/vowel ratio >3.0, bigram score <0.05 |
| **Zeek Detection** | `DNS_High_Entropy_Domain`, `DNS_High_NXDOMAIN_Ratio` |
| **Suricata Rule** | SID 9000006 |
| **Python Detection** | `dga_detector.py` RandomForest — precision 91.8%, recall 96.3% |
| **Confidence** | HIGH |
| **False Positive Risk** | MEDIUM — some CDN subdomains have high entropy (whitelist needed) |
| **Mitigation** | Block high-scoring domains, investigate originating host |

---

## Category 3: Data Exfiltration

### Pattern 3.1 — High-Volume HTTP POST Exfiltration

| Field | Value |
|-------|-------|
| **Pattern Name** | Large HTTP POST Data Exfiltration |
| **Description** | Malware or insider threat uploads large amounts of data via HTTP POST to external IP |
| **Zeek Fields** | `http.log`: method=POST, request_body_len>5MB, host=bare IP |
| **Statistical Signature** | Single POST body >5 MB, destination = external IP, no hostname |
| **Zeek Detection** | `Exfil_HTTP_Large_POST` |
| **Suricata Rule** | SID 9002001 |
| **Python Detection** | `exfil_detector.py` HTTP_LARGE_POST alert |
| **Confidence** | HIGH |
| **False Positive Risk** | MEDIUM — file upload services (S3, Dropbox) can trigger — use domain whitelist |
| **Mitigation** | Block destination IP, DLP inspection on HTTP POST |

---

## Category 4: Lateral Movement

### Pattern 4.1 — SMB PsExec Lateral Movement

| Field | Value |
|-------|-------|
| **Pattern Name** | PsExec Remote Execution via SMB |
| **Description** | Attacker writes PSEXESVC.exe to ADMIN$ share and creates remote service |
| **Zeek Fields** | `smb-monitor.log`: action=PSEXEC_BINARY, path=PSEXESVC.exe, share=ADMIN$ |
| **Statistical Signature** | PSEXESVC string in SMB write to ADMIN$ share |
| **Zeek Detection** | `SMB_PsExec_Pattern`, `SMB_Admin_Share_Access` |
| **Suricata Rule** | SID 9001002, 9001006 |
| **Python Detection** | `correlator.py` groups SMB scan + PsExec for high threat score |
| **Confidence** | VERY HIGH |
| **False Positive Risk** | LOW — PSEXESVC.exe to ADMIN$ is almost exclusively malicious |
| **Mitigation** | Block PsExec via AppLocker, restrict ADMIN$ access via GPO |

---

### Pattern 4.2 — NTLM Credential Spray / Pass-the-Hash

| Field | Value |
|-------|-------|
| **Pattern Name** | NTLM Credential Spray / Pass-the-Hash |
| **Description** | Attacker authenticates with captured NTLM hash to multiple hosts |
| **Zeek Fields** | `lateral-movement.log`: indicator=AUTH_SPRAY, host_count>5 |
| **Statistical Signature** | >5 SMB auth attempts from single source in <3 minutes, no prior failed password |
| **Zeek Detection** | `LM_Auth_Spray` |
| **Suricata Rule** | SID 9001005 — NTLM Type1 without username (PTH indicator) |
| **Python Detection** | `correlator.py` combines with SMB scan for CRITICAL verdict |
| **Confidence** | HIGH |
| **False Positive Risk** | LOW — PTH pattern (no username in NTLM Type1) is distinctive |
| **Mitigation** | Enable SMB signing, deploy Credential Guard, monitor DC logs |

---

## Pattern Summary Table

| # | Pattern | Category | Zeek Notice | Suricata SID | Confidence | FP Risk |
|---|---------|----------|------------|--------------|-----------|---------|
| 1.1 | Emotet HTTP Beacon | C2 | C2_Beaconing_Detected | 9003001 | VERY HIGH | LOW |
| 1.2 | CS jQuery Profile | C2 | C2_JA3_Suspicious | 9000001/9000002 | VERY HIGH | VERY LOW |
| 1.3 | AsyncRAT Heartbeat | C2 | C2_SSL_SelfSigned | 9000009/9003004 | VERY HIGH | VERY LOW |
| 2.1 | DNS Subdomain Exfil | Exfil/DNS | Exfil_DNS_Tunneling | 9000006 | HIGH | LOW |
| 2.2 | DGA Querying | DNS | DNS_High_Entropy | — | HIGH | MEDIUM |
| 3.1 | HTTP POST Exfil | Exfil | Exfil_HTTP_Large_POST | 9002001 | HIGH | MEDIUM |
| 4.1 | PsExec via SMB | Lateral | SMB_PsExec_Pattern | 9001002 | VERY HIGH | LOW |
| 4.2 | NTLM Spray/PTH | Lateral | LM_Auth_Spray | 9001005 | HIGH | LOW |

---

## Detection Coverage Summary

```
Total patterns documented:      8
MITRE ATT&CK techniques covered: 12
  T1071.001 — Application Layer Protocol: Web
  T1071.004 — Application Layer Protocol: DNS
  T1573.002 — Encrypted Channel: Asymmetric
  T1048     — Exfiltration Over Alternative Protocol
  T1048.003 — Exfiltration Over Alternative Protocol: Web
  T1021.002 — Remote Services: SMB/Windows Admin Shares
  T1569.002 — System Services: Service Execution
  T1110.003 — Brute Force: Password Spraying
  T1550.002 — Use Alternate Authentication Material: PTH
  T1041     — Exfiltration Over C2 Channel
  T1082     — System Information Discovery
  T1018     — Remote System Discovery
```
