# =============================================================
# File: ioc-master-list.md
# =============================================================

# IOC Master List — Project 5 Zeek NSM

**Compiled from:** All 5 PCAP analyses + Zeek/Suricata detections  
**Last Updated:** 2025-03-11  
**Analyst:** Amoah Reinhard

---

## IP Addresses

| IP Address | Port(s) | Malware Family | Role | Confidence | Source Analysis |
|------------|---------|---------------|------|-----------|----------------|
| 45.33.32.156 | 80 | Emotet Epoch 4 | C2 primary | HIGH | emotet-analysis.md |
| 185.220.101.10 | 8080 | TrickBot | C2 | HIGH | emotet-analysis.md |
| 103.75.190.11 | 443 | Emotet/TrickBot | Payload delivery | HIGH | emotet-analysis.md |
| 185.220.101.45 | 443, 80 | Cobalt Strike | Team Server | VERY HIGH | cobalt-strike-analysis.md |
| 91.92.241.103 | 6606, 7707 | AsyncRAT | C2 | VERY HIGH | asyncrat-analysis.md |
| 185.180.143.44 | 53 | DNS Tunneling | Attacker NS | HIGH | dns-tunneling-analysis.md |

---

## Domains

| Domain | Malware Family | Role | Registrar Pattern | Source |
|--------|---------------|------|------------------|--------|
| jquery-cdn.net | Cobalt Strike | Fake CDN typosquatting | Registered 30 days prior | cobalt-strike-analysis.md |
| exfil.c2ops.net | DNS Tunneling | Data receiver | Attacker NS | dns-tunneling-analysis.md |
| c2ops.net | DNS Tunneling | Attacker TLD | Newly registered | dns-tunneling-analysis.md |

---

## File Hashes

| Hash | Type | Filename | Malware Family | Source |
|------|------|----------|---------------|--------|
| d41d8cd98f00b204e9800998ecf8427e | MD5 | update.exe | TrickBot dropper | emotet-analysis.md |
| da39a3ee5e6b4b0d3255bfef95601890afd80709 | SHA1 | update.exe | TrickBot dropper | emotet-analysis.md |
| 5f4dcc3b5aa765d61d8327deb882cf99 | MD5 | beacon.exe | Cobalt Strike | cobalt-strike-analysis.md |
| aefb9ef5b7a4d55b67d6f1b5fe6e4f91 | MD5 | AsyncRAT.exe | AsyncRAT | asyncrat-analysis.md |

---

## JA3 Hashes

| JA3 Hash | Malware Family | Confidence | Source |
|----------|---------------|-----------|--------|
| a0e9f5d64349fb13191bc781f81f42e1 | Cobalt Strike (default profile) | VERY HIGH | cobalt-strike-analysis.md, emotet-analysis.md |
| 72a589da586844d7f0818ce684948eea | Metasploit Meterpreter | HIGH | c2-ssl-patterns.md |
| de9f2c7fd25e1b3afad3e85a0bd17d9b | AsyncRAT | VERY HIGH | asyncrat-analysis.md |

---

## SSL Certificates

| Subject / CN | Issuer | Notes | Malware | Source |
|-------------|--------|-------|---------|--------|
| CN=AsyncRAT Server | CN=AsyncRAT Server | Self-signed, hardcoded CN | AsyncRAT | asyncrat-analysis.md |
| CN=jquery-cdn.net | CN=jquery-cdn.net | Self-signed fake CDN cert | Cobalt Strike | cobalt-strike-analysis.md |
| CN=lab.example.com | CN=lab.example.com | Self-signed generic | Emotet loader | emotet-analysis.md |

---

## URLs

| URL | Method | Malware | Pattern Description |
|-----|--------|---------|---------------------|
| `http://45.33.32.156/bqkV2/Kx9m/` | POST | Emotet | Epoch 4 URL pattern `/[a-z]{4-8}/[a-z]{4-8}/` |
| `http://185.220.101.10/images/abcd1234efgh/` | POST | TrickBot | TrickBot image path pattern |
| `http://103.75.190.11/update.exe` | GET | TrickBot dropper | Executable delivery |
| `https://185.220.101.45/jquery-3.3.1.min.js` | GET/POST | Cobalt Strike | jQuery malleable C2 profile |

---

## DNS IOCs

| Domain Pattern | Type | Malware | Source |
|---------------|------|---------|--------|
| `*.exfil.c2ops.net` | DNS tunnel receiver | DNS Tunneling | dns-tunneling-analysis.md |
| `[A-Za-z0-9+/]{30,}.exfil-domain.net` | Base64 subdomain exfil | DNS Tunneling | dns-exfil-patterns.md |

---

## Network Behavior IOCs (Statistical)

| Behavior | Value | Malware | Detection Method |
|----------|-------|---------|-----------------|
| Beacon interval | 60.0s (CV=0.005) | Emotet | beaconing_detector.py |
| Beacon interval | 60.3s (CV=0.020) | Cobalt Strike | beaconing_detector.py |
| Heartbeat interval | 5.0s (CV=0.040) | AsyncRAT | beaconing_detector.py |
| DNS query rate | 191 queries/min | DNS Tunneling | dns-anomaly.zeek |
| NXDOMAIN ratio | 90.4% | DNS Tunneling | dns-anomaly.zeek |
| HTTP POST body size | 45 KB recurring | Emotet | data-exfil-detect.zeek |

---

## Internal Hosts Compromised

| IP | Hostname | Method | Malware | Source |
|----|----------|--------|---------|--------|
| 192.168.1.55 | WORKSTATION-7 | Phishing | Emotet + TrickBot | emotet-analysis.md |
| 192.168.1.42 | DEV-LAPTOP-3 | Unknown initial vector | Cobalt Strike | cobalt-strike-analysis.md |
| 192.168.1.78 | OFFICE-PC-12 | Phishing | AsyncRAT | asyncrat-analysis.md |
| 192.168.1.33 | LAPTOP-SALES-08 | Unknown | DNS Tunnel exfil tool | dns-tunneling-analysis.md |
| 192.168.1.20 | FILE-SERVER-1 | PsExec (lateral) | Cobalt Strike | lateral-movement-analysis.md |
| 192.168.1.25 | HR-PC-05 | WMI (lateral) | Cobalt Strike | lateral-movement-analysis.md |
| 192.168.1.30 | FINANCE-WS-2 | SMB (lateral) | Cobalt Strike | lateral-movement-analysis.md |
| 192.168.1.35 | DC-01 | Pass-the-Hash | Cobalt Strike | lateral-movement-analysis.md |

---

## Suricata Rule SIDs Triggered

| SID | Signature | Malware | Hits Total |
|-----|-----------|---------|-----------|
| 9000001 | C2 COBALT STRIKE Default HTTP Beacon | Cobalt Strike | 4 |
| 9000002 | C2 COBALT STRIKE TLS JA3 Fingerprint | Cobalt Strike | 18 |
| 9000006 | C2 DNS Long Query Possible Tunneling | DNS Tunnel | 127 |
| 9000007 | C2 BEACON Regular HTTP GET Pattern | Emotet/CS | 2 |
| 9000008 | C2 TLS Non-Standard Port Suspicious Cert | AsyncRAT/CS | 105 |
| 9000009 | C2 ASYNCRAT TLS JA3 Fingerprint | AsyncRAT | 104 |
| 9001001 | LATERAL MOVEMENT SMB Multi-Host Scan | — | 1 |
| 9001002 | LATERAL MOVEMENT PsExec Service Binary | — | 2 |
| 9001004 | LATERAL MOVEMENT WMI Remote Execution | — | 3 |
| 9001005 | LATERAL MOVEMENT Pass-the-Hash NTLM | — | 22 |
| 9002001 | EXFIL Large HTTP POST to External | Emotet | 1 |
| 9002002 | EXFIL DNS TXT Record Large Response | DNS Tunnel | 18 |
| 9002003 | EXFIL DNS Subdomain Tunneling High Rate | DNS Tunnel | 8 |
| 9003001 | MALWARE EMOTET HTTP C2 Check-in | Emotet | 12 |
| 9003004 | MALWARE ASYNCRAT SSL Certificate | AsyncRAT | 104 |

---

## Recommended Firewall Blocks

```
# IP blocks
45.33.32.156/32
185.220.101.10/32
103.75.190.11/32
185.220.101.45/32
91.92.241.103/32
185.180.143.44/32

# Domain blocks (DNS firewall / RPZ)
jquery-cdn.net
c2ops.net
exfil.c2ops.net

# Port blocks (outbound — review per environment)
6606/tcp    (AsyncRAT)
7707/tcp    (AsyncRAT)
4443/tcp    (Cobalt Strike alt listener)
```
