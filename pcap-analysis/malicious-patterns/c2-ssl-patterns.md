# =============================================================
# File: c2-ssl-patterns.md
# =============================================================

# SSL/TLS C2 Indicators Reference

## Why Attackers Use TLS for C2

TLS encryption hides payload content from deep packet inspection. Most enterprise
firewalls allow outbound HTTPS (port 443) without content inspection.
Attackers leverage TLS to make C2 traffic appear as normal web browsing.

However, TLS metadata — certificates, JA3 fingerprints, handshake patterns —
still leaks enough information for detection without decrypting traffic.

---

## Indicator 1: JA3 Fingerprinting

JA3 is an MD5 hash of TLS ClientHello parameters. Malware frameworks produce
distinctive JA3 hashes because they use custom TLS libraries, not standard browsers.

### Known Malicious JA3 Hashes

| JA3 Hash | Malware Family | Notes |
|----------|---------------|-------|
| `a0e9f5d64349fb13191bc781f81f42e1` | Cobalt Strike | Default CS TLS profile |
| `72a589da586844d7f0818ce684948eea` | Metasploit Meterpreter | Default reverse HTTPS |
| `de9f2c7fd25e1b3afad3e85a0bd17d9b` | AsyncRAT | .NET TLS default |
| `4d7a28d6f2263ed61de88ca66eb011e3` | Sliver C2 | Go TLS client |
| `b386946a5a44d1ddcc843bc75336dfce` | Havoc C2 | Custom implant |
| `d0ec3b5f84b63bb40fa5e8e2b3e9e7f5` | Brute Ratel | Commercial C2 |

### Zeek ssl.log JA3 Detection Example
```
ts             id.orig_h      id.resp_h         ja3                                 ja3s
1718437391     192.168.1.42   185.220.101.45    a0e9f5d64349fb13191bc781f81f42e1   ← CS MATCH
```

### Detection in Zeek
```zeek
# c2-patterns.zeek fires this notice:
C2_JA3_Suspicious: 192.168.1.42 -> 185.220.101.45
  JA3: a0e9f5d64349fb13191bc781f81f42e1 (Cobalt Strike default)
```

---

## Indicator 2: Self-Signed Certificates

Legitimate HTTPS services use CA-signed certificates. Malware C2 servers
typically generate self-signed certs because:
- They don't own a real domain (or use throwaway domains)
- They can't obtain a CA cert for an IP address
- They generate the cert programmatically at install time

### Zeek ssl.log Detection
```
subject          issuer            valid_from   valid_until  self_signed
CN=AsyncRAT      CN=AsyncRAT       2024-06-01   2025-06-01   TRUE   ← ALERT
CN=Metasploit    CN=Metasploit     2024-05-10   2025-05-10   TRUE   ← ALERT
```

**Self-signed detection:** `subject == issuer`

### Common Malware Certificate Patterns

| CN Pattern | Malware |
|-----------|---------|
| `CN=AsyncRAT Server` | AsyncRAT (hardcoded) |
| `CN=Metasploit` | Metasploit default |
| `CN=<random 8 chars>` | Cobalt Strike custom profile |
| `CN=localhost` | Generic RAT |
| `CN=<victim hostname>` | Some loaders mimic victim machine |

---

## Indicator 3: Certificate on Non-Standard Port

Legitimate HTTPS uses port 443. C2 servers on non-standard TLS ports are suspicious,
especially when combined with self-signed certificates.

### Common Malware TLS Ports

| Port | Malware / Use Case |
|------|--------------------|
| 4443 | Cobalt Strike default HTTPS listener |
| 8443 | Empire, Havoc, generic C2 |
| 6606 | AsyncRAT primary |
| 7707 | AsyncRAT secondary |
| 9001 | Tor-like C2 |
| 1337 | Generic hacker/testing |
| 8080 | TrickBot, generic fallback |

### Zeek Detection
```
C2_SSL_SelfSigned: 192.168.1.78 -> 91.92.241.103:6606
  CN=AsyncRAT Server (self-signed, non-standard port)
```

---

## Indicator 4: Expired TLS Certificates

Attackers often use certificates past their expiration date because:
- They generated the cert during setup and never renewed it
- The cert was self-signed with a short validity period
- The malware doesn't validate cert expiry

### Zeek Detection
```
C2_SSL_Expired: 192.168.1.55 -> 45.33.32.156:443
  cert expired: 2025-12-01 (4 months ago)
```

---

## Indicator 5: Unusual Certificate Attributes

| Attribute | Suspicious Pattern | Normal Pattern |
|-----------|-------------------|----------------|
| CN | Generic/random string | Real domain name |
| SANs | Missing or single IP | Multiple domain names |
| Issuer | Same as Subject | Trusted CA name |
| Key size | 1024-bit RSA | 2048+ or ECDSA |
| Signature algo | MD5, SHA1 | SHA256+ |
| Validity period | < 30 days or > 3 years | 90 days – 1 year |

---

## Indicator 6: TLS to IP Address (No SNI)

Legitimate TLS connections include a Server Name Indication (SNI) extension with
the hostname. C2 connections to bare IP addresses often omit SNI.

### Zeek ssl.log
```
server_name field is empty when connecting to IP directly
```

### Detection query (Kibana KQL)
```
event.dataset: zeek.ssl AND NOT tls.server_name: * AND destination.ip: *
```

---

## Detection Summary

| Indicator | Zeek Notice | Suricata SID | Confidence |
|-----------|------------|--------------|-----------|
| Known JA3 hash | C2_JA3_Suspicious | 9000002, 9000003, 9000009 | VERY HIGH |
| Self-signed cert | C2_SSL_SelfSigned | 9000008 | MEDIUM |
| Expired cert | C2_SSL_Expired | — | MEDIUM |
| Non-standard port + TLS | C2_SSL_SelfSigned | 9000008 | HIGH |
| CN = malware name | C2_SSL_SelfSigned | 9003004 | VERY HIGH |
| No SNI on external IP | C2_No_PTR_Record | — | LOW-MEDIUM |

---

## Hunting Queries (Kibana KQL)

```kql
# Find all self-signed certs to external IPs
event.dataset: zeek.ssl AND tls.server.subject: * AND NOT tls.server.issuer: "Let's Encrypt*"
AND NOT tls.server.issuer: "DigiCert*" AND NOT tls.server.issuer: "GlobalSign*"

# Find TLS on non-standard ports
event.dataset: zeek.ssl AND NOT destination.port: 443 AND NOT destination.port: 8443

# Find known bad JA3 hashes
tls.client.ja3: "a0e9f5d64349fb13191bc781f81f42e1" OR
tls.client.ja3: "72a589da586844d7f0818ce684948eea" OR
tls.client.ja3: "de9f2c7fd25e1b3afad3e85a0bd17d9b"
```
