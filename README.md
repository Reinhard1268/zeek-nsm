# Project Name — Zeek Network Security Monitoring & Anomaly Detection

**Author:** Amoah Reinhard  
**Platform:** Kali Linux | 32GB RAM  
**Stack:** Zeek · Suricata · Elasticsearch · Kibana · TheHive · Wazuh  
---

## Overview

This project builds a full network security monitoring (NSM) pipeline using Zeek and Suricata
to detect C2 beaconing, DNS exfiltration, lateral movement, and data exfiltration in real time.
Custom Zeek scripts fire structured notices. Suricata rules provide signature-based detection.
Python anomaly detection models (statistical + ML) run on top of Zeek logs. All alerts are
correlated and pushed to TheHive for case management.

---

## Project Structure
```
zeek-nsm/
├── zeek/
│   ├── scripts/                    # Custom Zeek detection scripts
│   │   ├── beaconing-detect.zeek   # C2 beacon detection via interval CV analysis
│   │   ├── c2-patterns.zeek        # JA3, self-signed certs, suspicious UAs
│   │   ├── data-exfil-detect.zeek  # Volume, HTTP POST, DNS label exfil
│   │   ├── dns-anomaly.zeek        # NXDOMAIN ratio, entropy, query rate
│   │   └── lateral-movement.zeek   # SMB scan, PsExec, WMI, RDP lateral
│   └── custom-protocols/
│       ├── smb-monitor.zeek        # SMB write rates, ransomware ext, admin shares
│       └── rdp-monitor.zeek        # RDP brute force, NLA disabled, external RDP
│
├── suricata/
│   └── rules/
│       ├── c2-detection.rules      # Cobalt Strike, AsyncRAT, Sliver JA3 + patterns
│       ├── lateral-movement.rules  # SMB scan, PsExec, PTH, WMI, RDP brute force
│       ├── exfiltration.rules      # HTTP POST/PUT, DNS tunnel, ICMP, FTP exfil
│       ├── malware-traffic.rules   # Emotet, TrickBot, AsyncRAT, PowerShell cradles
│       └── local.rules             # IOC-based blocks, DC monitoring, recon alerts
│
├── elastic/
│   └── ingest-pipelines/
│       ├── zeek-conn-pipeline.json     # ECS mapping for conn.log
│       ├── zeek-dns-pipeline.json      # ECS mapping for dns.log
│       ├── zeek-http-pipeline.json     # ECS mapping for http.log
│       └── suricata-eve-pipeline.json  # ECS mapping for eve.json alerts
│
├── anomaly-detection/
│   ├── beaconing/
│   │   ├── beaconing_detector.py       # CV-based beacon detector (Python)
│   │   └── beacon-analysis-results.md  # Detection results from sample traffic
│   ├── dga/
│   │   ├── dga_detector.py             # RandomForest DGA classifier
│   │   ├── dga-detection-results.md    # Detection results + model metrics
│   │   └── domain-wordlists/
│   │       ├── legitimate-domains.txt  # 500 known-good domains (training)
│   │       └── known-dga-domains.txt   # 300 known DGA domains (training)
│   └── exfil-detector/
│       └── exfil_detector.py           # Volume + DNS + HTTP exfil detector
│
├── python/
│   ├── parsers/
│   │   ├── zeek_log_parser.py      # Zeek TSV/JSON → pandas DataFrame parser
│   │   └── suricata_parser.py      # Suricata EVE JSON → pandas DataFrame parser
│   ├── anomaly-models/
│   │   ├── statistical_models.py   # IntervalAnalyzer, EntropyCalculator, VolumeAnalyzer
│   │   └── ml_classifier.py        # DGAClassifier (RF) + BeaconClassifier (IsolationForest)
│   └── alert-correlator/
│       └── correlator.py           # Zeek + Suricata alert correlator → TheHive
│
├── pcap-analysis/
│   ├── samples/
│   │   └── README.md               # Where to download sample PCAPs
│   ├── results/
│   │   ├── emotet-analysis.md          # Emotet Epoch 4 PCAP analysis
│   │   ├── cobalt-strike-analysis.md   # Cobalt Strike jQuery profile analysis
│   │   ├── asyncrat-analysis.md        # AsyncRAT C2 channel analysis
│   │   ├── dns-tunneling-analysis.md   # DNS tunnel (dnscat2/iodine) analysis
│   │   └── lateral-movement-analysis.md # PsExec + PTH lateral movement analysis
│   └── malicious-patterns/
│       ├── beaconing-patterns.md   # Beacon pattern reference (CV, intervals)
│       ├── c2-ssl-patterns.md      # JA3, self-signed cert, expired cert patterns
│       └── ioc-master-list.md      # Master IOC list (IPs, domains, hashes, JA3s)
│
├── docs/
│   ├── setup-guide.md      # Full installation and configuration guide
│   └── patterns-found.md   # All detected attack patterns with MITRE mapping
│
└── sample-alerts.json      # Sample Suricata EVE alert output for testing
```

---

## Detection Capabilities

| Category | Technique | Detection Method | MITRE ID |
|----------|-----------|-----------------|----------|
| C2 Beaconing | Regular interval HTTP/HTTPS beacon | CV < 0.3 on connection intervals | T1071.001 |
| C2 Beaconing | Cobalt Strike JA3 fingerprint | JA3 hash match | T1071.001 |
| C2 Beaconing | AsyncRAT TLS certificate | CN=AsyncRAT Server + port 6606 | T1573.002 |
| DNS Exfil | Base64 subdomain encoding | Label length > 50, entropy > 3.5 | T1048 |
| DNS Exfil | High NXDOMAIN ratio | NXDOMAIN > 70% over 5min window | T1071.004 |
| DNS Exfil | High query rate (tunneling) | > 100 queries/min to single domain | T1071.004 |
| DGA | Algorithmically generated domains | RandomForest on entropy + n-gram score | T1568.002 |
| Data Exfil | High outbound volume | > 100 MB/hr per src→dst pair | T1048.003 |
| Data Exfil | Large HTTP POST | POST body > 5 MB to external | T1048.003 |
| Lateral Movement | SMB multi-host scan | > 5 SMB hosts in 3 minutes | T1021.002 |
| Lateral Movement | PsExec via SMB | PSEXESVC.exe write to ADMIN$ | T1569.002 |
| Lateral Movement | Pass-the-Hash | NTLM Type1 without username | T1550.002 |
| Lateral Movement | WMI remote execution | DCOM port 135 repeated connections | T1047 |
| Lateral Movement | Internal RDP | RDP src and dst both internal | T1021.001 |

---

## Quick Start

### 1. Install Zeek and Suricata
```bash
# Zeek
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_Testing/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list
sudo apt update && sudo apt install -y zeek
export PATH=/opt/zeek/bin:$PATH

# Suricata
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install -y suricata
sudo suricata-update
```

### 2. Deploy Zeek Scripts
```bash
sudo mkdir -p /opt/zeek/share/zeek/site/zeek-nsm
sudo cp zeek/scripts/*.zeek /opt/zeek/share/zeek/site/zeek-nsm/
sudo cp zeek/custom-protocols/*.zeek /opt/zeek/share/zeek/site/zeek-nsm/

# Add to local.zeek
echo '@load zeek-nsm/beaconing-detect' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo '@load zeek-nsm/dns-anomaly'      | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo '@load zeek-nsm/data-exfil-detect'| sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo '@load zeek-nsm/c2-patterns'      | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo '@load zeek-nsm/lateral-movement' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo '@load zeek-nsm/smb-monitor'      | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo '@load zeek-nsm/rdp-monitor'      | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
echo '@load policy/tuning/json-logs'   | sudo tee -a /opt/zeek/share/zeek/site/local.zeek

sudo zeekctl deploy
```

### 3. Deploy Suricata Rules
```bash
sudo cp suricata/rules/*.rules /etc/suricata/rules/
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

### 4. Load Elastic Ingest Pipelines
```bash
for pipeline in zeek-conn zeek-dns zeek-http suricata-eve; do
  curl -X PUT "http://localhost:9200/_ingest/pipeline/${pipeline}-pipeline" \
    -H "Content-Type: application/json" \
    -u elastic:YOUR_PASSWORD \
    -d @elastic/ingest-pipelines/${pipeline}-pipeline.json
done
```

### 5. Install Python Dependencies
```bash
pip3 install -r requirements.txt --break-system-packages
```

### 6. Run Anomaly Detection
```bash
# Beaconing detection on live Zeek logs
python3 anomaly-detection/beaconing/beaconing_detector.py \
  --input /opt/zeek/logs/current/conn.log \
  --min-connections 10 --threshold 0.3

# DGA detection
python3 anomaly-detection/dga/dga_detector.py \
  --input /opt/zeek/logs/current/dns.log \
  --threshold 0.70

# Exfiltration detection
python3 anomaly-detection/exfil-detector/exfil_detector.py \
  --input-dir /opt/zeek/logs/current/ \
  --threshold-mb 100

# Alert correlator → TheHive
python3 python/alert-correlator/correlator.py \
  --zeek-notice /opt/zeek/logs/current/notice.log \
  --suricata-eve /var/log/suricata/eve.json \
  --threshold 70 --push-thehive --mode continuous
```

### 7. Analyze a PCAP Offline
```bash
zeek -r /path/to/sample.pcap /opt/zeek/share/zeek/site/local.zeek
suricata -r /path/to/sample.pcap -l /tmp/suricata-out/
python3 anomaly-detection/beaconing/beaconing_detector.py --input conn.log
```

---

## Thresholds Reference

| Parameter | Default | File | Description |
|-----------|---------|------|-------------|
| `cv_threshold` | 0.3 | beaconing-detect.zeek | Max CV to classify as beacon |
| `min_connections` | 10 | beaconing-detect.zeek | Min connections required |
| `entropy_threshold` | 3.5 bits | dns-anomaly.zeek | Shannon entropy for DGA/exfil |
| `query_rate_threshold` | 100/min | dns-anomaly.zeek | DNS queries per minute alert |
| `nxdomain_ratio_threshold` | 0.70 | dns-anomaly.zeek | NXDOMAIN ratio alert |
| `volume_threshold_bytes` | 100 MB | data-exfil-detect.zeek | Outbound volume per hour |
| `post_threshold_bytes` | 5 MB | data-exfil-detect.zeek | HTTP POST body size |
| `dns_label_threshold` | 50 chars | data-exfil-detect.zeek | DNS subdomain label length |
| `smb_scan_threshold` | 5 hosts | lateral-movement.zeek | SMB hosts in window |
| `rdp_brute_threshold` | 10 attempts | rdp-monitor.zeek | Failed RDP connections |

All thresholds use `&redef` and can be overridden in `local.zeek` without editing source files:
```zeek
redef BeaconingDetect::cv_threshold     = 0.2;
redef DNSAnomaly::query_rate_threshold  = 50;
redef DataExfil::volume_threshold_bytes = 52428800;  # 50 MB
```

---

## Malware Families Covered

| Malware | Detection Method | Key Indicator |
|---------|-----------------|---------------|
| Emotet Epoch 4 | HTTP URI pattern + Suricata | POST `/[a-z]{4-8}/[a-z]{4-8}/` |
| Cobalt Strike | JA3 + HTTP profile + beacon CV | JA3 `a0e9f5d6...`, jQuery URI |
| AsyncRAT | TLS cert CN + port + JA3 | `CN=AsyncRAT Server`, port 6606 |
| TrickBot | HTTP image path pattern | POST `/images/[hex]/` |
| dnscat2 / iodine | DNS entropy + NXDOMAIN ratio | Entropy > 3.8, NXDOMAIN > 90% |
| Generic ransomware | SMB write rate + extension | > 100 writes/min, `.wncry` etc |

---

## Stack Integration
```
Zeek logs (JSON)  ──┐
                    ├──► Filebeat ──► Elasticsearch ──► Kibana Dashboard
Suricata eve.json ──┘         (ingest pipelines apply ECS mapping)

Zeek notice.log   ──┐
                    ├──► correlator.py ──► TheHive 5 (cases + observables)
Suricata eve.json ──┘

Python detectors ──► stdout + JSON results ──► manual triage or TheHive API
```

---

## Files Count

| Directory | Files | Purpose |
|-----------|-------|---------|
| zeek/scripts | 5 | Core Zeek detection scripts |
| zeek/custom-protocols | 2 | SMB and RDP protocol monitors |
| suricata/rules | 5 | Suricata signature rules |
| elastic/ingest-pipelines | 4 | Elasticsearch ECS pipelines |
| anomaly-detection | 7 | Python detectors + results + wordlists |
| python | 5 | Parsers, ML models, correlator |
| pcap-analysis | 9 | PCAP results, patterns, IOC list |
| docs | 2 | Setup guide, patterns found |
| root | 1 | sample-alerts.json |
| **Total** | **40** | |

---

## References

- [Zeek Documentation](https://docs.zeek.org)
- [Suricata Rules Reference](https://suricata.readthedocs.io/en/latest/rules/)
- [MITRE ATT&CK — Network](https://attack.mitre.org/tactics/TA0011/)
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
- [TheHive Project](https://thehive-project.org)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net)
- [MalwareBazaar](https://bazaar.abuse.ch)
- [JA3 Fingerprints Database](https://ja3er.com)
