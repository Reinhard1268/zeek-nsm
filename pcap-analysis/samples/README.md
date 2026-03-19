# =============================================================
# File: README.md
# =============================================================

# PCAP Samples Directory

This directory holds sample PCAP files used to test and demonstrate
the detection capabilities of Project 5 — Zeek NSM & Anomaly Detection.

## Directory Structure

```
pcap-analysis/
├── samples/               ← You are here
│   └── README.md
├── results/               ← Analysis reports per malware family
└── malicious-patterns/    ← Pattern reference documentation
```

## Recommended Public PCAP Sources

| Source | URL | Content |
|--------|-----|---------|
| Malware Traffic Analysis | https://www.malware-traffic-analysis.net | Real Emotet, IcedID, Cobalt Strike captures |
| PacketTotal | https://packettotal.com | Community-submitted classified PCAPs |
| Netresec | https://www.netresec.com/?page=PcapFiles | Curated malware + CTF PCAPs |
| PCAP Over IP | https://github.com/chrissanders/packets | Training PCAPs |

## Files to Download Per Analysis

| Report | Search Term | Save As |
|--------|-------------|---------|
| emotet-analysis.md | malware-traffic-analysis "Emotet" | emotet-c2.pcap |
| cobalt-strike-analysis.md | malware-traffic-analysis "Cobalt Strike" | cobalt-strike.pcap |
| asyncrat-analysis.md | malware-traffic-analysis "AsyncRAT" | asyncrat.pcap |
| dns-tunneling-analysis.md | netresec DNS tunnel | dns-tunnel.pcap |
| lateral-movement-analysis.md | packettotal lateral movement | lateral-movement.pcap |

## Analyzing a PCAP with Zeek

```bash
# Run Zeek on a PCAP
zeek -r samples/emotet-c2.pcap /opt/zeek/share/zeek/site/local.zeek

# Key output logs
# conn.log, dns.log, http.log, ssl.log, files.log, notice.log, weird.log

# Then run anomaly detectors
python3 ../../anomaly-detection/beaconing/beaconing_detector.py --input conn.log
python3 ../../anomaly-detection/dga/dga_detector.py --input dns.log
python3 ../../anomaly-detection/exfil-detector/exfil_detector.py --input-dir .
```

## Analyzing with Suricata

```bash
suricata -r samples/emotet-c2.pcap -l /var/log/suricata/pcap-results/

# View alerts
cat /var/log/suricata/pcap-results/eve.json \
  | jq 'select(.event_type=="alert") | {sig: .alert.signature, src: .src_ip, dst: .dest_ip}'
```

## .gitignore

Add to `.gitignore` to avoid committing large PCAP files:
```
pcap-analysis/samples/*.pcap
pcap-analysis/samples/*.pcapng
pcap-analysis/samples/*.cap
```
