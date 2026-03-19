# =============================================================
# File: setup-guide.md
# Project 5 Setup Guide — Zeek NSM & Anomaly Detection

**Environment:** Kali Linux | 32GB RAM | Docker stack from Project 1  
**Author:** Amoah Reinhard

---

## Prerequisites

Your Project 1 stack must be running:
```bash
docker ps | grep -E "wazuh|elastic|kibana|thehive|shuffle"
```

---

## Step 1 — Install Zeek on Kali Linux

### Option A: APT (Recommended — stable)
```bash
# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_Testing/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_Testing/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt update
sudo apt install -y zeek

# Verify
zeek --version

# Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Option B: Build from source (latest features)
```bash
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev \
  python3-dev swig zlib1g-dev libmaxminddb-dev

git clone --recursive https://github.com/zeek/zeek
cd zeek
./configure --prefix=/opt/zeek
make -j$(nproc)
sudo make install
```

---

## Step 2 — Install Suricata 7.x

```bash
# Add OISF repository
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata

# Verify
suricata --version

# Update rules (Emerging Threats)
sudo suricata-update
sudo suricata-update enable-source et/open
sudo suricata-update

# Test config
sudo suricata -T -c /etc/suricata/suricata.yaml
```

---

## Step 3 — Configure Zeek

### node.cfg
```bash
sudo nano /opt/zeek/etc/node.cfg
```
```ini
[zeek]
type=standalone
host=localhost
interface=eth0    # Change to your interface (ip a)
```

### networks.cfg
```bash
sudo nano /opt/zeek/etc/networks.cfg
```
```
10.0.0.0/8         Private RFC1918
172.16.0.0/12      Private RFC1918
192.168.0.0/16     Private RFC1918
```

### local.zeek
```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```
```zeek
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/smb
@load base/protocols/rdp
@load base/frameworks/notice
@load base/frameworks/files

# Load custom Project 5 scripts
@load /opt/zeek/share/zeek/site/project5/beaconing-detect
@load /opt/zeek/share/zeek/site/project5/dns-anomaly
@load /opt/zeek/share/zeek/site/project5/data-exfil-detect
@load /opt/zeek/share/zeek/site/project5/c2-patterns
@load /opt/zeek/share/zeek/site/project5/lateral-movement
@load /opt/zeek/share/zeek/site/project5/http-analyzer
@load /opt/zeek/share/zeek/site/project5/smb-monitor
@load /opt/zeek/share/zeek/site/project5/rdp-monitor

# Enable JSON logging (for Elastic)
@load policy/tuning/json-logs.zeek
```

---

## Step 4 — Load Custom Zeek Scripts

```bash
# Create project5 scripts directory
sudo mkdir -p /opt/zeek/share/zeek/site/project5

# Copy all custom scripts
sudo cp zeek/scripts/*.zeek /opt/zeek/share/zeek/site/project5/
sudo cp zeek/custom-protocols/*.zeek /opt/zeek/share/zeek/site/project5/

# Deploy and test
cd /opt/zeek
sudo bin/zeekctl deploy

# Check status
sudo bin/zeekctl status

# View logs
ls /opt/zeek/logs/current/
```

---

## Step 5 — Configure Suricata

```bash
sudo nano /etc/suricata/suricata.yaml
```

Key settings to update:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - dns
        - http
        - tls
        - flow

rule-files:
  - /etc/suricata/rules/c2-detection.rules
  - /etc/suricata/rules/lateral-movement.rules
  - /etc/suricata/rules/exfiltration.rules
  - /etc/suricata/rules/malware-traffic.rules
  - /etc/suricata/rules/local.rules
  - suricata.rules
```

```bash
# Copy project rules
sudo cp suricata/rules/*.rules /etc/suricata/rules/

# Test and start
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

---

## Step 6 — Set Up Elastic Ingest Pipelines

```bash
# Copy your .env values
ELASTIC_HOST=http://localhost:9200
ELASTIC_PASS=your_password

# Load conn pipeline
curl -X PUT "$ELASTIC_HOST/_ingest/pipeline/zeek-conn-pipeline" \
  -H "Content-Type: application/json" \
  -u elastic:$ELASTIC_PASS \
  -d @elastic/ingest-pipelines/zeek-conn-pipeline.json

# Load dns pipeline
curl -X PUT "$ELASTIC_HOST/_ingest/pipeline/zeek-dns-pipeline" \
  -H "Content-Type: application/json" \
  -u elastic:$ELASTIC_PASS \
  -d @elastic/ingest-pipelines/zeek-dns-pipeline.json

# Load http pipeline
curl -X PUT "$ELASTIC_HOST/_ingest/pipeline/zeek-http-pipeline" \
  -H "Content-Type: application/json" \
  -u elastic:$ELASTIC_PASS \
  -d @elastic/ingest-pipelines/zeek-http-pipeline.json

# Load suricata pipeline
curl -X PUT "$ELASTIC_HOST/_ingest/pipeline/suricata-eve-pipeline" \
  -H "Content-Type: application/json" \
  -u elastic:$ELASTIC_PASS \
  -d @elastic/ingest-pipelines/suricata-eve-pipeline.json
```

---

## Step 7 — Import Kibana Dashboard

```bash
# Import the network security dashboard
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -u elastic:$ELASTIC_PASS \
  --form file=@elastic/dashboards/network-security-dashboard.ndjson

# Or via Kibana UI:
# Stack Management → Saved Objects → Import → select network-security-dashboard.ndjson
```

---

## Step 8 — Configure Filebeat

```bash
sudo apt install -y filebeat

sudo nano /etc/filebeat/filebeat.yml
```

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/zeek/logs/current/*.log
    fields:
      log_type: zeek
    json.keys_under_root: true
    processors:
      - add_fields:
          target: event
          fields:
            module: zeek

  - type: log
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    fields:
      log_type: suricata
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  username: "elastic"
  password: "your_password"
  pipeline: "zeek-conn-pipeline"

setup.kibana:
  host: "localhost:5601"
  username: "elastic"
  password: "your_password"
```

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo filebeat test output
```

---

## Step 9 — Run First PCAP Analysis

```bash
# Download a sample PCAP (see pcap-analysis/samples/README.md)
# Run Zeek on it
cd /tmp
zeek -r /path/to/sample.pcap /opt/zeek/share/zeek/site/local.zeek

# Run anomaly detectors
python3 anomaly-detection/beaconing/beaconing_detector.py --input /tmp/conn.log
python3 anomaly-detection/dga/dga_detector.py --input /tmp/dns.log
python3 anomaly-detection/exfil-detector/exfil_detector.py --input-dir /tmp/

# Run Suricata
suricata -r /path/to/sample.pcap -l /tmp/suricata-results/
```

---

## Step 10 — Live Capture

```bash
# Start Zeek live capture
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl start

# Start Suricata live capture (already started via systemctl)
sudo systemctl status suricata

# Monitor in real time
tail -f /opt/zeek/logs/current/notice.log
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

## Step 11 — Test Anomaly Detection Scripts

```bash
pip3 install -r requirements.txt --break-system-packages

# Train DGA classifier
python3 anomaly-detection/dga/dga_detector.py \
  --train \
  --legit anomaly-detection/dga/domain-wordlists/legitimate-domains.txt \
  --dga   anomaly-detection/dga/domain-wordlists/known-dga-domains.txt \
  --model models/dga_classifier.joblib

# Run beaconing detector on live logs
python3 anomaly-detection/beaconing/beaconing_detector.py \
  --input /opt/zeek/logs/current/conn.log \
  --min-connections 10 --threshold 0.3

# Run correlator
python3 python/alert-correlator/correlator.py \
  --zeek-notice /opt/zeek/logs/current/notice.log \
  --suricata-eve /var/log/suricata/eve.json \
  --mode oneshot --threshold 70
```

---

## Step 12 — Connect Alert Correlator to TheHive

```bash
# Set TheHive API key in .env
echo "THEHIVE_API_KEY=your_api_key_here" >> .env

# Run correlator with TheHive push
python3 python/alert-correlator/correlator.py \
  --zeek-notice /opt/zeek/logs/current/notice.log \
  --suricata-eve /var/log/suricata/eve.json \
  --threshold 70 \
  --push-thehive \
  --mode continuous \
  --interval 300
```

TheHive cases will appear at http://localhost:9000 under your organization.

---

## Verification Checklist

- [ ] `zeekctl status` shows Zeek running
- [ ] `systemctl status suricata` shows active
- [ ] `/opt/zeek/logs/current/conn.log` is populating
- [ ] `/var/log/suricata/eve.json` is populating
- [ ] Filebeat is shipping logs to Elasticsearch
- [ ] Kibana dashboard shows live data
- [ ] Anomaly detection scripts run without errors
- [ ] TheHive receives test alert from correlator
