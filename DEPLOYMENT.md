# PayloadZer0 - KEV Threat Scanner - Quick Deployment Guide

## 🚀 Initial Setup (5 minutes)

### Step 1: Install Prerequisites
```bash
# Install Go (if not already installed)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Or use package manager
# Ubuntu/Debian: sudo apt install golang-go
# CentOS/RHEL: sudo yum install golang
# macOS: brew install go
```

### Step 2: Run Setup Script
```bash
chmod +x setup.sh
./setup.sh
```

### Step 3: Configure Targets
```bash
# Edit hosts.txt with your targets
nano hosts.txt

# Example content:
# https://app1.com
# https://app2.com
# 192.168.1.100
# 10.10.10.50
```

### Step 4: Set Up Teams Notifications (Optional but Recommended)
```bash
# Get your Teams webhook URL from:
# Teams Channel → ⋯ → Connectors → Incoming Webhook

# Set environment variable
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/YOUR_WEBHOOK_URL"

# Or add to ~/.bashrc for persistence
echo 'export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/YOUR_WEBHOOK_URL"' >> ~/.bashrc
```

### Step 5: Test Run
```bash
# Quick test scan
python3 payloadZer0.py -t hosts.txt --force-scan --scan-recent-days 7

# Check results
ls -lh scan_results/
cat kev_scanner.log
```

## 🏃 Production Deployment

### Option A: Screen/Tmux (Quick & Easy)
```bash
# Using screen
screen -S kev-scanner
python3 payloadZer0.py -t hosts.txt --continuous --interval 3600
# Press Ctrl+A then D to detach

# Reattach later
screen -r kev-scanner

# Using tmux
tmux new -s kev-scanner
python3 payloadZer0.py -t hosts.txt --continuous --interval 3600
# Press Ctrl+B then D to detach

# Reattach later
tmux attach -t kev-scanner
```

### Option B: Systemd Service (Production Grade)
```bash
# Create service user
sudo useradd -r -s /bin/false kev-scanner

# Install to /opt
sudo mkdir -p /opt/kev-scanner
sudo cp -r * /opt/kev-scanner/
sudo chown -R kev-scanner:kev-scanner /opt/kev-scanner

# Create log directory
sudo mkdir -p /var/log/kev-scanner /var/log/kev-scans
sudo chown kev-scanner:kev-scanner /var/log/kev-scanner /var/log/kev-scans

# Install systemd service
sudo cp kev-scanner.service /etc/systemd/system/
sudo nano /etc/systemd/system/kev-scanner.service  # Update TEAMS_WEBHOOK_URL

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable kev-scanner
sudo systemctl start kev-scanner

# Check status
sudo systemctl status kev-scanner
sudo journalctl -u kev-scanner -f
```

### Option C: Docker (Containerized)
```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim

# Install Go
RUN apt-get update && apt-get install -y wget git && \
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Set up application
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY payloadZer0.py .
COPY hosts.txt .

# Update templates
RUN nuclei -update-templates

# Create directories
RUN mkdir -p /app/scan_results /app/logs

CMD ["python3", "payloadZer0.py", "-t", "hosts.txt", "--continuous", "--interval", "3600"]
EOF

# Build and run
docker build -t kev-scanner .
docker run -d --name kev-scanner \
  -e TEAMS_WEBHOOK_URL="your_webhook_url" \
  -v $(pwd)/scan_results:/app/scan_results \
  -v $(pwd)/kev_database.json:/app/kev_database.json \
  kev-scanner
```

## 📊 Monitoring & Operations

### Real-Time Dashboard
```bash
# View live dashboard
python3 monitor_dashboard.py --continuous

# Single snapshot
python3 monitor_dashboard.py
```

### Common Operations
```bash
# View logs in real-time
tail -f kev_scanner.log

# Check scanner status
ps aux | grep payloadZer0

# Restart scanner (systemd)
sudo systemctl restart kev-scanner

# Force immediate scan
pkill -USR1 -f payloadZer0.py  # Send signal (if implemented)
# Or just restart with force-scan
python3 payloadZer0.py -t hosts.txt --force-scan

# Update Nuclei templates manually
nuclei -update-templates

# Clear database (start fresh)
mv kev_database.json kev_database.json.backup
```

### Log Analysis
```bash
# Recent errors
grep ERROR kev_scanner.log | tail -20

# New CVE discoveries
grep "New CVE added" kev_scanner.log

# Scan statistics
grep "Scan complete" kev_scanner.log | tail -10

# Vulnerable findings
grep "Found.*vulnerable hosts" kev_scanner.log

# Teams notifications sent
grep "Teams notification sent" kev_scanner.log
```

## 🎯 Red Team Use Cases

### Pre-Engagement Setup
```bash
# Configure target list
cat > client_external.txt << EOF
https://client.com
https://portal.client.com
https://mail.client.com
EOF

# Run initial baseline
python3 payloadZer0.py -t client_external.txt --force-scan --scan-recent-days 90
```

### Continuous Monitoring During Engagement
```bash
# Start monitoring
screen -dmS client-kev python3 payloadZer0.py \
  -t client_external.txt \
  --continuous \
  --interval 7200 \
  --output-dir ./client_scans

# Check findings
python3 monitor_dashboard.py
```

### Quick Triage
```bash
# Scan only critical recent CVEs (last 7 days)
python3 payloadZer0.py -t targets.txt --force-scan --scan-recent-days 7

# Fast scan with aggressive settings
python3 payloadZer0.py -t targets.txt \
  --force-scan \
  --rate-limit 500 \
  --scan-timeout 5
```

### Reporting
```bash
# Generate vulnerability summary
for file in scan_results/*.json; do
  cve=$(basename "$file" .json | sed 's/_/-/g')
  count=$(wc -l < "$file")
  echo "$cve: $count findings"
done | sort -t: -k2 -rn

# Extract vulnerable hosts by CVE
jq -r '.host' scan_results/CVE_2024_*_results.json | sort -u

# Generate report
python3 << EOF
import json
from pathlib import Path

results = {}
for file in Path('scan_results').glob('*.json'):
    cve = file.stem.replace('_', '-')
    hosts = set()
    with open(file) as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                hosts.add(data.get('host', 'unknown'))
    results[cve] = list(hosts)

# Output
for cve, hosts in sorted(results.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"\n{cve}: {len(hosts)} vulnerable hosts")
    for host in hosts[:5]:
        print(f"  - {host}")
EOF
```

## 🔧 Troubleshooting

### Issue: Scanner not finding templates
```bash
# Update templates manually
nuclei -update-templates

# Check if template exists
nuclei -tl | grep -i "cve-2024"

# List all CVE templates
nuclei -tl -tags cve | head -20
```

### Issue: High false positive rate
```bash
# Increase timeout
python3 payloadZer0.py -t hosts.txt --scan-timeout 20

# Verify manually
nuclei -u https://target.com -t cves/2024/CVE-2024-1234.yaml -debug
```

### Issue: Scanner consuming too many resources
```bash
# Reduce rate limit
python3 payloadZer0.py -t hosts.txt --continuous --rate-limit 50

# Increase scan interval
python3 payloadZer0.py -t hosts.txt --continuous --interval 7200
```

### Issue: Teams notifications not working
```bash
# Test webhook directly
curl -X POST "$TEAMS_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"text":"Test from KEV Scanner"}'

# Check if webhook is set
echo $TEAMS_WEBHOOK_URL

# Verify in logs
grep "Teams" kev_scanner.log
```

## 📈 Performance Tuning

### Small Environment (< 100 hosts)
```bash
python3 payloadZer0.py -t hosts.txt --continuous \
  --interval 1800 \
  --rate-limit 300 \
  --scan-timeout 10
```

### Medium Environment (100-1000 hosts)
```bash
python3 payloadZer0.py -t hosts.txt --continuous \
  --interval 3600 \
  --rate-limit 150 \
  --scan-timeout 15
```

### Large Environment (> 1000 hosts)
```bash
python3 payloadZer0.py -t hosts.txt --continuous \
  --interval 7200 \
  --rate-limit 100 \
  --scan-timeout 20
```

## 🔒 Security Best Practices

1. **Authorization**: Ensure you have written authorization to scan all targets
2. **Rate Limiting**: Don't overwhelm target systems - adjust rate-limit accordingly
3. **Network Segmentation**: Run from a dedicated security testing network if possible
4. **Log Security**: Restrict access to logs and results (contain sensitive findings)
5. **Webhook Security**: Never commit Teams webhook URLs to version control
6. **Credentials**: Never store credentials in targets file or scripts

## 🎓 Training Use Cases

### For SOC Team
```bash
# Demonstrate emerging threats
python3 payloadZer0.py -t demo_targets.txt --force-scan --scan-recent-days 30

# Show real-time monitoring
python3 monitor_dashboard.py --continuous
```

### For Red Team Exercises
```bash
# Simulate attacker reconnaissance
python3 payloadZer0.py -t blue_team_assets.txt --force-scan

# Generate attack surface report
python3 monitor_dashboard.py
```

## 🏆 Success Metrics

Track these metrics to demonstrate value:

- **Time to Detection**: How quickly new KEV CVEs are identified in your environment
- **Vulnerability Remediation**: Track closure rate of identified CVEs
- **Coverage**: Percentage of assets regularly scanned
- **False Positives**: Track and tune scanner configuration
- **Mean Time to Scan**: Average scan duration per CVE
