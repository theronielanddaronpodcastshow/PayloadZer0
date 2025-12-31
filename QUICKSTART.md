# 🚨 PayloadZer0 - KEV Threat Scanner - Quick Start

## What This Does

Automatically monitors CISA's Known Exploited Vulnerabilities (KEV) catalog and scans your infrastructure for emerging threats using Nuclei. Sends real-time Microsoft Teams alerts when new exploited CVEs are discovered or vulnerabilities are found in your environment.

**Perfect for Red Team operations** - Get instant visibility into emerging threats across your attack surface.

## ⚡ 60-Second Setup

```bash
# 1. Run setup (installs everything)
chmod +x setup.sh && ./setup.sh

# 2. Edit your targets
nano hosts.txt

# 3. Set Teams webhook (optional but recommended)
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/YOUR_URL"

# 4. Run your first scan
python3 payloadZer0.py -t hosts.txt --force-scan

# 5. Start continuous monitoring
python3 payloadZer0.py -t hosts.txt --continuous --interval 3600
```

## 📋 What You Get

**Core Features:**
- ✅ Auto-deduplication - only scans NEW CVEs
- ✅ Continuous monitoring with configurable intervals
- ✅ Microsoft Teams real-time alerts (new CVEs, findings, scan status)
- ✅ Per-CVE result files for tracking
- ✅ Comprehensive logging
- ✅ Resume capability across restarts

**Included Tools:**
1. **payloadZer0.py** - Main scanner
2. **monitor_dashboard.py** - Real-time monitoring dashboard
3. **kev_utils.py** - Reporting and analysis utilities
4. **setup.sh** - Automated installation

## 🎯 Red Team Usage Examples

### Quick Threat Assessment
```bash
# Check what's exploitable in your environment
python3 payloadZer0.py -t targets.txt --force-scan --scan-recent-days 30
```

### Continuous Monitoring
```bash
# Monitor 24/7 with Teams alerts
python3 payloadZer0.py -t prod_assets.txt --continuous --interval 3600
```

### Pre-Engagement Recon
```bash
# Scan client's external facing apps
echo "https://client.com" > client.txt
echo "https://portal.client.com" >> client.txt
python3 payloadZer0.py -t client.txt --force-scan --scan-recent-days 90
```

## 📊 Monitoring Commands

```bash
# Real-time dashboard
python3 monitor_dashboard.py --continuous

# Generate report
python3 kev_utils.py report

# Export findings to CSV
python3 kev_utils.py export -o findings.csv

# List vulnerable hosts
python3 kev_utils.py list-hosts

# Search for specific CVEs
python3 kev_utils.py search "microsoft exchange"

# Check if CVE is tracked
python3 kev_utils.py check-cve CVE-2024-1234
```

## 🔔 Teams Notifications

The scanner sends 4 types of alerts:

1. **🚨 New CVE Alert** (Red) - New exploited CVE discovered in CISA KEV
2. **▶️ Scan Started** (Orange) - Vulnerability scan beginning
3. **💥 Critical Findings** (Red) - Vulnerable hosts found
4. **✅ Scan Complete** (Green/Red) - Scan finished with summary

## 📁 File Structure

```
payloadZer0.py     # Main scanner
monitor_dashboard.py      # Live dashboard
kev_utils.py              # Utilities
setup.sh                  # Installation script
kev_database.json         # CVE tracking (auto-created)
kev_scanner.log          # Logs
hosts.txt                # Your targets
scan_results/            # Per-CVE JSON results
  ├── CVE_2024_1234_results.json
  └── CVE_2024_5678_results.json
```

## 🔧 Common Commands

```bash
# View logs
tail -f kev_scanner.log

# Check scanner status
ps aux | grep payloadZer0

# Force scan all recent CVEs
python3 payloadZer0.py -t hosts.txt --force-scan --scan-recent-days 30

# Update Nuclei templates
nuclei -update-templates

# Run in background with screen
screen -dmS kev python3 payloadZer0.py -t hosts.txt --continuous --interval 3600

# Reattach to background session
screen -r kev
```

## ⚙️ Configuration Options

```bash
# Adjust scan speed
--rate-limit 150          # Requests per second (default: 150)
--scan-timeout 10         # Per-host timeout in seconds

# Control scanning
--interval 3600           # Check interval in seconds
--scan-recent-days 30     # Scan CVEs from last N days

# Notifications
--teams-webhook URL       # Teams webhook URL
--no-notify-findings      # Disable findings alerts
--no-notify-scan-events   # Disable scan start/end alerts

# Output
--output-dir ./results    # Custom output directory
--database ./db.json      # Custom database path
```

## 🏆 Why This Tool is Game-Changing

**For Red Team:**
- Get exploitable CVEs automatically as they're disclosed
- Scan your client's infrastructure continuously
- Instant Teams alerts when new attack vectors appear
- Perfect for demonstrating current threat landscape

**For Security Testing:**
- Catch zero-day exploits in the wild targeting your org
- Automatic deduplication = no wasted scans
- Comprehensive logging for audit trails
- Per-CVE results for targeted remediation

**For Continuous Monitoring:**
- Set it and forget it
- Runs 24/7 with automatic template updates
- Resilient to failures with auto-restart
- Low resource usage

## 🎓 Learning Resources

- **README.md** - Comprehensive documentation
- **DEPLOYMENT.md** - Production deployment guide
- **Full help**: `python3 payloadZer0.py --help`

## 🆘 Quick Troubleshooting

**Nuclei not found?**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$HOME/go/bin
```

**No templates found?**
```bash
nuclei -update-templates
```

**Teams not working?**
```bash
# Test webhook
curl -X POST "$TEAMS_WEBHOOK_URL" -H "Content-Type: application/json" -d '{"text":"test"}'
```

## 💪 Pro Tips

1. **Start conservative** - Use default rate limits first
2. **Test on small target list** - Verify everything works before scaling
3. **Enable Teams alerts** - You want real-time notification of critical findings
4. **Run in screen/tmux** - For persistent background execution
5. **Check logs regularly** - `tail -f kev_scanner.log`
6. **Use the dashboard** - `python3 monitor_dashboard.py --continuous`

## 🚀 Production Deployment

For 24/7 operation, use systemd:

```bash
sudo cp kev-scanner.service /etc/systemd/system/
sudo nano /etc/systemd/system/kev-scanner.service  # Edit paths/webhook
sudo systemctl enable kev-scanner
sudo systemctl start kev-scanner
sudo systemctl status kev-scanner
```

---
