# Keyword Filtering Guide - Targeted CVE Monitoring

## Overview

The keyword filtering feature allows you to monitor **only specific vendors/products** instead of scanning all CISA KEV CVEs. Perfect for focusing on your organization's technology stack.

## Use Cases

### Enterprise with Specific Tech Stack
```bash
# Only monitor CVEs affecting your infrastructure
python3 payloadZer0.py -t hosts.txt \
    --continuous \
    --keywords cisco "palo alto" fortinet vmware microsoft
```

### Network Security Focus
```bash
# Monitor only network appliance CVEs
python3 payloadZer0.py -t hosts.txt \
    --continuous \
    --keywords cisco fortinet "palo alto" juniper checkpoint
```

### Cloud Infrastructure
```bash
# Monitor cloud platform CVEs
python3 payloadZer0.py -t hosts.txt \
    --continuous \
    --keywords aws azure "google cloud" vmware kubernetes docker
```

### Specific Vendor Monitoring
```bash

python3 payloadZer0.py -t hosts.txt \
    --continuous \
    --keywords microsoft oracle cisco "palo alto" vmware citrix
```

## How It Works

Keywords filter CVEs based on matches in:
- **Vendor/Project name** (e.g., "Microsoft", "Cisco")
- **Product name** (e.g., "Exchange Server", "ASA")
- **Vulnerability name** (e.g., "Microsoft Exchange Remote Code Execution")
- **Description** (full text search)

**Match is case-insensitive** - "cisco", "Cisco", "CISCO" all work the same.

## Command Syntax

### Basic Keyword Filtering
```bash
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --keywords cisco fortinet
```

### Multi-Word Keywords (Use Quotes)
```bash
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --keywords "palo alto" "microsoft exchange" "vmware vcenter"
```

### Continuous Monitoring with Keywords
```bash
python3 payloadZer0.py -t hosts.txt \
    --continuous \
    --interval 3600 \
    --keywords cisco microsoft vmware
```

### Combine with Other Options
```bash
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --scan-recent-days 90 \
    --keywords fortinet cisco \
    --teams-webhook "https://..."
```

## Example Output

```
🔍 Filtering CVEs by keywords: cisco, palo alto, fortinet
================================================================================
  ✓ CVE-2024-1234 matches keyword 'cisco': Cisco ASA
  ✓ CVE-2024-5678 matches keyword 'palo alto': Palo Alto Networks PAN-OS
  ✓ CVE-2024-9012 matches keyword 'fortinet': Fortinet FortiOS
  ⊘ Skipped 45 CVE(s) not matching keywords
================================================================================

Starting scan of 3 CVE(s) against 100 target(s)
================================================================================
```

## Utility Commands

### Preview CVEs by Keywords
Before running a scan, see what CVEs match your keywords:

```bash
# Search for specific vendor
python3 kev_utils.py search cisco

# List CVEs for multiple keywords
python3 kev_utils.py list-keywords cisco fortinet "palo alto"
```

Output:
```
================================================================================
CVEs MATCHING KEYWORDS: cisco, fortinet, palo alto
================================================================================

🔍 Keyword: 'cisco' - 12 CVE(s)
--------------------------------------------------------------------------------
  CVE-2024-1234: Cisco Adaptive Security Appliance
    → Remote Code Execution Vulnerability
    → Added: 2024-11-15
  CVE-2024-5678: Cisco IOS XE
    → Authentication Bypass
    → Added: 2024-10-22
  ... and 10 more

🔍 Keyword: 'fortinet' - 8 CVE(s)
--------------------------------------------------------------------------------
  CVE-2024-9012: Fortinet FortiOS
    → SSL VPN Vulnerability
    → Added: 2024-12-01
  ... and 7 more

================================================================================
TOTAL: 20 unique CVE(s) found
================================================================================
```

## Common Keyword Lists

### Network Infrastructure
```bash
--keywords cisco juniper "palo alto" fortinet checkpoint arista "f5 networks"
```

### Enterprise Software
```bash
--keywords microsoft oracle sap vmware citrix adobe
```

### Web & Application
```bash
--keywords apache nginx tomcat wordpress drupal joomla
```

### Security Appliances
```bash
--keywords "palo alto" fortinet checkpoint "trend micro" sophos "barracuda networks"
```

### Virtualization & Cloud
```bash
--keywords vmware "hyper-v" citrix aws azure "google cloud"
```

### Telecommunications
```bash
--keywords cisco "juniper networks" huawei ericsson nokia
```

## Advanced Usage

### Save Keyword Lists
```bash
# Create keyword file
cat > network_vendors.txt << EOF
cisco
palo alto
fortinet
juniper
checkpoint
EOF

# Use in script
KEYWORDS=$(cat network_vendors.txt | tr '\n' ' ')
python3 payloadZer0.py -t hosts.txt --continuous --keywords $KEYWORDS
```

### Multiple Focused Scans
```bash
# Scan 1: Network devices
python3 payloadZer0.py -t network_devices.txt \
    --continuous --interval 7200 \
    --keywords cisco juniper fortinet \
    --output-dir ./scans/network &

# Scan 2: Enterprise apps  
python3 payloadZer0.py -t enterprise_apps.txt \
    --continuous --interval 7200 \
    --keywords microsoft oracle vmware \
    --output-dir ./scans/enterprise &
```

### Keyword + Recent Days
```bash
# Cisco CVEs from last 6 months
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --scan-recent-days 180 \
    --keywords cisco
```

## Performance Benefits

**Without keywords:**
- Scans ALL CISA KEV CVEs (typically 1000+)
- 40-60% have Nuclei templates (~500 CVEs)
- Longer scan times

**With keywords:**
- Scans only matching CVEs (typically 10-50)
- Same 40-60% template rate (~5-20 CVEs)
- **Much faster scans**
- Less noise in results

## Real-World Examples

### Example 1: Financial Services
```bash
# Focus on Microsoft, Citrix, VMware, Palo Alto
python3 payloadZer0.py -t prod_servers.txt \
    --continuous \
    --interval 3600 \
    --keywords microsoft citrix vmware "palo alto" \
    --teams-webhook "https://..."
```

### Example 2: Red Team Assessment
```bash
# Pre-engagement: What CVEs affect the client's tech?
python3 kev_utils.py list-keywords cisco fortinet vmware microsoft

# Then scan their external infrastructure
python3 payloadZer0.py -t client_external.txt \
    --force-scan \
    --scan-recent-days 365 \
    --keywords cisco fortinet vmware microsoft
```

### Example 3: SOC Monitoring
```bash
# Monitor critical network infrastructure 24/7
python3 payloadZer0.py -t critical_infrastructure.txt \
    --continuous \
    --interval 1800 \
    --keywords cisco juniper "palo alto" fortinet \
    --notify-findings \
    --teams-webhook "https://soc.webhook.url"
```

## Keyword Best Practices

### 1. Use Specific Keywords
✅ Good: `"palo alto"`, `"microsoft exchange"`, `fortinet`
❌ Too broad: `network`, `server`, `security`

### 2. Include Product Families
```bash
--keywords cisco "cisco asa" "cisco ios" "cisco ise"
```

### 3. Check Your Keywords Work
```bash
# Test before continuous monitoring
python3 kev_utils.py list-keywords YOUR KEYWORDS HERE
```

### 4. Update Keywords as Stack Changes
```bash
# Quarterly review of keyword list
python3 kev_utils.py list-keywords cisco microsoft vmware
# Add/remove based on your current tech stack
```

### 5. Combine General + Specific
```bash
# General vendor + specific products
--keywords microsoft "microsoft exchange" "microsoft sharepoint" cisco "cisco asa"
```

## Monitoring Strategy

### Tier 1: Critical Infrastructure
```bash
# Check every 30 minutes
--keywords "critical vendor 1" "critical vendor 2" --interval 1800
```

### Tier 2: General Infrastructure
```bash
# Check every 2 hours
--keywords "your vendors" --interval 7200
```

### Tier 3: Comprehensive Baseline
```bash
# Weekly full scan without keywords
--force-scan --scan-recent-days 7
# (Run on weekends)
```

## Troubleshooting

### "No CVEs match my keywords"
```bash
# Check if keyword exists in database
python3 kev_utils.py search YOUR_KEYWORD

# Try variations
python3 kev_utils.py search cisco
python3 kev_utils.py search "cisco systems"
```

### "Getting CVEs I don't want"
Keywords are substring matches. If you search for "net", you'll match:
- Fortinet
- Palo Alto Networks
- .NET vulnerabilities

**Solution:** Use more specific keywords or exact product names.

### "Missing CVEs I expect"
```bash
# Check what the CVE is actually called
python3 kev_utils.py search PARTIAL_NAME

# Example: searching "palo" instead of "palo alto"
python3 kev_utils.py search palo
```

## Integration with Existing Workflows

### Daily Security Brief
```bash
#!/bin/bash
# daily_brief.sh

# Get new CVEs for your stack
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --scan-recent-days 1 \
    --keywords cisco microsoft vmware

# Generate report
python3 kev_utils.py report -o daily_report.txt

# Email to team
mail -s "Daily KEV Report" security-team@company.com < daily_report.txt
```

### Integration with SIEM
```bash
# Scan and export findings
python3 payloadZer0.py -t hosts.txt \
    --keywords YOUR_VENDORS \
    --force-scan

python3 kev_utils.py export -o findings.csv

# Import to SIEM (example: Splunk)
/opt/splunk/bin/splunk add oneshot findings.csv -sourcetype kev_scan
```

## Summary

✅ **Use keywords to:**
- Focus on your tech stack
- Reduce scan time
- Minimize noise
- Target specific vendors

✅ **Don't use keywords for:**
- Initial baseline (scan everything first)
- Discovering unknown infrastructure
- Comprehensive security posture assessment

**Recommendation:** 
- Run without keywords weekly (baseline)
- Run with keywords continuously (monitoring)
- This gives you both broad visibility and focused alerting
