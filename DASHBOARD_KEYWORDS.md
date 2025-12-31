# Monitor Dashboard with Keyword Filtering

## Overview

The monitor dashboard now supports keyword filtering to show only CVEs matching your specified vendors/products.

## Usage

### View All CVEs (Default)
```bash
python3 monitor_dashboard.py --continuous
```

### View Only Specific Vendors
```bash
# Monitor only Cisco CVEs
python3 monitor_dashboard.py --continuous --keywords cisco

# Monitor multiple vendors
python3 monitor_dashboard.py --continuous --keywords cisco fortinet vmware
```

### Single Snapshot with Keywords
```bash
python3 monitor_dashboard.py --keywords "palo alto" microsoft
```

## What Gets Filtered

When you specify keywords, the dashboard shows:

✅ **CVE Database Statistics** - Only CVEs matching keywords
✅ **Scan Results** - Only findings for matching CVEs  
✅ **Recent Additions** - Only matching recent CVEs

❌ **Not filtered:**
- Log activity (shows all logs)
- System status
- File sizes

## Example Output

**Without keywords:**
```
================================================================================
                    🔍 KEV THREAT SCANNER DASHBOARD
================================================================================
Last updated: 2024-12-12 15:30:45
--------------------------------------------------------------------------------

📊 CVE DATABASE STATISTICS
--------------------------------------------------------------------------------
Total CVEs tracked: 1,234
Known ransomware CVEs: 89
CVEs added last 7 days: 15
```

**With keywords (cisco, fortinet):**
```
================================================================================
                    🔍 KEV THREAT SCANNER DASHBOARD
================================================================================
Last updated: 2024-12-12 15:30:45
🎯 Filtered by keywords: cisco, fortinet
--------------------------------------------------------------------------------

📊 CVE DATABASE STATISTICS
--------------------------------------------------------------------------------
Showing CVEs matching: cisco, fortinet
Total CVEs tracked: 45
Known ransomware CVEs: 3
CVEs added last 7 days: 2

Recent additions:
  • CVE-2024-1234 - Cisco ASA (1d ago)
  • CVE-2024-5678 - Fortinet FortiOS (3d ago)
```

## Use Cases

### Red Team Operations
```bash
# Monitor only target's tech stack
python3 monitor_dashboard.py --continuous \
    --keywords cisco "palo alto" vmware
```

### SOC Monitoring
```bash
# Monitor critical infrastructure vendors
python3 monitor_dashboard.py --continuous \
    --keywords cisco juniper fortinet checkpoint
```

### Security Assessment
```bash
# Quick view of specific vendor CVEs
python3 monitor_dashboard.py \
    --keywords microsoft
```

## Integration with Scanner

Run scanner with keywords in one terminal:
```bash
python3 kev_threat_scanner.py -t hosts.txt \
    --continuous \
    --keywords cisco fortinet vmware
```

Monitor with matching keywords in another terminal:
```bash
python3 monitor_dashboard.py --continuous \
    --keywords cisco fortinet vmware
```

Both will show the same filtered view!

## Command Reference

```bash
# View help
python3 monitor_dashboard.py --help

# Continuous mode (default refresh)
python3 monitor_dashboard.py --continuous

# With keywords
python3 monitor_dashboard.py --continuous --keywords cisco fortinet

# Single snapshot
python3 monitor_dashboard.py --keywords microsoft

# Custom database location
python3 monitor_dashboard.py --continuous \
    --db /path/to/kev_database.json \
    --keywords cisco
```

## Tips

1. **Match scanner keywords** - Use same keywords in dashboard as your scanner for consistency
2. **Multiple terminals** - Run scanner in background, dashboard in foreground
3. **Quick checks** - Use without `--continuous` for quick filtered snapshots
4. **Broad vs Specific** - Start broad (cisco), refine if needed (cisco asa)

## Example Workflows

### Workflow 1: Focused Monitoring
```bash
# Terminal 1: Run scanner
python3 kev_threat_scanner.py -t hosts.txt \
    --continuous --interval 3600 \
    --keywords cisco fortinet > scanner.log 2>&1 &

# Terminal 2: Watch dashboard
python3 monitor_dashboard.py --continuous \
    --keywords cisco fortinet
```

### Workflow 2: Multi-Vendor Tracking
```bash
# Terminal 1: Network devices
python3 monitor_dashboard.py --continuous \
    --keywords cisco juniper fortinet

# Terminal 2: Enterprise apps
python3 monitor_dashboard.py --continuous \
    --keywords microsoft vmware citrix
```

### Workflow 3: Quick Assessment
```bash
# Check what Cisco CVEs exist
python3 monitor_dashboard.py --keywords cisco

# Check findings
python3 kev_utils.py list-hosts --cve CVE-2024-XXXX
```

## Summary

✅ Dashboard respects keyword filtering
✅ Shows only matching CVEs and findings
✅ Use same keywords as scanner for consistency
✅ Perfect for focused monitoring
✅ Great for red team ops targeting specific tech

Now your entire workflow can be keyword-filtered!
