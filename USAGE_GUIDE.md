# KEV Scanner - Updated Usage Guide

## New Features Added

### 1. Clear Template Status
The scanner now clearly indicates whether a Nuclei template exists for each CVE:

```
✓ Found 2 Nuclei template(s) for CVE-2024-1234
  → /path/to/template1.yaml
  → /path/to/template2.yaml

✗ No Nuclei template available for CVE-2024-5678 - SKIPPING
```

### 2. Detailed Scan Output
See exactly what's being scanned:

```
[1/10] Processing CVE-2024-1234...
✓ Found 1 Nuclei template(s) for CVE-2024-1234
▶ Scanning CVE-2024-1234 against 15 target(s)...
✓ CVE-2024-1234: Found 2 VULNERABLE host(s) in 3.45s
  1. https://app1.example.com
  2. https://app2.example.com
```

### 3. Summary Statistics
Get a clear summary at the end:

```
================================================================================
SCAN COMPLETE - SUMMARY
================================================================================
Total CVEs processed: 50
  ✓ CVEs with Nuclei templates: 32
  ✗ CVEs without templates (skipped): 18
  ⚠ CVEs with findings: 5
Total unique vulnerable hosts: 12
Total scan duration: 245.67 seconds

⚠ Note: 18 CVE(s) were skipped due to missing Nuclei templates
  This is normal - not all CISA KEV CVEs have public Nuclei templates yet
================================================================================
```

### 4. Real-Time Nuclei Output
Use `--show-nuclei-output` to see raw Nuclei scanning in real-time:

```bash
python3 payloadZer0.py -t hosts.txt --force-scan --show-nuclei-output
```

This shows you EXACTLY what Nuclei is doing:
```
[Nuclei Output Below]
------------------------------------------------------------
[INF] Using Interactsh Server: oast.pro
[CVE-2024-1234] [http] [critical] https://vulnerable.example.com/admin
[CVE-2024-1234] [http] [critical] https://app2.example.com/login
------------------------------------------------------------
```

## Usage Examples

### Basic Scan (See What Has Templates)
```bash
python3 payloadZer0.py -t hosts.txt --force-scan
```

Output shows:
- Which CVEs have templates (✓)
- Which CVEs don't have templates (✗ SKIPPING)
- Number of hosts scanned per CVE
- Vulnerable hosts found
- Summary statistics

### Verbose Mode (See Everything)
```bash
python3 payloadZer0.py -t hosts.txt --force-scan --show-nuclei-output
```

Shows:
- Template discovery
- Real-time Nuclei scanning output
- Each host being tested
- Vulnerable findings as they're discovered

### Continuous Monitoring with Clear Logging
```bash
python3 payloadZer0.py -t hosts.txt --continuous --interval 3600

# Watch logs
tail -f kev_scanner.log
```

Logs show:
```
[1/10] Processing CVE-2024-1234...
✓ Found 1 Nuclei template(s) for CVE-2024-1234
  → /path/to/cve-2024-1234.yaml
▶ Scanning CVE-2024-1234 against 100 target(s)...
✓ CVE-2024-1234: No vulnerabilities found (scanned 100 hosts in 8.45s)

[2/10] Processing CVE-2024-5678...
✗ No Nuclei template available for CVE-2024-5678 - SKIPPING
```

## Understanding the Output

### Symbols Used
- ✓ Success / Found
- ✗ Not found / Skipped
- ▶ Action starting
- ⚠ Warning / Note
- ⊘ Skipped

### Log Levels
- **INFO**: Normal operation (✓ ✗ ▶)
- **WARNING**: Issues but not fatal (⚠)
- **ERROR**: Problems that need attention
- **DEBUG**: Detailed technical info (use with --verbose-scan)

## Troubleshooting

### "No Nuclei template available" - Is this bad?
**No, this is normal!** 

Not all CISA KEV CVEs have public Nuclei templates. The scanner:
1. Checks if a template exists
2. If YES → scans your hosts
3. If NO → skips and moves to next CVE

You'll typically see:
- 30-50% of CVEs have templates
- 50-70% don't have templates yet

This is expected and not an error.

### See which CVEs were scanned vs skipped
Check the summary at the end:
```
✓ CVEs with Nuclei templates: 32
✗ CVEs without templates (skipped): 18
```

### Want to see what Nuclei is actually doing?
```bash
# Use this flag to see raw Nuclei output
python3 payloadZer0.py -t hosts.txt --force-scan --show-nuclei-output
```

### Check if a specific CVE has a template
```bash
nuclei -tl -tags CVE-2024-1234
```

If it returns a path → template exists
If it returns nothing → no template available

## Performance Notes

### Speed Per CVE
- Template discovery: ~1 second
- Actual scan: Depends on:
  - Number of hosts (100 hosts = ~5-10s)
  - Network latency
  - Host responsiveness
  - Rate limiting (default 150 req/s)

### Why Some CVEs Scan Faster
- Small target list
- Simple templates
- Fast-responding hosts
- No vulnerabilities found

### Why Some CVEs Take Longer
- Large target list
- Complex templates
- Slow-responding hosts
- Many vulnerabilities found

## Best Practices

1. **Start with force-scan** to see what has templates
```bash
python3 payloadZer0.py -t hosts.txt --force-scan --scan-recent-days 30
```

2. **Check the summary** to understand coverage
```
✓ CVEs with Nuclei templates: 15 out of 50
```

3. **Use continuous mode** once you know what to expect
```bash
python3 payloadZer0.py -t hosts.txt --continuous --interval 7200
```

4. **Monitor logs** to track activity
```bash
tail -f kev_scanner.log
```

## Command Reference

### Key Flags

**--show-nuclei-output**
- Shows raw Nuclei scanning output in real-time
- Use to see exactly what's being tested
- Great for debugging

**--verbose-scan**
- Shows Nuclei progress (not silent mode)
- Less detailed than --show-nuclei-output

**--force-scan**
- Scans recent CVEs immediately
- Use with --scan-recent-days to control timeframe

**--scan-recent-days N**
- Scan CVEs added in last N days
- Default: 30 days

**--continuous**
- Run forever, checking for new CVEs
- Use with --interval to control frequency

## Example Workflows

### Initial Assessment
```bash
# See what's vulnerable in your environment
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --scan-recent-days 90 \
    --show-nuclei-output
```

### Production Monitoring
```bash
# Continuous monitoring with Teams alerts
python3 payloadZer0.py -t hosts.txt \
    --continuous \
    --interval 3600 \
    --teams-webhook "https://..."
```

### Debugging Issues
```bash
# Maximum verbosity
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --show-nuclei-output \
    --verbose-scan
```

---

## Summary of Improvements

✅ Clear indication of which CVEs have templates
✅ Shows which CVEs are being skipped (no template)
✅ Displays number of hosts scanned per CVE
✅ Shows vulnerable hosts as they're found
✅ Comprehensive summary statistics
✅ Real-time Nuclei output option
✅ Better logging with symbols (✓ ✗ ▶ ⚠)
✅ Scan duration per CVE
✅ Target count per scan

Now you'll never wonder if a CVE has a template or if it's actually scanning!
