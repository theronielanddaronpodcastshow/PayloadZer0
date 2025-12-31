# Template Detection Troubleshooting Guide

## Problem: "Says no template found when template exists"

### Quick Fix - Use the Test Tool

```bash
# Test if scanner can find a specific CVE template
python3 test_template_detection.py CVE-2025-48703
```

This will show you:
- Which detection methods work
- Where the template is located
- If it's actually scannable

### Understanding Template Detection

The scanner uses **4 methods** to find templates (in order):

1. **nuclei -tl -tags CVE-2025-48703** (lowercase)
2. **nuclei -tl -tags 2025-48703** (without CVE- prefix)
3. **Filesystem search** in nuclei-templates directory
4. **Direct template validation** with nuclei -validate

If ALL 4 fail, it reports "no template found."

### Common Causes

#### 1. Templates Not Updated
```bash
# Update templates
nuclei -update-templates

# Verify update worked
ls -la ~/nuclei-templates/http/cves/2025/
```

#### 2. Nuclei -tl Command Not Working
Sometimes `nuclei -tl -tags` doesn't work reliably. Test manually:

```bash
# This should list the template
nuclei -tl -tags cve-2025-48703

# If that doesn't work, try without CVE- prefix
nuclei -tl -tags 2025-48703

# If STILL doesn't work, search filesystem
find ~/nuclei-templates -name "*2025-48703*"
```

#### 3. Template in Wrong Location
```bash
# Find where your templates actually are
nuclei -version  # Shows config path

# Common locations:
ls ~/nuclei-templates/
ls ~/.local/nuclei-templates/
ls /root/nuclei-templates/
```

#### 4. Template Naming Doesn't Match CVE
Some templates use different naming conventions:

```bash
# Search for the year and number separately
find ~/nuclei-templates -name "*2025*" | grep -i 48703

# Or search the entire templates directory
grep -r "CVE-2025-48703" ~/nuclei-templates/
```

### Debug Mode

Run the scanner with debug mode to see ALL detection attempts:

```bash
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --scan-recent-days 7 \
    --debug
```

This shows:
```
DEBUG - Method 1 failed for CVE-2025-48703: ...
DEBUG - Method 2 failed for CVE-2025-48703: ...
DEBUG - Method 3 (filesystem search) failed for CVE-2025-48703: ...
```

### Manual Template Lookup

If scanner can't find it but you know it exists:

```bash
# Find the exact path
find ~/nuclei-templates -name "*48703*"

# Example result:
# /home/user/nuclei-templates/http/cves/2025/CVE-2025-48703.yaml

# Test if Nuclei can use it
nuclei -t /home/user/nuclei-templates/http/cves/2025/CVE-2025-48703.yaml \
       -l hosts.txt
```

### Solutions

#### Solution 1: Update Templates
```bash
nuclei -update-templates
python3 payloadZer0.py -t hosts.txt --force-scan --scan-recent-days 7
```

#### Solution 2: Specify Templates Path
If templates are in a custom location:

```bash
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --templates-path /custom/path/to/nuclei-templates
```

#### Solution 3: Check Nuclei Tags
Sometimes templates don't have the CVE as a tag. Check the template file:

```bash
cat ~/nuclei-templates/http/cves/2025/CVE-2025-48703.yaml | grep -A5 "id:"
```

Look for the `id:` field. It should match the CVE.

#### Solution 4: Re-run Detection Test
```bash
# Full diagnostic
python3 test_template_detection.py CVE-2025-48703

# If it finds the template, the scanner should too
# If it doesn't, check the output for why
```

### Still Not Working?

If the test tool finds it but the scanner doesn't:

1. Check Nuclei version:
```bash
nuclei -version
# Should be v3.x or higher
```

2. Reinstall Nuclei:
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

3. Check permissions:
```bash
ls -la ~/nuclei-templates/http/cves/2025/
# Should be readable by your user
```

4. Try with specific template path:
```bash
# Find the template
TEMPLATE=$(find ~/nuclei-templates -name "*48703*" | head -1)

# Test it directly
nuclei -t "$TEMPLATE" -l hosts.txt
```

### Report the Issue

If template detection is still failing:

1. Run the test tool:
```bash
python3 test_template_detection.py CVE-2025-48703 > debug_output.txt
```

2. Run scanner with debug:
```bash
python3 payloadZer0.py -t hosts.txt \
    --force-scan \
    --scan-recent-days 1 \
    --debug 2>&1 | grep "CVE-2025-48703" > scanner_debug.txt
```

3. Share both outputs

### Quick Reference

**Test single CVE:**
```bash
python3 test_template_detection.py CVE-2025-48703
```

**Debug scanner:**
```bash
python3 payloadZer0.py -t hosts.txt --force-scan --debug
```

**Update templates:**
```bash
nuclei -update-templates
```

**Find template manually:**
```bash
find ~/nuclei-templates -name "*48703*"
```

**Test template works:**
```bash
nuclei -t /path/to/template.yaml -l hosts.txt -silent
```

## Expected Behavior

After fixes, you should see:

```
[1/10] Processing CVE-2025-48703...
✓ Found 1 Nuclei template(s) for CVE-2025-48703
  → /home/user/nuclei-templates/http/cves/2025/CVE-2025-48703.yaml
▶ Scanning CVE-2025-48703 against 15 target(s)...
✓ CVE-2025-48703: No vulnerabilities found (scanned 15 hosts in 2.34s)
```

## Template Detection Success Rate

**Normal expectations:**
- 40-60% of CISA KEV CVEs have Nuclei templates
- Newer CVEs (last 30 days): 30-40% have templates
- Older CVEs (1+ years): 50-70% have templates

If your success rate is much lower (< 20%), there's likely a detection issue.

## Advanced: Custom Template Detection

If you have custom templates or templates from other sources:

```bash
# Point to custom directory
python3 payloadZer0.py -t hosts.txt \
    --templates-path /path/to/custom/templates \
    --force-scan
```

The scanner will search both the custom path and default Nuclei templates.
