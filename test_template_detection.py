#!/usr/bin/env python3
"""
Template Verification Tool
Tests whether the scanner can find a specific CVE template
"""

import subprocess
import sys
import os
from pathlib import Path

def test_template_detection(cve_id):
    """Test all methods of finding a template"""
    print("=" * 80)
    print(f"Testing Template Detection for {cve_id}")
    print("=" * 80)
    
    found_templates = []
    
    # Method 1: nuclei -tl -tags (lowercase)
    print(f"\n[Method 1] nuclei -tl -tags {cve_id.lower()}")
    try:
        result = subprocess.run(
            ["nuclei", "-tl", "-tags", cve_id.lower()],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"  Return code: {result.returncode}")
        if result.stdout.strip():
            lines = [l.strip() for l in result.stdout.split('\n') if l.strip() and ('.yaml' in l or '.yml' in l)]
            if lines:
                print(f"  ✓ Found {len(lines)} template(s):")
                for line in lines:
                    print(f"    → {line}")
                    found_templates.extend(lines)
            else:
                print(f"  ✗ No templates found")
                print(f"  Raw output: {result.stdout[:200]}")
        else:
            print(f"  ✗ No output")
        if result.stderr:
            print(f"  Stderr: {result.stderr[:200]}")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # Method 2: Without CVE- prefix
    cve_number = cve_id.replace('CVE-', '').replace('cve-', '')
    print(f"\n[Method 2] nuclei -tl -tags {cve_number}")
    try:
        result = subprocess.run(
            ["nuclei", "-tl", "-tags", cve_number],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"  Return code: {result.returncode}")
        if result.stdout.strip():
            lines = [l.strip() for l in result.stdout.split('\n') if l.strip() and ('.yaml' in l or '.yml' in l)]
            if lines:
                print(f"  ✓ Found {len(lines)} template(s):")
                for line in lines:
                    print(f"    → {line}")
                    found_templates.extend(lines)
            else:
                print(f"  ✗ No templates found")
        else:
            print(f"  ✗ No output")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # Method 3: Filesystem search
    print(f"\n[Method 3] Filesystem search in nuclei-templates/")
    possible_dirs = [
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.local/nuclei-templates"),
        "/root/nuclei-templates",
        os.path.expanduser("~/go/pkg/mod/github.com/projectdiscovery/nuclei-templates"),
    ]
    
    for templates_dir in possible_dirs:
        if os.path.exists(templates_dir):
            print(f"  Checking: {templates_dir}")
            
            cve_variations = [
                cve_id.lower(),
                cve_id.upper(),
                cve_id.lower().replace('-', ''),
                cve_number.lower(),
            ]
            
            found_in_dir = []
            for root, dirs, files in os.walk(templates_dir):
                for file in files:
                    if file.endswith(('.yaml', '.yml')):
                        file_lower = file.lower()
                        for cve_var in cve_variations:
                            if cve_var in file_lower:
                                full_path = os.path.join(root, file)
                                found_in_dir.append(full_path)
                                break
            
            if found_in_dir:
                print(f"  ✓ Found {len(found_in_dir)} template(s):")
                for path in found_in_dir:
                    print(f"    → {path}")
                    found_templates.extend(found_in_dir)
            else:
                print(f"  ✗ No templates found in this directory")
        else:
            print(f"  ✗ Directory doesn't exist: {templates_dir}")
    
    # Method 4: Direct template lookup
    print(f"\n[Method 4] Direct template lookup")
    try:
        # Try common template paths
        test_paths = [
            f"cves/{cve_id.split('-')[1]}/{cve_id.upper()}.yaml",
            f"http/cves/{cve_id.split('-')[1]}/{cve_id.lower()}.yaml",
            cve_id.lower(),
            cve_id.upper(),
        ]
        
        for test_path in test_paths:
            result = subprocess.run(
                ["nuclei", "-t", test_path, "-validate"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"  ✓ Template validated: {test_path}")
                found_templates.append(test_path)
                break
        else:
            print(f"  ✗ No valid template found with direct lookup")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    unique_templates = list(set(found_templates))
    
    if unique_templates:
        print(f"✓ FOUND {len(unique_templates)} unique template(s) for {cve_id}:")
        for template in unique_templates:
            print(f"  → {template}")
        
        # Test if we can actually scan with it
        print(f"\n[Test Scan] Testing template with nuclei...")
        test_file = "/tmp/test_target.txt"
        with open(test_file, 'w') as f:
            f.write("https://example.com\n")
        
        try:
            result = subprocess.run(
                ["nuclei", "-t", unique_templates[0], "-l", test_file, "-silent"],
                capture_output=True,
                text=True,
                timeout=30
            )
            print(f"  Return code: {result.returncode}")
            if result.returncode == 0:
                print(f"  ✓ Template is valid and scannable")
            else:
                print(f"  ⚠ Template returned non-zero exit code")
                if result.stderr:
                    print(f"  Stderr: {result.stderr[:200]}")
        except Exception as e:
            print(f"  ✗ Scan test failed: {e}")
    else:
        print(f"✗ NO TEMPLATES FOUND for {cve_id}")
        print("\nTroubleshooting:")
        print("  1. Check if templates are updated: nuclei -update-templates")
        print("  2. Verify Nuclei installation: nuclei -version")
        print("  3. Check templates directory exists")
        print(f"  4. Manually search: find ~/nuclei-templates -name '*{cve_id.lower()}*'")
    
    print("=" * 80)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_template_detection.py CVE-2024-1234")
        sys.exit(1)
    
    cve_id = sys.argv[1].upper()
    if not cve_id.startswith("CVE-"):
        cve_id = "CVE-" + cve_id
    
    test_template_detection(cve_id)
