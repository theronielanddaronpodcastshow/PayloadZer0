#!/usr/bin/env python3
"""
KEV Scanner Utilities
Common operations and helper functions
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

def export_findings_csv(results_dir='scan_results', output_file='findings.csv'):
    """Export all findings to CSV format"""
    import csv
    
    findings = []
    results_path = Path(results_dir)
    
    if not results_path.exists():
        print(f"Error: {results_dir} not found")
        return False
    
    for result_file in results_path.glob('*.json'):
        cve_id = result_file.stem.replace('_', '-')
        if not cve_id.startswith('CVE'):
            cve_id = f"CVE-{cve_id}"
        
        try:
            with open(result_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.append({
                                'CVE': cve_id,
                                'Host': data.get('host', data.get('matched-at', 'unknown')),
                                'Template': data.get('template', 'unknown'),
                                'Severity': data.get('info', {}).get('severity', 'unknown'),
                                'Matched': data.get('matched-at', ''),
                                'Timestamp': data.get('timestamp', '')
                            })
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"Warning: Could not process {result_file}: {e}")
    
    if not findings:
        print("No findings to export")
        return False
    
    # Write CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['CVE', 'Host', 'Template', 'Severity', 'Matched', 'Timestamp'])
        writer.writeheader()
        writer.writerows(findings)
    
    print(f"Exported {len(findings)} findings to {output_file}")
    return True

def generate_report(db_path='kev_database.json', results_dir='scan_results', output_file='report.txt'):
    """Generate a comprehensive text report"""
    
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("KEV THREAT SCANNER REPORT")
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # Database statistics
    if Path(db_path).exists():
        with open(db_path, 'r') as f:
            db = json.load(f)
        
        report_lines.append("DATABASE STATISTICS")
        report_lines.append("-" * 80)
        report_lines.append(f"Total CVEs tracked: {len(db)}")
        
        ransomware = sum(1 for cve in db.values() if cve.get('known_ransomware') == 'Known')
        report_lines.append(f"Known ransomware CVEs: {ransomware}")
        
        # Recent additions
        recent = []
        for cve_id, data in db.items():
            try:
                date_added = datetime.strptime(data.get('date_added', ''), '%Y-%m-%d')
                if (datetime.now() - date_added).days <= 7:
                    recent.append((cve_id, data))
            except:
                continue
        
        report_lines.append(f"CVEs added in last 7 days: {len(recent)}")
        report_lines.append("")
    
    # Scan results
    results_path = Path(results_dir)
    if results_path.exists():
        stats = defaultdict(lambda: {'hosts': set(), 'findings': 0})
        
        for result_file in results_path.glob('*.json'):
            cve_id = result_file.stem.replace('_', '-')
            if not cve_id.startswith('CVE'):
                cve_id = f"CVE-{cve_id}"
            
            try:
                with open(result_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                host = data.get('host', data.get('matched-at', 'unknown'))
                                stats[cve_id]['hosts'].add(host)
                                stats[cve_id]['findings'] += 1
                            except:
                                continue
            except:
                continue
        
        report_lines.append("SCAN RESULTS SUMMARY")
        report_lines.append("-" * 80)
        report_lines.append(f"CVEs with findings: {len(stats)}")
        
        total_hosts = len(set(h for s in stats.values() for h in s['hosts']))
        total_findings = sum(s['findings'] for s in stats.values())
        
        report_lines.append(f"Total vulnerable hosts: {total_hosts}")
        report_lines.append(f"Total findings: {total_findings}")
        report_lines.append("")
        
        # Top findings
        report_lines.append("TOP VULNERABILITIES")
        report_lines.append("-" * 80)
        
        sorted_stats = sorted(stats.items(), key=lambda x: len(x[1]['hosts']), reverse=True)
        for i, (cve_id, data) in enumerate(sorted_stats[:20], 1):
            host_count = len(data['hosts'])
            finding_count = data['findings']
            report_lines.append(f"{i}. {cve_id}")
            report_lines.append(f"   Vulnerable hosts: {host_count}")
            report_lines.append(f"   Total findings: {finding_count}")
            
            # Sample hosts
            for host in list(data['hosts'])[:3]:
                report_lines.append(f"   - {host}")
            if len(data['hosts']) > 3:
                report_lines.append(f"   ... and {len(data['hosts']) - 3} more")
            report_lines.append("")
    
    # Write report
    report_text = '\n'.join(report_lines)
    
    with open(output_file, 'w') as f:
        f.write(report_text)
    
    print(report_text)
    print(f"\nReport saved to {output_file}")
    return True

def list_vulnerable_hosts(results_dir='scan_results', cve_id=None):
    """List all vulnerable hosts, optionally filtered by CVE"""
    
    results_path = Path(results_dir)
    if not results_path.exists():
        print(f"Error: {results_dir} not found")
        return
    
    vulnerabilities = defaultdict(set)
    
    for result_file in results_path.glob('*.json'):
        file_cve = result_file.stem.replace('_', '-')
        if not file_cve.startswith('CVE'):
            file_cve = f"CVE-{file_cve}"
        
        # Filter by CVE if specified
        if cve_id and cve_id.upper() != file_cve.upper():
            continue
        
        try:
            with open(result_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            host = data.get('host', data.get('matched-at', 'unknown'))
                            vulnerabilities[file_cve].add(host)
                        except:
                            continue
        except:
            continue
    
    if not vulnerabilities:
        print(f"No vulnerabilities found{' for ' + cve_id if cve_id else ''}")
        return
    
    # Print results
    for cve, hosts in sorted(vulnerabilities.items()):
        print(f"\n{cve}: {len(hosts)} vulnerable hosts")
        for host in sorted(hosts):
            print(f"  - {host}")

def cleanup_old_results(results_dir='scan_results', days=30):
    """Clean up scan results older than specified days"""
    
    results_path = Path(results_dir)
    if not results_path.exists():
        print(f"Error: {results_dir} not found")
        return
    
    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    
    for result_file in results_path.glob('*.json'):
        modified_time = datetime.fromtimestamp(result_file.stat().st_mtime)
        
        if modified_time < cutoff:
            result_file.unlink()
            removed += 1
            print(f"Removed: {result_file.name}")
    
    print(f"\nRemoved {removed} files older than {days} days")

def check_cve_status(cve_id, db_path='kev_database.json'):
    """Check if a specific CVE is in the database"""
    
    if not Path(db_path).exists():
        print(f"Error: {db_path} not found")
        return
    
    with open(db_path, 'r') as f:
        db = json.load(f)
    
    cve_id = cve_id.upper()
    
    if cve_id in db:
        cve_data = db[cve_id]
        print(f"✓ {cve_id} found in database")
        print(f"\nDetails:")
        print(f"  Vendor/Project: {cve_data.get('vendor_project', 'N/A')}")
        print(f"  Product: {cve_data.get('product', 'N/A')}")
        print(f"  Name: {cve_data.get('vulnerability_name', 'N/A')}")
        print(f"  Date Added: {cve_data.get('date_added', 'N/A')}")
        print(f"  Description: {cve_data.get('short_description', 'N/A')}")
        print(f"  Ransomware: {cve_data.get('known_ransomware', 'N/A')}")
    else:
        print(f"✗ {cve_id} not found in database")
        print("This CVE is not currently in the CISA KEV catalog")

def search_cves(keyword, db_path='kev_database.json'):
    """Search CVEs by keyword in database"""
    
    if not Path(db_path).exists():
        print(f"Error: {db_path} not found")
        return
    
    with open(db_path, 'r') as f:
        db = json.load(f)
    
    keyword = keyword.lower()
    matches = []
    
    for cve_id, data in db.items():
        searchable = ' '.join([
            data.get('vendor_project', ''),
            data.get('product', ''),
            data.get('vulnerability_name', ''),
            data.get('short_description', '')
        ]).lower()
        
        if keyword in searchable:
            matches.append((cve_id, data))
    
    if not matches:
        print(f"No CVEs found matching '{keyword}'")
        return
    
    print(f"Found {len(matches)} CVE(s) matching '{keyword}':\n")
    
    for cve_id, data in matches:
        print(f"{cve_id}: {data.get('vulnerability_name', 'N/A')}")
        print(f"  Vendor/Product: {data.get('vendor_project', 'N/A')} {data.get('product', 'N/A')}")
        print(f"  Added: {data.get('date_added', 'N/A')}")
        print()

def list_by_keywords(keywords, db_path='kev_database.json'):
    """List all CVEs matching any of the provided keywords"""
    
    if not Path(db_path).exists():
        print(f"Error: {db_path} not found")
        return
    
    with open(db_path, 'r') as f:
        db = json.load(f)
    
    keywords_lower = [k.lower() for k in keywords]
    matches_by_keyword = {k: [] for k in keywords}
    
    for cve_id, data in db.items():
        searchable = ' '.join([
            data.get('vendor_project', ''),
            data.get('product', ''),
            data.get('vulnerability_name', ''),
            data.get('short_description', '')
        ]).lower()
        
        for keyword in keywords_lower:
            if keyword in searchable:
                matches_by_keyword[keyword].append((cve_id, data))
    
    print("=" * 80)
    print(f"CVEs MATCHING KEYWORDS: {', '.join(keywords)}")
    print("=" * 80)
    
    total_matches = 0
    for keyword in keywords:
        matches = matches_by_keyword[keyword.lower()]
        total_matches += len(matches)
        
        print(f"\n🔍 Keyword: '{keyword}' - {len(matches)} CVE(s)")
        print("-" * 80)
        
        if matches:
            for cve_id, data in matches[:10]:  # Show first 10
                print(f"  {cve_id}: {data.get('vendor_project', 'N/A')} {data.get('product', 'N/A')}")
                print(f"    → {data.get('vulnerability_name', 'N/A')[:70]}")
                print(f"    → Added: {data.get('date_added', 'N/A')}")
            
            if len(matches) > 10:
                print(f"  ... and {len(matches) - 10} more")
        else:
            print(f"  No CVEs found for '{keyword}'")
    
    print("\n" + "=" * 80)
    print(f"TOTAL: {total_matches} unique CVE(s) found")
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(
        description='KEV Scanner Utilities - Helper tools for common operations'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export findings to CSV')
    export_parser.add_argument('--results-dir', default='scan_results', help='Results directory')
    export_parser.add_argument('-o', '--output', default='findings.csv', help='Output CSV file')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate comprehensive report')
    report_parser.add_argument('--db', default='kev_database.json', help='Database path')
    report_parser.add_argument('--results-dir', default='scan_results', help='Results directory')
    report_parser.add_argument('-o', '--output', default='report.txt', help='Output file')
    
    # List hosts command
    list_parser = subparsers.add_parser('list-hosts', help='List vulnerable hosts')
    list_parser.add_argument('--results-dir', default='scan_results', help='Results directory')
    list_parser.add_argument('--cve', help='Filter by specific CVE')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old scan results')
    cleanup_parser.add_argument('--results-dir', default='scan_results', help='Results directory')
    cleanup_parser.add_argument('--days', type=int, default=30, help='Remove files older than N days')
    
    # Check CVE command
    check_parser = subparsers.add_parser('check-cve', help='Check if CVE is in database')
    check_parser.add_argument('cve_id', help='CVE ID to check (e.g., CVE-2024-1234)')
    check_parser.add_argument('--db', default='kev_database.json', help='Database path')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search CVEs by keyword')
    search_parser.add_argument('keyword', help='Keyword to search')
    search_parser.add_argument('--db', default='kev_database.json', help='Database path')
    
    # List by keywords command
    keywords_parser = subparsers.add_parser('list-keywords', help='List CVEs matching multiple keywords')
    keywords_parser.add_argument('keywords', nargs='+', help='Keywords to search (e.g., cisco fortinet "palo alto")')
    keywords_parser.add_argument('--db', default='kev_database.json', help='Database path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute command
    if args.command == 'export':
        export_findings_csv(args.results_dir, args.output)
    
    elif args.command == 'report':
        generate_report(args.db, args.results_dir, args.output)
    
    elif args.command == 'list-hosts':
        list_vulnerable_hosts(args.results_dir, args.cve)
    
    elif args.command == 'cleanup':
        cleanup_old_results(args.results_dir, args.days)
    
    elif args.command == 'check-cve':
        check_cve_status(args.cve_id, args.db)
    
    elif args.command == 'search':
        search_cves(args.keyword, args.db)
    
    elif args.command == 'list-keywords':
        list_by_keywords(args.keywords, args.db)

if __name__ == "__main__":
    main()
