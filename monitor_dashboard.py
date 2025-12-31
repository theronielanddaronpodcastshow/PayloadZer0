#!/usr/bin/env python3
"""
PayloadZer0 KEV Scanner Monitoring Dashboard
Real-time status and statistics viewer
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import time

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def format_time_ago(timestamp_str):
    """Format timestamp as 'X hours/minutes ago'"""
    try:
        ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        now = datetime.now(ts.tzinfo)
        delta = now - ts
        
        if delta.days > 0:
            return f"{delta.days} day{'s' if delta.days != 1 else ''} ago"
        hours = delta.seconds // 3600
        if hours > 0:
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        minutes = (delta.seconds % 3600) // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    except:
        return "Unknown"

def load_database(db_path='kev_database.json'):
    """Load CVE database"""
    if not Path(db_path).exists():
        return {}
    
    try:
        with open(db_path, 'r') as f:
            return json.load(f)
    except:
        return {}

def analyze_scan_results(results_dir='scan_results'):
    """Analyze scan results directory"""
    results_path = Path(results_dir)
    if not results_path.exists():
        return {}
    
    stats = defaultdict(lambda: {'vulnerable_hosts': set(), 'total_findings': 0})
    
    for result_file in results_path.glob('*.json'):
        cve_id = result_file.stem.replace('_', '-').upper()
        if not cve_id.startswith('CVE'):
            cve_id = 'CVE-' + cve_id.replace('CVE', '')
        
        try:
            with open(result_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            host = data.get('host', data.get('matched-at', 'unknown'))
                            stats[cve_id]['vulnerable_hosts'].add(host)
                            stats[cve_id]['total_findings'] += 1
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            continue
    
    # Convert sets to counts
    for cve_id in stats:
        stats[cve_id]['unique_hosts'] = len(stats[cve_id]['vulnerable_hosts'])
        stats[cve_id]['vulnerable_hosts'] = list(stats[cve_id]['vulnerable_hosts'])[:5]  # Keep top 5
    
    return dict(stats)

def tail_log(log_path='kev_scanner.log', lines=10):
    """Get last N lines from log file"""
    if not Path(log_path).exists():
        return []
    
    try:
        with open(log_path, 'r') as f:
            return f.readlines()[-lines:]
    except:
        return []

def display_dashboard(continuous=False, keywords=None):
    """Display monitoring dashboard"""
    
    while True:
        clear_screen()
        
        # Header
        print("=" * 80)
        print(" " * 20 + "PayloadZer0 - KEV THREAT SCANNER DASHBOARD")
        print("=" * 80)
        print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if keywords:
            print(f"🎯 Filtered by keywords: {', '.join(keywords)}")
        print("-" * 80)
        
        # Database statistics
        print("\n📊 CVE DATABASE STATISTICS")
        print("-" * 80)
        db = load_database()
        
        if db:
            # Apply keyword filter if specified
            if keywords:
                filtered_db = {}
                keywords_lower = [k.lower() for k in keywords]
                
                for cve_id, data in db.items():
                    searchable = ' '.join([
                        data.get('vendor_project', ''),
                        data.get('product', ''),
                        data.get('vulnerability_name', ''),
                        data.get('short_description', '')
                    ]).lower()
                    
                    for keyword in keywords_lower:
                        if keyword in searchable:
                            filtered_db[cve_id] = data
                            break
                
                db = filtered_db
                print(f"Showing CVEs matching: {', '.join(keywords)}")
            
            total_cves = len(db)
            ransomware_cves = sum(1 for cve in db.values() if cve.get('known_ransomware') == 'Known')
            
            # Recent additions
            recent_cves = []
            for cve_id, data in db.items():  # db is already filtered if keywords specified
                try:
                    date_added = datetime.strptime(data.get('date_added', ''), '%Y-%m-%d')
                    days_old = (datetime.now() - date_added).days
                    if days_old <= 7:
                        recent_cves.append((cve_id, data, days_old))
                except:
                    continue
            
            recent_cves.sort(key=lambda x: x[2])
            
            print(f"Total CVEs tracked: {total_cves}")
            print(f"Known ransomware CVEs: {ransomware_cves}")
            print(f"CVEs added last 7 days: {len(recent_cves)}")
            
            if recent_cves:
                print("\nRecent additions:")
                for cve_id, data, days in recent_cves[:5]:
                    vendor = data.get('vendor_project', 'N/A')
                    product = data.get('product', 'N/A')
                    print(f"  • {cve_id} - {vendor} {product} ({days}d ago)")
        else:
            print("⚠️  No CVE database found. Run scanner to initialize.")
        
        # Scan results (also filtered by keywords if specified)
        print("\n🎯 SCAN RESULTS")
        print("-" * 80)
        results = analyze_scan_results()
        
        # Filter results by keywords if specified
        if keywords and results:
            keywords_lower = [k.lower() for k in keywords]
            filtered_results = {}
            
            # Check each CVE in results against keywords
            for cve_id, data in results.items():
                if cve_id in db:  # If CVE matches keywords from database filter above
                    filtered_results[cve_id] = data
            
            results = filtered_results
        
        if results:
            total_vulnerable = sum(r['unique_hosts'] for r in results.values())
            total_findings = sum(r['total_findings'] for r in results.values())
            
            print(f"CVEs with findings: {len(results)}")
            print(f"Total vulnerable hosts: {total_vulnerable}")
            print(f"Total vulnerability instances: {total_findings}")
            
            # Top vulnerable CVEs
            print("\nTop findings:")
            sorted_results = sorted(results.items(), key=lambda x: x[1]['unique_hosts'], reverse=True)
            
            for cve_id, data in sorted_results[:10]:
                hosts = data['unique_hosts']
                findings = data['total_findings']
                print(f"  🔴 {cve_id}: {hosts} host{'s' if hosts != 1 else ''} ({findings} finding{'s' if findings != 1 else ''})")
                
                # Show sample hosts
                if data['vulnerable_hosts']:
                    for host in data['vulnerable_hosts'][:2]:
                        print(f"     ↳ {host}")
        else:
            if keywords:
                print(f"No scan results found for keywords: {', '.join(keywords)}")
            else:
                print("No scan results found yet.")
        
        # Recent log activity
        print("\n📝 RECENT LOG ACTIVITY")
        print("-" * 80)
        log_lines = tail_log(lines=8)
        
        if log_lines:
            for line in log_lines:
                line = line.strip()
                if 'ERROR' in line:
                    print(f"  ❌ {line}")
                elif 'WARNING' in line:
                    print(f"  ⚠️  {line}")
                elif 'INFO' in line:
                    print(f"  ℹ️  {line}")
                else:
                    print(f"     {line}")
        else:
            print("No log file found.")
        
        # Status indicators
        print("\n🔧 SYSTEM STATUS")
        print("-" * 80)
        
        # Check if scanner is running
        try:
            import subprocess
            result = subprocess.run(['pgrep', '-f', 'kev_threat_scanner.py'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                print(f"✅ Scanner running (PID: {', '.join(pids)})")
            else:
                print("⚠️  Scanner not running")
        except:
            print("❓ Unable to check scanner status")
        
        # File system info
        db_path = Path('kev_database.json')
        if db_path.exists():
            size = db_path.stat().st_size / 1024
            modified = datetime.fromtimestamp(db_path.stat().st_mtime)
            print(f"📁 Database: {size:.1f} KB (modified {format_time_ago(modified.isoformat())})")
        
        results_path = Path('scan_results')
        if results_path.exists():
            result_files = list(results_path.glob('*.json'))
            total_size = sum(f.stat().st_size for f in result_files) / 1024 / 1024
            print(f"📁 Scan results: {len(result_files)} files ({total_size:.2f} MB)")
        
        print("\n" + "=" * 80)
        
        if continuous:
            print("Press Ctrl+C to exit... (refreshing in 10 seconds)")
            try:
                time.sleep(10)
            except KeyboardInterrupt:
                print("\n\nDashboard stopped.")
                break
        else:
            break

def main():
    import argparse
    parser = argparse.ArgumentParser(description='PayloadZer0 - KEV Scanner Monitoring Dashboard')
    parser.add_argument('-c', '--continuous', action='store_true', 
                       help='Continuously refresh dashboard')
    parser.add_argument('--db', default='kev_database.json',
                       help='Path to KEV database')
    parser.add_argument('--results', default='scan_results',
                       help='Path to scan results directory')
    parser.add_argument('--log', default='kev_scanner.log',
                       help='Path to log file')
    parser.add_argument('--keywords', nargs='+',
                       help='Filter display by keywords (e.g., --keywords cisco fortinet)')
    
    args = parser.parse_args()
    
    try:
        display_dashboard(continuous=args.continuous, keywords=args.keywords)
    except KeyboardInterrupt:
        print("\n\nDashboard stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()
