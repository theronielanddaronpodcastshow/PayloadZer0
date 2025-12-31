#!/usr/bin/env python3
"""
PayloadZer0 Emerging Threat Scanner
Monitors CISA Known Exploited Vulnerabilities catalog and automatically
scans targets using Nuclei templates for active exploitation.

Author: OB1Sec
"""

import json
import os
import sys
import time
import hashlib
import subprocess
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Set, Optional
import requests
from dataclasses import dataclass, asdict
import threading
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('kev_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class KEVEntry:
    """Represents a CISA KEV catalog entry"""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware: str
    notes: str
    
    def __hash__(self):
        return hash(self.cve_id)
    
    def __eq__(self, other):
        if isinstance(other, KEVEntry):
            return self.cve_id == other.cve_id
        return False


class TeamsNotifier:
    """Handle Microsoft Teams webhook notifications"""
    
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv('TEAMS_WEBHOOK_URL')
        self.enabled = bool(self.webhook_url)
        
        if not self.enabled:
            logger.warning("Teams webhook URL not configured. Notifications disabled.")
    
    def send_notification(self, title: str, message: str, color: str = "0078D4", 
                         facts: Optional[List[Dict]] = None) -> bool:
        """Send notification to Teams channel"""
        if not self.enabled:
            return False
        
        try:
            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color,
                "summary": title,
                "sections": [{
                    "activityTitle": title,
                    "activitySubtitle": f"PayloadZer0 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "text": message,
                    "facts": facts or []
                }]
            }
            
            response = requests.post(
                self.webhook_url,
                json=card,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"Teams notification sent: {title}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return False
    
    def notify_new_cves(self, cves: List[KEVEntry]):
        """Notify about newly discovered CVEs"""
        facts = [
            {"name": "CVE Count", "value": str(len(cves))},
            {"name": "CVEs", "value": ", ".join([c.cve_id for c in cves[:10]])}
        ]
        if len(cves) > 10:
            facts.append({"name": "Additional", "value": f"+{len(cves) - 10} more"})
        
        self.send_notification(
            title="🚨 New CISA KEV Vulnerabilities Detected",
            message=f"Discovered {len(cves)} new exploited vulnerabilities in the wild.",
            color="FF0000",
            facts=facts
        )
    
    def notify_scan_start(self, cve_count: int, target_count: int):
        """Notify scan has started"""
        self.send_notification(
            title="▶️ Vulnerability Scan Started",
            message=f"Beginning scan for {cve_count} CVEs against {target_count} targets",
            color="FFA500",
            facts=[
                {"name": "CVEs to Scan", "value": str(cve_count)},
                {"name": "Target Hosts", "value": str(target_count)}
            ]
        )
    
    def notify_scan_complete(self, duration: float, findings: Dict[str, int]):
        """Notify scan has completed"""
        total_findings = sum(findings.values())
        color = "FF0000" if total_findings > 0 else "00FF00"
        
        facts = [
            {"name": "Duration", "value": f"{duration:.2f} seconds"},
            {"name": "Total Findings", "value": str(total_findings)}
        ]
        
        for cve, count in sorted(findings.items(), key=lambda x: x[1], reverse=True)[:10]:
            if count > 0:
                facts.append({"name": cve, "value": f"{count} vulnerable hosts"})
        
        icon = "🔴" if total_findings > 0 else "✅"
        self.send_notification(
            title=f"{icon} Vulnerability Scan Completed",
            message=f"Scan finished. Found {total_findings} vulnerable hosts across {len([c for c in findings.values() if c > 0])} CVEs.",
            color=color,
            facts=facts
        )
    
    def notify_findings(self, cve_id: str, vulnerable_hosts: List[str]):
        """Notify about specific CVE findings"""
        if not vulnerable_hosts:
            return
        
        self.send_notification(
            title=f"💥 CRITICAL: Active Exploitation Detected - {cve_id}",
            message=f"Found {len(vulnerable_hosts)} vulnerable hosts for actively exploited CVE",
            color="FF0000",
            facts=[
                {"name": "CVE", "value": cve_id},
                {"name": "Vulnerable Hosts", "value": str(len(vulnerable_hosts))},
                {"name": "Sample Hosts", "value": ", ".join(vulnerable_hosts[:5])}
            ]
        )


class KEVDatabase:
    """Manage local KEV database with deduplication"""
    
    def __init__(self, db_path: str = "kev_database.json"):
        self.db_path = Path(db_path)
        self.cves: Dict[str, KEVEntry] = {}
        self.load()
    
    def load(self):
        """Load existing database"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    self.cves = {
                        cve_id: KEVEntry(**entry) 
                        for cve_id, entry in data.items()
                    }
                logger.info(f"Loaded {len(self.cves)} CVEs from database")
            except Exception as e:
                logger.error(f"Failed to load database: {e}")
                self.cves = {}
        else:
            logger.info("No existing database found, creating new one")
    
    def save(self):
        """Save database to disk"""
        try:
            with open(self.db_path, 'w') as f:
                data = {cve_id: asdict(entry) for cve_id, entry in self.cves.items()}
                json.dump(data, f, indent=2)
            logger.info(f"Saved {len(self.cves)} CVEs to database")
        except Exception as e:
            logger.error(f"Failed to save database: {e}")
    
    def add_cves(self, new_cves: List[KEVEntry]) -> List[KEVEntry]:
        """Add CVEs and return only new ones (deduplication)"""
        added = []
        for cve in new_cves:
            if cve.cve_id not in self.cves:
                self.cves[cve.cve_id] = cve
                added.append(cve)
                logger.info(f"New CVE added: {cve.cve_id} - {cve.vulnerability_name}")
        
        if added:
            self.save()
        
        return added
    
    def get_all_cves(self) -> List[KEVEntry]:
        """Get all CVEs from database"""
        return list(self.cves.values())
    
    def get_recent_cves(self, days: int = 7) -> List[KEVEntry]:
        """Get CVEs added in the last N days"""
        cutoff = datetime.now() - timedelta(days=days)
        recent = []
        
        for cve in self.cves.values():
            try:
                date_added = datetime.strptime(cve.date_added, "%Y-%m-%d")
                if date_added >= cutoff:
                    recent.append(cve)
            except ValueError:
                continue
        
        return recent
    
    def filter_by_keywords(self, cves: List[KEVEntry], keywords: List[str]) -> List[KEVEntry]:
        """Filter CVEs by keywords in vendor, product, or description"""
        if not keywords:
            return cves
        
        filtered = []
        keywords_lower = [k.lower() for k in keywords]
        
        for cve in cves:
            # Create searchable text from CVE fields
            searchable = ' '.join([
                cve.vendor_project.lower(),
                cve.product.lower(),
                cve.vulnerability_name.lower(),
                cve.short_description.lower()
            ])
            
            # Check if any keyword matches
            for keyword in keywords_lower:
                if keyword in searchable:
                    filtered.append(cve)
                    logger.info(f"  ✓ {cve.cve_id} matches keyword '{keyword}': {cve.vendor_project} {cve.product}")
                    break
        
        return filtered


class NucleiScanner:
    """Handle Nuclei template discovery and scanning"""
    
    def __init__(self, nuclei_path: str = "nuclei", templates_path: Optional[str] = None):
        self.nuclei_path = nuclei_path
        self.templates_path = templates_path
        self.verify_nuclei()
    
    def verify_nuclei(self):
        """Verify Nuclei is installed and accessible"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Nuclei verified: {result.stdout.strip()}")
            else:
                raise Exception("Nuclei not responding correctly")
        except Exception as e:
            logger.error(f"Nuclei verification failed: {e}")
            logger.error("Please install Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            sys.exit(1)
    
    def update_templates(self) -> bool:
        """Update Nuclei templates"""
        try:
            logger.info("Updating Nuclei templates...")
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                logger.info("Templates updated successfully")
                return True
            else:
                logger.warning(f"Template update had issues: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Failed to update templates: {e}")
            return False
    
    def find_templates_for_cve(self, cve_id: str) -> List[str]:
        """Find Nuclei templates for a specific CVE using multiple methods"""
        templates = []
        
        # Method 1: Try nuclei -tl with the exact CVE ID
        try:
            result = subprocess.run(
                [self.nuclei_path, "-tl", "-tags", cve_id.lower()],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and ('.yaml' in line or '.yml' in line):
                        templates.append(line)
        except Exception as e:
            logger.debug(f"Method 1 failed for {cve_id}: {e}")
        
        # Method 2: Try with just the CVE number (without CVE- prefix)
        if not templates:
            cve_number = cve_id.replace('CVE-', '').replace('cve-', '')
            try:
                result = subprocess.run(
                    [self.nuclei_path, "-tl", "-tags", cve_number],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line and ('.yaml' in line or '.yml' in line):
                            templates.append(line)
            except Exception as e:
                logger.debug(f"Method 2 failed for {cve_id}: {e}")
        
        # Method 3: Direct filesystem search in Nuclei templates directory
        if not templates:
            try:
                # Get Nuclei templates directory
                result = subprocess.run(
                    [self.nuclei_path, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Try to find templates directory
                import os
                possible_dirs = [
                    os.path.expanduser("~/nuclei-templates"),
                    os.path.expanduser("~/.local/nuclei-templates"),
                    "/root/nuclei-templates",
                    self.templates_path if self.templates_path else None
                ]
                
                for templates_dir in possible_dirs:
                    if templates_dir and os.path.exists(templates_dir):
                        # Search for CVE template files
                        cve_variations = [
                            cve_id.lower(),
                            cve_id.upper(),
                            cve_id.lower().replace('-', ''),
                            cve_id.upper().replace('-', ''),
                        ]
                        
                        for root, dirs, files in os.walk(templates_dir):
                            for file in files:
                                if file.endswith(('.yaml', '.yml')):
                                    file_lower = file.lower()
                                    # Check if any CVE variation is in filename
                                    for cve_var in cve_variations:
                                        if cve_var in file_lower:
                                            full_path = os.path.join(root, file)
                                            templates.append(full_path)
                                            break
                        
                        if templates:
                            break
            except Exception as e:
                logger.debug(f"Method 3 (filesystem search) failed for {cve_id}: {e}")
        
        # Method 4: Try searching with template ID directly
        if not templates:
            try:
                result = subprocess.run(
                    [self.nuclei_path, "-t", cve_id.lower(), "-validate"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # If validate succeeds, the template exists
                if result.returncode == 0:
                    # Try to get the actual template path
                    result2 = subprocess.run(
                        [self.nuclei_path, "-t", cve_id.lower(), "-tl"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result2.stdout.strip():
                        for line in result2.stdout.split('\n'):
                            line = line.strip()
                            if line and ('.yaml' in line or '.yml' in line):
                                templates.append(line)
            except Exception as e:
                logger.debug(f"Method 4 failed for {cve_id}: {e}")
        
        # Deduplicate and clean up
        templates = list(set(templates))
        
        if templates:
            logger.info(f"✓ Found {len(templates)} Nuclei template(s) for {cve_id}")
            for template in templates:
                logger.info(f"  → {template}")
        else:
            logger.warning(f"✗ No Nuclei template available for {cve_id} - SKIPPING")
            logger.debug(f"  Tried: nuclei -tl -tags {cve_id.lower()}, filesystem search, and direct lookup")
        
        return templates
    
    def scan_targets(self, cve_id: str, templates: List[str], targets_file: str, 
                     output_dir: str, rate_limit: int = 150, timeout: int = 10,
                     verbose_scan: bool = False, show_nuclei_output: bool = False) -> Dict:
        """Scan targets with specified templates"""
        if not templates:
            logger.info(f"⊘ Skipping {cve_id} - No Nuclei template available")
            return {"cve": cve_id, "vulnerable_hosts": [], "scanned": False, "reason": "no_template"}
        
        # Count targets
        try:
            with open(targets_file, 'r') as f:
                target_list = [line.strip() for line in f if line.strip()]
                target_count = len(target_list)
        except Exception as e:
            logger.error(f"Cannot read targets file: {e}")
            return {"cve": cve_id, "vulnerable_hosts": [], "scanned": False, "reason": "file_error"}
        
        output_file = Path(output_dir) / f"{cve_id.replace('-', '_')}_results.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Build nuclei command
            cmd = [
                self.nuclei_path,
                "-l", targets_file,
                "-t", ",".join(templates),
                "-json",
                "-o", str(output_file),
                "-rate-limit", str(rate_limit),
                "-timeout", str(timeout),
            ]
            
            # Add silent mode unless verbose scanning requested
            if not verbose_scan:
                cmd.extend(["-silent", "-no-color"])
            
            if self.templates_path:
                cmd.extend(["-templates-path", self.templates_path])
            
            # Log the actual command being executed
            cmd_str = ' '.join(cmd)
            logger.info(f"▶ Scanning {cve_id} against {target_count} target(s)...")
            logger.debug(f"  Command: {cmd_str}")
            
            # Time the actual scan
            import time
            scan_start = time.time()
            
            # If showing Nuclei output, don't capture stdout so it prints to console
            if show_nuclei_output:
                logger.info("  [Nuclei Output Below]")
                logger.info("  " + "-" * 60)
                result = subprocess.run(
                    cmd,
                    capture_output=False,  # Let output go to console
                    text=True,
                    timeout=3600
                )
                logger.info("  " + "-" * 60)
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600  # 1 hour max per CVE scan
                )
                
                # Log Nuclei output for debugging
                if verbose_scan and result.stdout:
                    logger.info(f"  Nuclei stdout:\n{result.stdout}")
            
            scan_duration = time.time() - scan_start
            
            if result.stderr:
                logger.debug(f"  Nuclei stderr: {result.stderr[:500]}")
            
            if result.returncode != 0:
                logger.warning(f"  Nuclei exited with code {result.returncode} for {cve_id}")
            
            # Parse results
            vulnerable_hosts = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line)
                                    host = data.get('host', data.get('matched-at', 'unknown'))
                                    if host not in vulnerable_hosts:
                                        vulnerable_hosts.append(host)
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    logger.error(f"  Error parsing results for {cve_id}: {e}")
            
            # Report results
            if vulnerable_hosts:
                logger.info(f"✓ {cve_id}: Found {len(vulnerable_hosts)} VULNERABLE host(s) in {scan_duration:.2f}s")
                for i, host in enumerate(vulnerable_hosts[:5], 1):
                    logger.info(f"  {i}. {host}")
                if len(vulnerable_hosts) > 5:
                    logger.info(f"  ... and {len(vulnerable_hosts) - 5} more")
            else:
                logger.info(f"✓ {cve_id}: No vulnerabilities found (scanned {target_count} hosts in {scan_duration:.2f}s)")
            
            return {
                "cve": cve_id,
                "vulnerable_hosts": vulnerable_hosts,
                "scanned": True,
                "output_file": str(output_file),
                "scan_duration": scan_duration,
                "targets_scanned": target_count
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"⏱ Scan timeout for {cve_id} after 1 hour")
            return {"cve": cve_id, "vulnerable_hosts": [], "scanned": False, "error": "timeout"}
        except Exception as e:
            logger.error(f"✗ Scan error for {cve_id}: {e}")
            return {"cve": cve_id, "vulnerable_hosts": [], "scanned": False, "error": str(e)}


class KEVThreatScanner:
    """Main orchestrator for KEV monitoring and scanning"""
    
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self, config: Dict):
        self.config = config
        self.db = KEVDatabase(config.get('database_path', 'kev_database.json'))
        self.notifier = TeamsNotifier(config.get('teams_webhook'))
        self.scanner = NucleiScanner(
            config.get('nuclei_path', 'nuclei'),
            config.get('templates_path')
        )
        self.running = False
    
    def fetch_kev_catalog(self) -> Optional[List[KEVEntry]]:
        """Fetch latest CISA KEV catalog"""
        try:
            logger.info("Fetching CISA KEV catalog...")
            response = requests.get(self.CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            kev_entries = []
            for vuln in vulnerabilities:
                entry = KEVEntry(
                    cve_id=vuln.get('cveID', ''),
                    vendor_project=vuln.get('vendorProject', ''),
                    product=vuln.get('product', ''),
                    vulnerability_name=vuln.get('vulnerabilityName', ''),
                    date_added=vuln.get('dateAdded', ''),
                    short_description=vuln.get('shortDescription', ''),
                    required_action=vuln.get('requiredAction', ''),
                    due_date=vuln.get('dueDate', ''),
                    known_ransomware=vuln.get('knownRansomwareCampaignUse', ''),
                    notes=vuln.get('notes', '')
                )
                kev_entries.append(entry)
            
            logger.info(f"Fetched {len(kev_entries)} vulnerabilities from CISA KEV")
            return kev_entries
            
        except Exception as e:
            logger.error(f"Failed to fetch KEV catalog: {e}")
            return None
    
    def scan_for_cves(self, cves: List[KEVEntry], targets_file: str) -> Dict[str, int]:
        """Scan targets for specified CVEs"""
        results = {}
        output_dir = self.config.get('output_dir', 'scan_results')
        
        # Count targets
        try:
            with open(targets_file, 'r') as f:
                target_count = len([line for line in f if line.strip()])
        except Exception as e:
            logger.error(f"Cannot read targets file: {e}")
            return results
        
        # Statistics tracking
        cves_with_templates = 0
        cves_without_templates = 0
        cves_with_findings = 0
        total_vulnerable_hosts = set()
        
        logger.info("=" * 80)
        logger.info(f"Starting scan of {len(cves)} CVE(s) against {target_count} target(s)")
        logger.info("=" * 80)
        
        # Notify scan start
        if self.config.get('notify_scan_events', True):
            self.notifier.notify_scan_start(len(cves), target_count)
        
        start_time = time.time()
        
        for idx, cve in enumerate(cves, 1):
            logger.info(f"\n[{idx}/{len(cves)}] Processing {cve.cve_id}...")
            
            # Find templates
            templates = self.scanner.find_templates_for_cve(cve.cve_id)
            
            if not templates:
                results[cve.cve_id] = 0
                cves_without_templates += 1
                continue
            
            cves_with_templates += 1
            
            # Scan
            scan_result = self.scanner.scan_targets(
                cve.cve_id,
                templates,
                targets_file,
                output_dir,
                rate_limit=self.config.get('rate_limit', 150),
                timeout=self.config.get('scan_timeout', 10),
                verbose_scan=self.config.get('verbose_scan', False),
                show_nuclei_output=self.config.get('show_nuclei_output', False)
            )
            
            vulnerable_count = len(scan_result.get('vulnerable_hosts', []))
            results[cve.cve_id] = vulnerable_count
            
            if vulnerable_count > 0:
                cves_with_findings += 1
                total_vulnerable_hosts.update(scan_result['vulnerable_hosts'])
            
            # Notify if findings and enabled
            if vulnerable_count > 0 and self.config.get('notify_findings', True):
                self.notifier.notify_findings(
                    cve.cve_id,
                    scan_result['vulnerable_hosts']
                )
        
        duration = time.time() - start_time
        
        # Print summary
        logger.info("\n" + "=" * 80)
        logger.info("SCAN COMPLETE - SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total CVEs processed: {len(cves)}")
        logger.info(f"  ✓ CVEs with Nuclei templates: {cves_with_templates}")
        logger.info(f"  ✗ CVEs without templates (skipped): {cves_without_templates}")
        logger.info(f"  ⚠ CVEs with findings: {cves_with_findings}")
        logger.info(f"Total unique vulnerable hosts: {len(total_vulnerable_hosts)}")
        logger.info(f"Total scan duration: {duration:.2f} seconds")
        
        if cves_without_templates > 0:
            logger.info(f"\n⚠ Note: {cves_without_templates} CVE(s) were skipped due to missing Nuclei templates")
            logger.info("  This is normal - not all CISA KEV CVEs have public Nuclei templates yet")
        
        logger.info("=" * 80 + "\n")
        
        # Notify scan complete
        if self.config.get('notify_scan_events', True):
            self.notifier.notify_scan_complete(duration, results)
        
        return results
    
    def check_and_scan(self, targets_file: str, force_scan: bool = False, keywords: List[str] = None):
        """Check for new CVEs and scan if found"""
        # Fetch latest KEV
        kev_entries = self.fetch_kev_catalog()
        if not kev_entries:
            logger.error("Failed to fetch KEV catalog, skipping this cycle")
            return
        
        # Add to database and get new CVEs
        new_cves = self.db.add_cves(kev_entries)
        
        # Apply keyword filtering if specified
        if keywords:
            logger.info(f"\n🔍 Filtering CVEs by keywords: {', '.join(keywords)}")
            logger.info("=" * 80)
            
            if new_cves:
                filtered_new = self.db.filter_by_keywords(new_cves, keywords)
                skipped = len(new_cves) - len(filtered_new)
                if skipped > 0:
                    logger.info(f"  ⊘ Skipped {skipped} CVE(s) not matching keywords")
                new_cves = filtered_new
            
            if force_scan:
                all_recent = self.db.get_recent_cves(
                    days=self.config.get('scan_recent_days', 30)
                )
                filtered_recent = self.db.filter_by_keywords(all_recent, keywords)
                skipped = len(all_recent) - len(filtered_recent)
                if skipped > 0:
                    logger.info(f"  ⊘ Skipped {skipped} recent CVE(s) not matching keywords")
                logger.info("=" * 80)
        
        if not new_cves and not force_scan:
            logger.info("No new CVEs found, skipping scan")
            return
        
        if new_cves:
            logger.info(f"Discovered {len(new_cves)} new CVEs!")
            # Notify about new CVEs
            if self.config.get('notify_new_cves', True):
                self.notifier.notify_new_cves(new_cves)
        
        # Decide what to scan
        if force_scan:
            if keywords:
                cves_to_scan = self.db.filter_by_keywords(
                    self.db.get_recent_cves(days=self.config.get('scan_recent_days', 30)),
                    keywords
                )
            else:
                cves_to_scan = self.db.get_recent_cves(
                    days=self.config.get('scan_recent_days', 30)
                )
            logger.info(f"Force scan: scanning {len(cves_to_scan)} CVE(s)")
        else:
            cves_to_scan = new_cves
        
        # Perform scan
        if cves_to_scan:
            results = self.scan_for_cves(cves_to_scan, targets_file)
            logger.info(f"Scan complete. Results: {results}")
        else:
            logger.info("No CVEs to scan after filtering")
    
    def run_continuous(self, targets_file: str, check_interval: int = 3600, keywords: List[str] = None):
        """Run continuous monitoring mode"""
        logger.info(f"Starting continuous monitoring (check every {check_interval}s)")
        if keywords:
            logger.info(f"🎯 Monitoring keywords: {', '.join(keywords)}")
        self.running = True
        
        # Initial template update
        self.scanner.update_templates()
        
        # Initial scan
        self.check_and_scan(targets_file, force_scan=True, keywords=keywords)
        
        try:
            while self.running:
                logger.info(f"Waiting {check_interval} seconds until next check...")
                time.sleep(check_interval)
                
                if not self.running:
                    break
                
                # Update templates periodically
                if self.config.get('auto_update_templates', True):
                    self.scanner.update_templates()
                
                # Check and scan
                self.check_and_scan(targets_file, keywords=keywords)
                
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
            self.running = False
        
        logger.info("Continuous monitoring stopped")
    
    def stop(self):
        """Stop the scanner"""
        self.running = False


def main():
    parser = argparse.ArgumentParser(
        description='CISA KEV Emerging Threat Scanner - Monitor and scan for actively exploited vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single scan of recent CVEs
  python payloadZer0.py -t hosts.txt --force-scan
  
  # Monitor only Cisco and Fortinet CVEs
  python payloadZer0.py -t hosts.txt --continuous --keywords cisco fortinet
  
  # Monitor with multi-word keywords
  python payloadZer0.py -t hosts.txt --continuous --keywords "palo alto" "microsoft exchange"
  
  # Continuous monitoring (check every hour)
  python payloadZer0.py -t hosts.txt --continuous --interval 3600
  
  # Continuous with Teams notifications and keyword filtering
  python payloadZer0.py -t hosts.txt --continuous --teams-webhook "https://..." --keywords cisco vmware
  
  # Disable specific notifications
  python payloadZer0.py -t hosts.txt --continuous --no-notify-findings
        """
    )
    
    parser.add_argument('-t', '--targets', required=True, help='File containing target hosts (one per line)')
    parser.add_argument('--continuous', action='store_true', help='Run in continuous monitoring mode')
    parser.add_argument('--interval', type=int, default=3600, help='Check interval in seconds (default: 3600)')
    parser.add_argument('--force-scan', action='store_true', help='Force scan of recent CVEs on startup')
    parser.add_argument('--scan-recent-days', type=int, default=30, help='Days of recent CVEs to scan (default: 30)')
    parser.add_argument('--output-dir', default='scan_results', help='Output directory for results')
    parser.add_argument('--database', default='kev_database.json', help='Path to KEV database file')
    parser.add_argument('--nuclei-path', default='nuclei', help='Path to nuclei binary')
    parser.add_argument('--templates-path', help='Custom nuclei templates path')
    parser.add_argument('--rate-limit', type=int, default=150, help='Nuclei rate limit (requests/sec)')
    parser.add_argument('--scan-timeout', type=int, default=10, help='Per-host timeout in seconds')
    parser.add_argument('--teams-webhook', help='Microsoft Teams webhook URL for notifications')
    parser.add_argument('--no-notify-new-cves', action='store_true', help='Disable new CVE notifications')
    parser.add_argument('--no-notify-findings', action='store_true', help='Disable findings notifications')
    parser.add_argument('--no-notify-scan-events', action='store_true', help='Disable scan start/end notifications')
    parser.add_argument('--no-auto-update', action='store_true', help='Disable automatic template updates')
    parser.add_argument('--verbose-scan', action='store_true', help='Show Nuclei scanning output (not silent mode)')
    parser.add_argument('--show-nuclei-output', action='store_true', help='Display raw Nuclei output to console in real-time')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging (shows all template detection attempts)')
    parser.add_argument('--keywords', nargs='+', help='Filter CVEs by keywords (vendor/product names). Example: --keywords cisco "palo alto" fortinet')
    
    args = parser.parse_args()
    
    # Set debug level if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Validate targets file
    if not Path(args.targets).exists():
        logger.error(f"Targets file not found: {args.targets}")
        sys.exit(1)
    
    # Build configuration
    config = {
        'database_path': args.database,
        'output_dir': args.output_dir,
        'nuclei_path': args.nuclei_path,
        'templates_path': args.templates_path,
        'rate_limit': args.rate_limit,
        'scan_timeout': args.scan_timeout,
        'scan_recent_days': args.scan_recent_days,
        'teams_webhook': args.teams_webhook or os.getenv('TEAMS_WEBHOOK_URL'),
        'notify_new_cves': not args.no_notify_new_cves,
        'notify_findings': not args.no_notify_findings,
        'notify_scan_events': not args.no_notify_scan_events,
        'auto_update_templates': not args.no_auto_update,
        'verbose_scan': args.verbose_scan,
        'show_nuclei_output': args.show_nuclei_output
    }
    
    # Create scanner
    scanner = KEVThreatScanner(config)
    
    # Run based on mode
    if args.continuous:
        scanner.run_continuous(args.targets, args.interval, keywords=args.keywords)
    else:
        scanner.check_and_scan(args.targets, force_scan=args.force_scan, keywords=args.keywords)


if __name__ == "__main__":
    main()
