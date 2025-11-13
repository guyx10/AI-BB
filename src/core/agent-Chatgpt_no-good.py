#!/usr/bin/env python3
"""
Combined Autonomous Pentest Agent (complete)
- Merges original agent and CIDR/network additions
- Includes complete implementations for the previously-missing methods
- Uses simple, robust fallbacks if external modules/tools are not present
"""

import asyncio
import yaml
import json
import os
import re
import sys
import ipaddress
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

# Add the parent directory to path to fix imports (keeps original structure)
sys.path.insert(0, str(Path(__file__).parent.parent))

class AutonomousPentestAgent:
    def __init__(self, config_path: str = None, debug: bool = False, max_workers: int = 5):
        self.config = self.load_config(config_path) if config_path else {}
        self.discovered_targets: List[str] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.scan_name = ""
        self.debug = debug
        self.max_workers = max_workers
        self.scan_data_dir: Path = Path("scan_data")
        self._init_placeholders_run = False

        self._initialize_tools()
        print("🤖 Autonomous Pentest Agent with AI & Network Scanning Initialized")
        if debug:
            print("🔍 DEBUG MODE ENABLED - Detailed logging active")
            print(f"🔧 Parallel workers: {max_workers}")

    def _initialize_tools(self):
        """
        Try to import real tool modules. If unavailable, create minimal stub implementations.
        Stubs return empty responses but let the control flow run.
        """
        try:
            from tools.reconnaissance import ReconnaissanceEngine
            from tools.vulnerability_scanner import VulnerabilityScanner
            from tools.advanced_orchestrator import AdvancedOrchestrator
            from ai.ai_strategist import AIStrategist

            self.recon_engine = ReconnaissanceEngine()
            self.vuln_scanner = VulnerabilityScanner()
            self.advanced_orchestrator = AdvancedOrchestrator()
            self.ai_strategist = AIStrategist(self.config)

            # If the imported classes exist, we assume a real environment
            if self.debug:
                print("✅ Connected to real 'tools' and 'ai' modules.")
        except Exception as e:
            if self.debug:
                print(f"⚠️ Tool import failed or not present: {e} — using lightweight stubs")

            # Minimal stub classes
            class ReconnaissanceEngineStub:
                async def run_subfinder(self, target): return []
                async def run_amass(self, target): return []
                async def run_httpx(self, targets): return targets
                async def run_waybackurls(self, target): return []
                async def run_katana(self, target): return []
                async def run_nuclei(self, target): return []
                async def run_nmap_services(self, host, ports): return {}
            class VulnerabilityScannerStub:
                async def run_custom_tests(self, target): return []
            class AdvancedOrchestratorStub:
                def get_available_tools(self): return ['nmap', 'sslscan', 'enum4linux', 'smbclient', 'sqlmap', 'nuclei', 'ffuf', 'gobuster', 'dirb', 'nikto', 'whatweb', 'wapiti', 'skipfish', 'nc', 'ftp']
                async def run_ssl_scan(self, host): return {}
                async def run_smb_scan(self, host): return {}
            class AIStrategistStub:
                def __init__(self, cfg): pass
                async def analyze_scan_results(self, data): 
                    return {'risk_assessment': 'medium', 'immediate_actions': [], 'priority_targets': []}
                async def generate_executive_summary(self, data):
                    return {
                        'executive_summary': 'Placeholder summary (no AI modules loaded).',
                        'overall_risk': 'Medium',
                        'key_findings': [],
                        'recommendations': []
                    }

            self.recon_engine = ReconnaissanceEngineStub()
            self.vuln_scanner = VulnerabilityScannerStub()
            self.advanced_orchestrator = AdvancedOrchestratorStub()
            self.ai_strategist = AIStrategistStub(self.config)

    def load_config(self, config_path: str) -> Dict:
        """Load YAML configuration if provided"""
        try:
            with open(config_path, 'r') as f:
                cfg = yaml.safe_load(f) or {}
                print("✅ Configuration loaded successfully")
                return cfg
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            return {}

    def sanitize_filename(self, name: str) -> str:
        """Sanitize a string to be used as a filename/directory"""
        clean = re.sub(r'^https?://', '', name)
        clean = re.sub(r'[^a-zA-Z0-9\._-]', '_', clean)
        return clean[:120]

    # ------------------------------
    # High-level web assessment methods (full implementations)
    # ------------------------------
    async def run_full_assessment(self, target: str):
        """Run the full AI-powered web assessment for a URL/host."""
        # make sure target is a clean URL (if user passed host without scheme, add http://)
        if not re.match(r'^https?://', target):
            target = f"http://{target}"

        self.scan_name = self.sanitize_filename(target)
        self.scan_data_dir = Path("scan_data") / self.scan_name
        self.scan_data_dir.mkdir(parents=True, exist_ok=True)

        print(f"🎯 Starting AI-powered assessment of: {target}")
        print(f"📁 Scan name: {self.scan_name}")
        print(f"💾 Data directory: {self.scan_data_dir}")
        print("-" * 40)

        available_tools = self.advanced_orchestrator.get_available_tools()
        print(f"🔧 Available tools: {', '.join(available_tools)}")

        # 1. Recon
        recon_results = await self.conduct_enhanced_reconnaissance(target)

        # 2. Service-specific scans
        services_results = await self.run_service_specific_scans(target, recon_results)

        # 3. AI analysis of targets
        ai_analysis = await self.analyze_targets_with_ai(recon_results)

        # 4. AI-guided vulnerability scans
        await self.run_ai_guided_vulnerability_scans(ai_analysis)

        # 5. Generate report
        await self.generate_ai_enhanced_report(recon_results, services_results, ai_analysis)

        # Print a compact summary
        print(f"\n✅ AI-Powered web assessment complete! Found {len(self.vulnerabilities)} issues (may be placeholders).")

    async def conduct_enhanced_reconnaissance(self, target: str) -> Dict:
        """
        Enhanced reconnaissance stage for a web target.
        Uses recon_engine stub/real to run subdomain enumeration, HTTP probing, wayback, etc.
        Returns a dict with discovered hosts/urls.
        """
        print("🔍 Conducting enhanced reconnaissance...")
        results = {
            'target': target,
            'subdomains': [],
            'live_hosts': [],
            'wayback_urls': [],
            'httpx': [],
        }

        try:
            # Subdomain discovery (may be heavy)
            subfinder = await self.recon_engine.run_subfinder(target)
            amass = await self.recon_engine.run_amass(target)
            wayback = await self.recon_engine.run_waybackurls(target)

            # combine and dedupe
            subs = []
            for x in (subfinder or []):
                subs.append(x)
            for x in (amass or []):
                subs.append(x)
            results['subdomains'] = list(dict.fromkeys(subs))

            # HTTP probing
            httpx_targets = results['subdomains'] if results['subdomains'] else [target]
            httpx_out = await self.recon_engine.run_httpx(httpx_targets)
            results['httpx'] = httpx_out or []
            results['live_hosts'] = httpx_out or []

            results['wayback_urls'] = wayback or []

            # Save recon results
            out_file = self.scan_data_dir / "recon.json"
            with open(out_file, 'w') as f:
                json.dump(results, f, indent=2)

            print(f"   ✅ Recon complete — subdomains: {len(results['subdomains'])}, live: {len(results['live_hosts'])}")
        except Exception as e:
            if self.debug:
                print(f"   ❌ Recon error: {e}")

        return results

    async def run_service_specific_scans(self, target: str, recon_results: Dict) -> Dict:
        """
        Run service-specific scans (webapp scanners, header checks, SSL checks, directories).
        Returns a dict summarizing service scan outputs.
        """
        print("🛠️ Running service-specific scans...")
        summary = {'target': target, 'services': {}, 'web_findings': []}
        hosts = recon_results.get('live_hosts') or [target]

        # simple HTTP checks on each host
        for host in hosts:
            # If host contains scheme, extract host; else assume full host
            host_stripped = re.sub(r'^https?://', '', host).split('/')[0]
            # Run nmap basic service detection for ports 80/443
            cmd = f"nmap -sV -p 80,443 {host_stripped}"
            try:
                proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await proc.communicate()
                out = stdout.decode() if stdout else ""
                parsed = self._parse_nmap_services(out)
                summary['services'][host_stripped] = parsed
            except Exception as e:
                if self.debug:
                    print(f"   ❌ Service scan failed for {host}: {e}")

        # Save service results
        out_file = self.scan_data_dir / "services.json"
        with open(out_file, 'w') as f:
            json.dump(summary, f, indent=2)
        return summary

    async def analyze_targets_with_ai(self, recon_results: Dict) -> Dict:
        """
        Use (optional) AI strategist to analyze recon output and prioritize targets.
        Falls back to simple heuristics if AI is not available.
        """
        print("🧠 Analyzing targets with AI (or fallback heuristics)...")
        try:
            analysis = await self.ai_strategist.analyze_scan_results(recon_results)
            if not analysis:
                raise RuntimeError("Empty AI analysis")
            print("   ✅ AI analysis complete.")
        except Exception as e:
            if self.debug:
                print(f"   ⚠️ AI analysis failed or not present: {e} — using fallback analysis.")
            # Fallback simple analysis
            analysis = {
                'priority_targets': recon_results.get('httpx', [])[:10],
                'risk_assessment': 'medium',
                'suggested_actions': []
            }
        # Save analysis
        out_file = self.scan_data_dir / "ai_analysis.json"
        with open(out_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        return analysis

    async def run_ai_guided_vulnerability_scans(self, analysis: Dict):
        """
        Run vulnerability scans driven by AI analysis or heuristics.
        This coordinates custom tests and nuclei/dirb calls (placeholders if missing).
        """
        print("⚡ Running AI-guided vulnerability scans...")
        targets = analysis.get('priority_targets', [])
        findings = []

        for t in targets:
            # call vuln_scanner (may be stub)
            try:
                res = await self.vuln_scanner.run_custom_tests({'url': t})
                if res:
                    findings.extend(res)
            except Exception as e:
                if self.debug:
                    print(f"   ❌ vuln_scanner error for {t}: {e}")

            # Try to run nuclei via recon_engine.run_nuclei or the orchestrator if available
            try:
                nuclei_out = await self.recon_engine.run_nuclei(t)
                if nuclei_out:
                    findings.extend(nuclei_out)
            except Exception:
                # ignore, placeholder may not exist
                pass

        # Save findings
        self.vulnerabilities = findings
        out_file = self.scan_data_dir / "vulnerabilities.json"
        with open(out_file, 'w') as f:
            json.dump(findings, f, indent=2)

        print(f"   ✅ Vulnerability scanning stage complete — findings: {len(findings)}.")

    async def generate_ai_enhanced_report(self, recon_results: Dict, services_results: Dict, ai_analysis: Dict):
        """
        Combine recollected data and create an executive summary + JSON report.
        """
        print("📊 Generating AI-enhanced report...")
        report = {
            'meta': {
                'scan_name': self.scan_name,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            },
            'recon': recon_results,
            'services': services_results,
            'ai_analysis': ai_analysis,
            'vulnerabilities': self.vulnerabilities
        }

        # Try to generate an executive summary with AI strategist (if available)
        try:
            exec_summary = await self.ai_strategist.generate_executive_summary(report)
            report['executive_summary'] = exec_summary
        except Exception as e:
            if self.debug:
                print(f"   ⚠️ Executive summary generation failed: {e}")
            report['executive_summary'] = {
                'summary': 'No AI executive summary available (fallback).'
            }

        # Save report
        reports_dir = Path("reports") / self.scan_name
        reports_dir.mkdir(parents=True, exist_ok=True)
        out_path = reports_dir / f"report_{self.scan_name}.json"
        with open(out_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"   📁 Report saved to: {out_path}")

    # ------------------------------
    # Network / CIDR scanning additions (complete)
    # ------------------------------
    async def run_network_assessment(self, cidr_range: str):
        """Run network assessment; choose external vs internal automatically."""
        # confirm cidr sanity
        try:
            net = ipaddress.ip_network(cidr_range, strict=False)
        except Exception:
            print(f"❌ Invalid CIDR provided: {cidr_range}")
            return

        self.scan_name = self.sanitize_filename(cidr_range)
        self.scan_data_dir = Path("scan_data") / self.scan_name
        self.scan_data_dir.mkdir(parents=True, exist_ok=True)

        is_external = self._is_likely_external_range(cidr_range)
        scan_type = "external" if is_external else "internal"
        print(f"🌐 Starting network assessment of: {cidr_range} ({scan_type})")
        print(f"📁 Scan name: {self.scan_name}")
        print("-" * 40)

        if is_external:
            await self._run_external_network_scan(cidr_range)
        else:
            await self._run_internal_network_scan(cidr_range)

    def _is_likely_external_range(self, cidr_range: str) -> bool:
        """Return True if CIDR looks external (not in RFC1918 ranges)"""
        try:
            net = ipaddress.ip_network(cidr_range, strict=False)
            # RFC1918 internal spaces
            internal_nets = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('169.254.0.0/16')  # link-local
            ]
            for i in internal_nets:
                if net.subnet_of(i):
                    return False
            return True
        except Exception:
            return True

    async def _run_external_network_scan(self, cidr_range: str):
        """Stealthy external scanning pipeline"""
        print("   🛡️  Using EXTERNAL scanning strategy (stealthy, web-focused)")
        discovery = await self.conduct_external_host_discovery(cidr_range)
        services = await self.enumerate_external_services(discovery)
        vulns = await self.scan_external_web_applications(services)
        await self.generate_external_network_report({'discovery': discovery, 'services': services, 'vulnerabilities': vulns})

    async def _run_internal_network_scan(self, cidr_range: str):
        """Comprehensive internal scanning pipeline"""
        print("   🏠 Using INTERNAL scanning strategy (comprehensive, intrusive)")
        discovery = await self.conduct_internal_host_discovery(cidr_range)
        services = await self.enumerate_internal_services(discovery)
        vulns = await self.scan_internal_vulnerabilities(services)
        await self.generate_internal_network_report({'discovery': discovery, 'services': services, 'vulnerabilities': vulns})

    async def conduct_external_host_discovery(self, cidr_range: str) -> Dict:
        """Use nmap ping scan with low timing for stealthy discovery"""
        print(f"   🔍 Performing stealthy host discovery on {cidr_range} ...")
        cmd = f"nmap -T2 -sn {cidr_range} -oG -"
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            out = stdout.decode() if stdout else ""
            hosts = self._parse_nmap_live_hosts(out)
            await self._save_targets_to_file(hosts, "external_live_hosts.txt")
            print(f"   ✅ Found {len(hosts)} live external hosts")
            return {'cidr_range': cidr_range, 'live_hosts': hosts}
        except Exception as e:
            if self.debug:
                print(f"   ❌ External host discovery failed: {e}")
            return {'cidr_range': cidr_range, 'live_hosts': []}

    async def conduct_internal_host_discovery(self, cidr_range: str) -> Dict:
        """Use faster scanning for internal networks"""
        print(f"   🔍 Performing comprehensive host discovery on {cidr_range} ...")
        cmd = f"nmap -T4 -sn {cidr_range} -oG -"
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            out = stdout.decode() if stdout else ""
            hosts = self._parse_nmap_live_hosts(out)
            await self._save_targets_to_file(hosts, "internal_live_hosts.txt")
            print(f"   ✅ Found {len(hosts)} live internal hosts")
            return {'cidr_range': cidr_range, 'live_hosts': hosts}
        except Exception as e:
            if self.debug:
                print(f"   ❌ Internal host discovery failed: {e}")
            return {'cidr_range': cidr_range, 'live_hosts': []}

    async def enumerate_external_services(self, discovery_data: Dict) -> Dict:
        """Perform service detection on likely external ports (stealthy selection)"""
        hosts = discovery_data.get('live_hosts', [])
        if not hosts:
            return {'services': {}}
        print(f"   🌐 Enumerating external services on {len(hosts)} hosts...")
        services = {}
        # common external ports list
        external_ports = "21,22,25,53,80,110,143,443,465,587,993,995,2082,2083,2086,2087,2095,2096,8080,8443"
        for host in hosts:
            print(f"      📡 Scanning {host} (external ports)...")
            cmd = f"nmap -T2 -sV -p {external_ports} {host}"
            try:
                proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await proc.communicate()
                out = stdout.decode() if stdout else ""
                services[host] = self._parse_nmap_services(out)
            except Exception as e:
                if self.debug:
                    print(f"         ❌ nmap service scan failed for {host}: {e}")
        services_file = self.scan_data_dir / "external_services.json"
        with open(services_file, 'w') as f:
            json.dump(services, f, indent=2)
        return {'services': services}

    async def enumerate_internal_services(self, discovery_data: Dict) -> Dict:
        """Comprehensive port scanning on internal hosts"""
        hosts = discovery_data.get('live_hosts', [])
        if not hosts:
            return {'services': {}}
        print(f"   🛠️  Enumerating internal services on {len(hosts)} hosts...")
        services = {}
        for host in hosts:
            print(f"      🔧 Scanning top ports on {host}...")
            cmd = f"nmap -T4 -sV --top-ports 1000 {host}"
            try:
                proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await proc.communicate()
                out = stdout.decode() if stdout else ""
                services[host] = self._parse_nmap_services(out)
            except Exception as e:
                if self.debug:
                    print(f"         ❌ internal nmap failed for {host}: {e}")
        services_file = self.scan_data_dir / "internal_services.json"
        with open(services_file, 'w') as f:
            json.dump(services, f, indent=2)
        return {'services': services}

    async def scan_external_web_applications(self, services_data: Dict) -> Dict:
        """Scan web services discovered in external enumeration."""
        services = services_data.get('services', {})
        vulnerabilities = []
        print(f"   🕸️  Scanning external web applications...")
        for host, host_services in services.items():
            print(f"      🌐 Host: {host} — checking for web ports")
            web_targets = await self._convert_services_to_web_targets(host, host_services)
            for wt in web_targets:
                print(f"         🔍 Scanning {wt}")
                # minimal checks: run nuclei via recon_engine (may be a stub)
                try:
                    out = await self.recon_engine.run_nuclei(wt)
                    if out:
                        vulnerabilities.extend(out)
                except Exception:
                    pass
                # run SSL/TLS checks for https
                if wt.startswith('https://'):
                    ssl_find = await self._check_ssl_vulnerabilities(wt)
                    if ssl_find:
                        vulnerabilities.extend(ssl_find)
        self.vulnerabilities = vulnerabilities
        print(f"   ✅ External web scanning done — vulns: {len(vulnerabilities)}")
        return {'vulnerabilities': vulnerabilities}

    async def scan_internal_vulnerabilities(self, services_data: Dict) -> Dict:
        """Basic internal vulnerability scanning (quick checks)."""
        services = services_data.get('services', {})
        findings = []
        for host, host_services in services.items():
            # detect SMB-like ports
            if any(k.startswith('445') or k.startswith('139') for k in host_services.keys()):
                findings.append({
                    'type': 'SMB Service Detected',
                    'host': host,
                    'severity': 'medium',
                    'evidence': 'SMB service open on internal host'
                })
        self.vulnerabilities = findings
        print(f"   ✅ Internal vuln scan produced {len(findings)} findings")
        return {'vulnerabilities': findings}

    # ------------------------------
    # External/Internal report generation helpers
    # ------------------------------
    async def generate_external_network_report(self, results: Dict):
        target_dir = Path("reports") / self.scan_name
        target_dir.mkdir(parents=True, exist_ok=True)
        out_path = target_dir / f"external_network_report_{self.scan_name}.json"
        with open(out_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"   📁 External network report saved to: {out_path}")

    async def generate_internal_network_report(self, results: Dict):
        target_dir = Path("reports") / self.scan_name
        target_dir.mkdir(parents=True, exist_ok=True)
        out_path = target_dir / f"internal_network_report_{self.scan_name}.json"
        with open(out_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"   📁 Internal network report saved to: {out_path}")

    # ------------------------------
    # Utility parsers & helpers
    # ------------------------------
    def _parse_nmap_live_hosts(self, grep_output: str) -> List[str]:
        """
        Parse nmap -oG grepable output lines that look like:
        Host: 192.0.2.1 ()  Status: Up
        """
        hosts = []
        for line in grep_output.splitlines():
            line = line.strip()
            if line.startswith("Host:"):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    # basic IP check
                    try:
                        ipaddress.ip_address(ip)
                        hosts.append(ip)
                    except Exception:
                        continue
        # dedupe while keeping order
        return list(dict.fromkeys(hosts))

    def _parse_nmap_services(self, nmap_output: str) -> Dict[str, Dict[str, str]]:
        """
        Parse nmap textual output for lines such as:
        80/tcp open  http Apache httpd 2.4.29
        Returns a mapping 'port/proto' -> {service, state, raw}
        """
        services = {}
        for line in nmap_output.splitlines():
            line = line.strip()
            m = re.match(r'^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$', line)
            if m:
                port = m.group(1)
                proto = m.group(2)
                state = m.group(3)
                svc = m.group(4)
                raw = m.group(5) or ""
                services[f"{port}/{proto}"] = {'service': svc, 'state': state, 'raw': raw}
        return services

    async def _convert_services_to_web_targets(self, host: str, services: Dict) -> List[str]:
        """Turn service map into possible http(s) URLs using heuristics."""
        targets = []
        for port_proto, info in services.items():
            port = int(port_proto.split('/')[0])
            svc = info.get('service', '')
            if port == 80:
                targets.append(f"http://{host}")
            elif port == 443:
                targets.append(f"https://{host}")
            elif port in (8080, 8000, 8888, 8443):
                scheme = 'https' if port == 8443 else 'http'
                targets.append(f"{scheme}://{host}:{port}")
            elif 'http' in svc.lower():
                targets.append(f"http://{host}:{port}")
        return list(dict.fromkeys(targets))

    async def _check_ssl_vulnerabilities(self, url: str) -> List[Dict]:
        """Basic SSL check via nmap scripts for ciphers/cert info."""
        try:
            host = re.sub(r'^https?://', '', url).split('/')[0]
            cmd = f"nmap -p 443 --script ssl-enum-ciphers,ssl-cert {host}"
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            out = stdout.decode() if stdout else ""
            if "weak" in out.lower() or "TLSv1.0" in out or "TLSv1.1" in out:
                return [{
                    'type': 'SSL/TLS Weak Configuration',
                    'url': url,
                    'severity': 'medium',
                    'evidence': 'Weak ciphers/TLS detected via nmap'
                }]
        except Exception as e:
            if self.debug:
                print(f"   ❌ SSL check failed for {url}: {e}")
        return []

    async def _check_external_ssh(self, host: str) -> Dict:
        """Basic SSH presence check (banner via nmap)."""
        try:
            cmd = f"nmap -sV -p22 --script ssh-hostkey {host}"
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            out = stdout.decode() if stdout else ''
            if 'ssh' in out.lower():
                return {
                    'type': 'Open SSH Service',
                    'host': host,
                    'severity': 'low',
                    'evidence': 'SSH detected on external host'
                }
        except Exception as e:
            if self.debug:
                print(f"   ❌ SSH check failed for {host}: {e}")
        return None

    async def _save_targets_to_file(self, targets: List[str], filename: str) -> Path:
        """Persist a simple list of targets into the scan_data dir and return the path."""
        self.scan_data_dir.mkdir(parents=True, exist_ok=True)
        file_path = self.scan_data_dir / filename
        with open(file_path, 'w') as f:
            for t in targets:
                f.write(f"{t}\n")
        return file_path

    async def _load_targets_from_file(self, filename: str) -> List[str]:
        file_path = self.scan_data_dir / filename
        if file_path.exists():
            with open(file_path, 'r') as f:
                return [l.strip() for l in f.readlines() if l.strip()]
        return []

    # ------------------------------
    # Run / Input Helpers
    # ------------------------------
    def _looks_like_cidr(self, s: str) -> bool:
        """Return True if string is a recognizable CIDR (like 10.0.0.0/8 or 192.0.2.0/24)"""
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except Exception:
            return False

    async def run_from_input(self, input_target: str):
        """
        Decide whether input_target is CIDR (network) or host/URL (web).
        Handles cases where a parent orchestrator prepends http:// to a CIDR.
        """
        import re
        import ipaddress
    
        # Normalize input
        normalized = input_target.strip().strip('"').strip("'")
    
        # Strip any accidental scheme prefixes
        normalized = re.sub(r'^https?://', '', normalized, flags=re.IGNORECASE)
    
        # --- Forced CIDR detection ---
        is_cidr = False
        try:
            ipaddress.ip_network(normalized, strict=False)
            is_cidr = True
        except Exception:
            # Fallback regex match (handles odd formats)
            if re.search(r'\d+\.\d+\.\d+\.\d+/\d+', normalized):
                is_cidr = True
    
        if is_cidr:
            print(f"🌐 Detected CIDR or network range input: {normalized}")
            await self.run_network_assessment(normalized)
        else:
            print(f"🌍 Detected web/host input: {normalized}")
            await self.run_full_assessment(normalized)



# ------------------------------
# CLI Entrypoint
# ------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Autonomous Pentest Agent (combined web + network scanning)")
    parser.add_argument('target', help="Target URL, host, or CIDR range (e.g. https://example.com or 93.184.216.0/24)")
    parser.add_argument('--config', '-c', help="Path to YAML config", default=None)
    parser.add_argument('--debug', '-d', action='store_true', help="Enable debug output")
    parser.add_argument('--workers', '-w', type=int, default=5, help="Parallel worker count")
    args = parser.parse_args()

    agent = AutonomousPentestAgent(config_path=args.config, debug=args.debug, max_workers=args.workers)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(agent.run_from_input(args.target))
    except KeyboardInterrupt:
        print("\n✋ Interrupted by user")
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()

if __name__ == "__main__":
    main()
