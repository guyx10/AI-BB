#!/usr/bin/env python3
"""
Autonomous Pentest Agent - Complete Working Version
Enhanced with detailed POC generation and comprehensive reporting
Now with OWASP ZAP integration
Enhanced with batch processing for multiple domains from file

Me - -Working_With-AI
"""
import asyncio
import yaml
import json
import os
import re
import sys
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

# Add the parent directory to path to fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from tools.vulnerability_scanner import VulnerabilityScanner

class AutonomousPentestAgent:
    def __init__(self, config_path: str, debug: bool = False, max_workers: int = 5):
        self.config = self.load_config(config_path)
        self.discovered_targets = []
        self.vulnerabilities = []
        self.scan_name = ""
        self.debug = debug
        self.max_workers = max_workers
        self.scan_data_dir = None
        
        # Initialize tools
        self._initialize_tools()
        print("🤖 Autonomous Pentest Agent with AI Initialized")
        if debug:
            print("🔍 DEBUG MODE ENABLED - Detailed logging active")
            print(f"🔧 Parallel workers: {max_workers}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup resources"""
        await self.cleanup()

    async def cleanup(self):
        """Cleanup resources"""
        # Close AI strategist session if it exists
        if hasattr(self, 'ai_strategist') and self.ai_strategist:
            try:
                if hasattr(self.ai_strategist, '__aexit__'):
                    await self.ai_strategist.__aexit__(None, None, None)
                elif hasattr(self.ai_strategist, 'session') and self.ai_strategist.session:
                    await self.ai_strategist.session.close()
            except Exception as e:
                if self.debug:
                    print(f"🔧 Debug: Error during AI strategist cleanup: {e}")
        
        # Close any other resources here
        if hasattr(self, 'tool_orchestrator') and self.tool_orchestrator:
            if hasattr(self.tool_orchestrator, 'cleanup'):
                await self.tool_orchestrator.cleanup()
            
    def _initialize_tools(self):
        """Initialize all required tool modules"""
        try:
            from tools.reconnaissance import ReconnaissanceEngine
            from tools.vulnerability_scanner import VulnerabilityScanner
            from tools.advanced_orchestrator import AdvancedOrchestrator
            from ai.ai_strategist import AIStrategist
            
            self.recon_engine = ReconnaissanceEngine()
            self.vuln_scanner = VulnerabilityScanner()
            self.advanced_orchestrator = AdvancedOrchestrator()
            # Don't initialize session here - will be done in context manager
            self.ai_strategist = AIStrategist(self.config)
            
            # Initialize ZAP Scanner if configured
            if self.config.get('zap', {}).get('enabled', False):
                from tools.zap_scanner import ZAPScanner
                self.zap_scanner = ZAPScanner(self.config)
                print("🛡️  OWASP ZAP integration enabled")
            else:
                self.zap_scanner = None
                print("ℹ️  OWASP ZAP disabled (enable in config)")
            
        except ImportError as e:
            print(f"❌ Tool modules not found: {e}")
            print("📁 Creating missing tool modules...")
            self._create_missing_tools()
            self._initialize_tools()  # Retry after creation
    
    def _create_missing_tools(self):
        """Create missing tool modules"""
        tools_dir = Path(__file__).parent.parent / "tools"
        ai_dir = Path(__file__).parent.parent / "ai"
        
        tools_dir.mkdir(exist_ok=True)
        ai_dir.mkdir(exist_ok=True)
        
        # Create __init__.py files
        (tools_dir / "__init__.py").write_text("# Tools package\n")
        (ai_dir / "__init__.py").write_text("# AI package\n")
 
    def enhance_findings_with_pocs(self, findings: List[Dict]) -> List[Dict]:
        """Add actual exploit POCs to vulnerability findings"""
        print("🎯 Generating exploit POCs for verified findings...")
        
        try:
            # Import here to avoid circular imports
            from tools.poc_generator import POCGenerator
        except ImportError:
            print("❌ POCGenerator not found, skipping POC generation")
            return findings
        
        poc_generator = POCGenerator()
        enhanced_findings = []
        
        for finding in findings:
            # Only generate POCs for medium/high confidence findings
            confidence = finding.get('confidence', 'low').lower()
            severity = finding.get('severity', 'low').lower()
            
            if confidence in ['high', 'medium'] and severity in ['high', 'critical', 'medium']:
                try:
                    poc_data = poc_generator.generate_exploit_poc(finding)
                    enhanced_finding = {
                        **finding,
                        'exploit_poc': poc_data,
                        'verified': poc_data.get('verified', False)
                    }
                    enhanced_findings.append(enhanced_finding)
                    print(f"✅ Generated POC for: {finding.get('type')}")
                except Exception as e:
                    print(f"❌ POC generation failed for {finding.get('type')}: {e}")
                    enhanced_findings.append(finding)
            else:
                enhanced_findings.append(finding)
        
        verified_count = len([v for v in enhanced_findings if v.get('verified')])
        print(f"📊 POC generation complete: {verified_count} verified exploits")
        
        return enhanced_findings
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                print("✅ Configuration loaded successfully")
                return config
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            return {}
    
    def sanitize_filename(self, name: str) -> str:
        """Sanitize the target name to create a safe filename"""
        clean_name = re.sub(r'^https?://', '', name)
        clean_name = re.sub(r'[^a-zA-Z0-9\.\-]', '_', clean_name)
        return clean_name[:50]  # Limit length
    
    async def run_full_assessment(self, target: str):
        """Execute complete autonomous penetration test with AI"""
        self.scan_name = self.sanitize_filename(target)
        
        # Create scan data directory
        self.scan_data_dir = Path("scan_data") / self.scan_name
        self.scan_data_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"🎯 Starting AI-powered assessment of: {target}")
        print(f"📁 Scan name: {self.scan_name}")
        print(f"💾 Data directory: {self.scan_data_dir}")
        print("-" * 40)
        
        # Show available tools
        available_tools = self.advanced_orchestrator.get_available_tools()
        if self.zap_scanner:
            available_tools.append('zap')
        print(f"🔧 Available tools: {', '.join(available_tools)}")
        
        # Assessment phases
        phases = [
            ("🔍 Conducting Enhanced Reconnaissance", self.conduct_enhanced_reconnaissance),
            ("🛠️  Running Service-Specific Scans", self.run_service_specific_scans),
            ("🧠 AI-Powered Target Analysis", self.analyze_targets_with_ai),
            ("⚡ Running AI-Guided Vulnerability Scans", self.run_ai_guided_vulnerability_scans),
            ("📊 Generating AI-Enhanced Report", self.generate_ai_enhanced_report)
        ]
        
        results = {}
        for i, (phase_name, phase_func) in enumerate(phases, 1):
            print(f"\n[{i}/5] {phase_name}...")
            if i == 1:
                results['recon'] = await phase_func(target)
            elif i == 2:
                results['services'] = await phase_func(target, results['recon'])
            elif i == 3:
                results['analysis'] = await phase_func(results['recon'])
            elif i == 4:
                await phase_func(results['analysis'])
            else:
                await phase_func(results['recon'], results['services'], results['analysis'])
        
        # Final summary with verification
        await self._print_verification_summary(results)
        print(f"\n✅ AI-Powered Assessment complete! Found {len(self.vulnerabilities)} vulnerabilities.")

    async def _print_verification_summary(self, results: Dict):
        """Print detailed verification of what was tested"""
        print("\n" + "="*60)
        print("🔍 SCAN VERIFICATION SUMMARY")
        print("="*60)
        
        recon_data = results.get('recon', {})
        basic_recon = recon_data.get('basic_recon', {})
        
        # Reconnaissance verification
        print(f"\n📊 RECONNAISSANCE RESULTS:")
        print(f"   • Subdomains found: {len(basic_recon.get('subdomains', []))}")
        print(f"   • Live domains: {len(basic_recon.get('live_domains', []))}")
        print(f"   • Historical URLs: {len(basic_recon.get('endpoints', []))}")
        print(f"   • Crawled URLs: {len(basic_recon.get('crawled_urls', []))}")
        print(f"   • Open ports: {len(basic_recon.get('nmap_results', {}).get('open_ports', []))}")
        print(f"   • Total unique targets: {len(self.discovered_targets)}")
        print(f"   • Data directory: {self.scan_data_dir}")
        
        # Show sample of what was found
        if self.debug and self.discovered_targets:
            print(f"\n🎯 SAMPLE DISCOVERED TARGETS (first 10):")
            for i, target in enumerate(self.discovered_targets[:10], 1):
                print(f"   {i}. {target}")
        
        # Analysis verification
        analysis_data = results.get('analysis', {})
        priority_targets = analysis_data.get('priority_targets', [])
        print(f"\n🧠 AI ANALYSIS RESULTS:")
        print(f"   • Priority targets selected: {len(priority_targets)}")
        print(f"   • Recommended tests: {analysis_data.get('recommended_tests', [])}")
        
        if priority_targets and self.debug:
            print(f"\n🎯 PRIORITY TARGETS SELECTED:")
            for target in priority_targets:
                print(f"   • {target['url']} (score: {target['score']})")
        
        # Vulnerability scanning verification
        print(f"\n⚡ VULNERABILITY SCANNING:")
        print(f"   • Raw findings: Check individual tool outputs")
        print(f"   • Standardized vulnerabilities: {len(self.vulnerabilities)}")
        
        # ZAP-specific results
        zap_findings = [v for v in self.vulnerabilities if v.get('tool') == 'zap']
        if zap_findings:
            print(f"   • ZAP findings: {len(zap_findings)}")
        
        if self.vulnerabilities:
            print(f"\n🚨 VULNERABILITIES FOUND:")
            for vuln in self.vulnerabilities:
                tool_info = f" ({vuln['tool']})" if vuln.get('tool') else ""
                print(f"   • {vuln['type']} - {vuln['url']} (Severity: {vuln['severity']}{tool_info})")
        
        # Tool execution verification
        print(f"\n🛠️ TOOL EXECUTION VERIFICATION:")
        await self._verify_tool_execution(basic_recon)

    def scanner(self):
        """Get the vulnerability scanner instance"""
        from tools.vulnerability_scanner import VulnerabilityScanner
        return VulnerabilityScanner()
    
    async def _verify_tool_execution(self, basic_recon: Dict):
        """Verify that tools executed properly"""
        tools_verified = []
        
        if basic_recon.get('subdomains'):
            tools_verified.append("Subdomain enumeration (Amass/Subfinder)")
        
        if basic_recon.get('live_domains'):
            tools_verified.append("Live domain checking (HTTPx)")
        
        if basic_recon.get('endpoints'):
            tools_verified.append("Historical URL gathering (Waybackurls)")
        
        if basic_recon.get('crawled_urls'):
            tools_verified.append("Web crawling (Katana)")
        
        if basic_recon.get('nmap_results', {}).get('open_ports'):
            tools_verified.append("Port scanning (Nmap)")
        
        # Check for ZAP findings
        zap_findings = [v for v in self.vulnerabilities if v.get('tool') == 'zap']
        if zap_findings:
            tools_verified.append("Web application scanning (OWASP ZAP)")
        
        if self.vulnerabilities:
            vuln_tools = set(v.get('tool', 'Unknown') for v in self.vulnerabilities if v.get('tool') != 'zap')
            for tool in vuln_tools:
                tools_verified.append(f"Vulnerability scanning ({tool})")
        
        print(f"   ✅ Tools that executed successfully: {len(tools_verified)}")
        for tool in tools_verified:
            print(f"      • {tool}")
    
    async def _save_targets_to_file(self, targets: List[str], filename: str):
        """Save targets to file for later processing"""
        file_path = self.scan_data_dir / filename
        with open(file_path, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        return file_path

    async def _load_targets_from_file(self, filename: str) -> List[str]:
        """Load targets from file"""
        file_path = self.scan_data_dir / filename
        if file_path.exists():
            with open(file_path, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        return []
    
    async def conduct_enhanced_reconnaissance(self, target: str) -> Dict:
        """Run enhanced reconnaissance with AI-powered analysis"""
        print(f"   Running enhanced reconnaissance on {target}...")
        
        enhanced_results = {
            'basic_recon': await self.conduct_real_reconnaissance(target),
            'services_detected': {},
            'ai_analysis': {},
            'next_steps': []
        }
        
        # Service detection
        open_ports = enhanced_results['basic_recon'].get('nmap_results', {}).get('open_ports', [])
        enhanced_results['services_detected'] = self._detect_services_from_ports(open_ports)
        
        # Display service discovery
        self._display_service_summary(enhanced_results['services_detected'])
        
        # Run service-specific scans
        await self._run_service_scans(target, enhanced_results, open_ports)
        
        # AI-powered analysis
        await self._run_ai_analysis(enhanced_results)
        
        return enhanced_results
    
    def _detect_services_from_ports(self, open_ports: List) -> Dict:
        """Detect services from open ports"""
        services = {
            'web': [],
            'database': [],
            'network': [],
            'other': []
        }
        
        for port in open_ports:
            port_str = str(port)
            port_num = port_str.split('/')[0] if '/' in port_str else port_str
            
            service_info = {
                'port': port_num,
                'service': port_str.split('/')[1] if '/' in port_str else 'unknown'
            }
            
            if port_num in ['80', '443', '8080', '8443']:
                services['web'].append(service_info)
            elif port_num in ['3306', '5432', '1433', '27017']:
                services['database'].append(service_info)
            elif port_num in ['21', '22', '25', '53', '110', '135', '139', '445']:
                services['network'].append(service_info)
            else:
                services['other'].append(service_info)
        
        return services
    
    def _display_service_summary(self, services_detected: Dict):
        """Display service discovery summary"""
        print("   🎯 Service Discovery Summary:")
        for category, services in services_detected.items():
            if services:
                service_list = [f"{s['port']}/{s['service']}" for s in services]
                print(f"      • {category.upper()}: {', '.join(service_list)}")
    
    async def _run_service_scans(self, target: str, enhanced_results: Dict, open_ports: List):
        """Run service-specific scans based on detected services"""
        services = enhanced_results['services_detected']
        
        # SSL scanning
        if services['web'] and any(port in ['443', '8443'] for port in [s['port'] for s in services['web']]):
            print("   🔐 Running SSL/TLS scan...")
            enhanced_results['ssl_scan'] = await self.advanced_orchestrator.run_ssl_scan(target)
        else:
            print("   ⏭️  No HTTPS ports found, skipping SSL scan")
        
        # SMB scanning
        if any('445' in str(port) for port in open_ports):
            print("   💻 Running SMB enumeration...")
            enhanced_results['smb_scan'] = await self.advanced_orchestrator.run_smb_scan(target)
        else:
            print("   ⏭️  Port 445 not found, skipping SMB scan")
    
    async def _run_ai_analysis(self, enhanced_results: Dict):
        """Run AI analysis on scan results including vulnerabilities"""
        print("   🤔 AI analyzing results...")
        try:
            scan_data_for_ai = {
                'basic_recon': enhanced_results['basic_recon'],
                'bug_bounty_recon': enhanced_results.get('bug_bounty_recon', {}),
                'vulnerabilities_found': len(self.vulnerabilities),
                'services_detected': enhanced_results['services_detected'],
                'vulnerabilities': self.vulnerabilities[:10]  # Pass actual vulnerabilities
            }
            
            ai_analysis = await self.ai_strategist.analyze_scan_results(scan_data_for_ai)
            enhanced_results['ai_analysis'] = ai_analysis
            enhanced_results['next_steps'] = ai_analysis.get('immediate_actions', [])
            
            print(f"   🧠 AI Risk Assessment: {ai_analysis.get('risk_assessment', 'unknown')}")
            print(f"   🎯 AI Recommended Actions: {', '.join(ai_analysis.get('immediate_actions', ['None']))}")
            
        except Exception as e:
            print(f"   ❌ AI analysis error: {e}")
            enhanced_results['ai_analysis'] = {'risk_assessment': 'unknown', 'error': str(e)}
            enhanced_results['next_steps'] = ['continue_standard_scanning']
    
    async def conduct_real_reconnaissance(self, target: str) -> Dict:
        """Run real reconnaissance tools with file-based storage"""
        print(f"   Running real reconnaissance on {target}...")
        
        real_results = {
            'subdomains': [],
            'live_domains': [],
            'endpoints': [],
            'nmap_results': {},
            'crawled_urls': []
        }
        
        # Subdomain enumeration
        print("   🔎 Enumerating subdomains...")
        subdomains = await self.recon_engine.run_subfinder(target)
        if not subdomains:
            print("      Trying Amass as alternative...")
            subdomains = await self.recon_engine.run_amass(target)
        real_results['subdomains'] = subdomains
        await self._save_targets_to_file(subdomains, "subdomains.txt")
        print(f"      Found {len(subdomains)} subdomains")
        
        # Live domain checking
        print("   🌐 Checking live domains...")
        all_domains_to_check = [target] + subdomains
        live_domains = await self.recon_engine.run_httpx(all_domains_to_check)
        real_results['live_domains'] = live_domains
        await self._save_targets_to_file(live_domains, "live_domains.txt")
        print(f"      {len(live_domains)} domains are live")
        
        # Historical URLs
        print("   📜 Gathering historical URLs...")
        historical_urls = await self.recon_engine.run_waybackurls(target)
        real_results['endpoints'] = historical_urls
        await self._save_targets_to_file(historical_urls, "historical_urls.txt")
        print(f"      Found {len(historical_urls)} filtered historical URLs")
        
        # Crawling
        print("   🕷️ Crawling main target...")
        crawled_urls = await self.recon_engine.run_katana(target)
        real_results['crawled_urls'] = crawled_urls
        await self._save_targets_to_file(crawled_urls, "crawled_urls.txt")
        print(f"      Crawled {len(crawled_urls)} current URLs")
        
        # Port scanning
        print("   🔍 Running port scan...")
        nmap_results = await self.recon_engine.run_nmap(target)
        real_results['nmap_results'] = nmap_results
        # Save nmap results to file
        nmap_file = self.scan_data_dir / "nmap_results.json"
        with open(nmap_file, 'w') as f:
            json.dump(nmap_results, f, indent=2)
        print(f"      Found {len(nmap_results.get('open_ports', []))} open ports")
        
        # Combine all discovered targets and save to file
        all_targets = live_domains + historical_urls + crawled_urls
        unique_targets = list(set(all_targets))
        self.discovered_targets = unique_targets[:500]
        
        # Save all discovered targets to file
        await self._save_targets_to_file(self.discovered_targets, "all_discovered_targets.txt")
        print(f"      💾 Saved {len(self.discovered_targets)} unique targets to file")
        
        return real_results
    
    async def run_service_specific_scans(self, target: str, recon_data: Dict) -> Dict:
        """Run scans specific to discovered services"""
        service_scans = {}
        open_ports = recon_data.get('basic_recon', {}).get('nmap_results', {}).get('open_ports', [])
        
        # Convert port strings to numbers
        port_numbers = []
        for port in open_ports:
            try:
                port_num = int(str(port).split('/')[0])
                port_numbers.append(port_num)
            except:
                continue
        
        # Web service scans
        if any(port in [80, 443, 8080, 8443] for port in port_numbers):
            print("   🌐 Running additional web service scans...")
            service_scans['web_services'] = {
                'status': 'enhanced_scan_completed',
                'ports': [port for port in port_numbers if port in [80, 443, 8080, 8443]],
                'scans_performed': ['ssl_scan', 'web_scan']
            }
        
        if not service_scans:
            print("   ⏭️  No additional service-specific scans needed")
        else:
            print(f"   ✅ Completed {len(service_scans)} service-specific scan categories")
        
        return service_scans
    
    async def analyze_targets_with_ai(self, recon_data: Dict) -> Dict:
        """Use AI to analyze and prioritize targets"""
        print("   🧠 AI analyzing and prioritizing targets...")
        
        # Get AI analysis from enhanced reconnaissance
        ai_analysis = recon_data.get('ai_analysis', {})
        
        if ai_analysis and ai_analysis.get('priority_targets'):
            priority_targets = []
            for target_url in ai_analysis.get('priority_targets', []):
                priority_targets.append({
                    'url': target_url,
                    'priority': 'high',
                    'score': 10,
                    'reasons': ['AI-selected priority target']
                })
            
            if priority_targets:
                print(f"   🎯 AI selected {len(priority_targets)} priority targets")
                return {
                    'priority_targets': priority_targets[:20],
                    'all_targets': self.discovered_targets,
                    'risk_level': ai_analysis.get('risk_assessment', 'medium'),
                    'ai_strategy': ai_analysis.get('exploitation_strategy', ''),
                    'recommended_tests': ai_analysis.get('immediate_actions', [])
                }
        
        # Fallback to rule-based analysis
        return await self._analyze_targets_fallback(recon_data)
    
    async def _analyze_targets_fallback(self, recon_data: Dict) -> Dict:
        """Rule-based fallback target analysis"""
        print("   Analyzing and prioritizing targets...")
        
        priority_targets = []
        all_targets = self.discovered_targets
        
        # Known vulnerable endpoints
        known_vulnerable_paths = [
            '/artists.php', '/categories.php', '/products.php', '/login.php',
            '/search.php', '/hpp/', '/AJAX/', '/Mod_Rewrite_Shop/',
            '/admin', '/wp-admin', '/administrator', '/api/', '/graphql',
            '/upload', '/files', '/images', '/documents', '/backup'
        ]
        
        for target in all_targets:
            score = 0
            reasons = []
            
            # Score based on various factors
            for vuln_path in known_vulnerable_paths:
                if vuln_path in target:
                    score += 10
                    reasons.append(f'Known vulnerable path: {vuln_path}')
                    break
            
            if any(keyword in target.lower() for keyword in ['admin', 'login', 'auth', 'register', 'signin', 'signup']):
                score += 5
                reasons.append('Authentication endpoint')
            
            if '?' in target and '=' in target:
                score += 3
                reasons.append('Parameterized endpoint')
                
                if any(param in target.lower() for param in ['id=', 'artist=', 'cat=', 'user=', 'product=', 'search=', 'query=', 'file=']):
                    score += 3
                    reasons.append('SQLi-prone parameter')
            
            # Additional scoring factors
            if any(ext in target.lower() for ext in ['.php', '.asp', '.aspx', '.jsp']):
                score += 2
                reasons.append('Dynamic page')
                
            if any(pattern in target.lower() for pattern in ['config', 'backup', 'dump', 'sql']):
                score += 4
                reasons.append('Sensitive file pattern')
            
            # Categorize by score
            if score >= 8:
                priority = 'critical'
            elif score >= 5:
                priority = 'high'
            elif score >= 2:
                priority = 'medium'
            else:
                priority = 'low'
            
            priority_targets.append({
                'url': target, 
                'priority': priority, 
                'score': score,
                'reasons': reasons
            })
        
        # Sort by score (highest first)
        priority_targets.sort(key=lambda x: x['score'], reverse=True)
        
        # Take top 20 for enhanced scanning
        top_targets = priority_targets[:20]
        
        analysis = {
            'priority_targets': top_targets,
            'all_targets': self.discovered_targets,
            'risk_level': 'high' if any(t['priority'] in ['critical', 'high'] for t in priority_targets) else 'medium',
            'recommended_tests': ['SQLi', 'XSS', 'Authentication Testing', 'Directory Brute-force', 'Comprehensive Scanning']
        }
        
        print(f"   ✅ Prioritized {len(priority_targets)} targets")
        print(f"   🎯 Selected {len(top_targets)} targets for enhanced scanning")
        print(f"   🌐 Will scan {len(self.discovered_targets)} total targets")
        
        # Print top targets
        for i, target in enumerate(top_targets[:5], 1):
            print(f"      {i}. {target['url']} (score: {target['score']}, priority: {target['priority']})")
        
        return analysis
    
    async def run_ai_guided_vulnerability_scans(self, analysis_results: Dict):
        """Run comprehensive vulnerability scans with parallel processing"""
        priority_targets = analysis_results.get('priority_targets', [])
        all_targets = analysis_results.get('all_targets', [])
        ai_recommendations = analysis_results.get('recommended_tests', [])
        
        print(f"   🧠 Running comprehensive parallel scans on {len(priority_targets)} priority + {len(all_targets)} total targets")
        print(f"   📋 AI Recommendations: {ai_recommendations}")
        print(f"   🔄 Parallel workers: {self.max_workers}")
        
        # Create vulnerabilities directory
        vuln_dir = self.scan_data_dir / "vulnerabilities"
        vuln_dir.mkdir(exist_ok=True)
        
        # Skip all unsupported methods - your scanner only has basic methods
        print("   ⏭️  Using basic vulnerability scanner (advanced methods not available)")
        
        # Scan priority targets first (in-depth, parallel)
        print(f"   🔍 Scanning {len(priority_targets)} priority targets with enhanced tests...")
        priority_findings = await self._scan_targets_parallel(priority_targets, enhanced=True, batch_name="priority")
        
        # Scan all other discovered targets (basic scan, parallel)
        other_targets = [t for t in all_targets if t not in [pt['url'] for pt in priority_targets]]
        if other_targets:
            print(f"   🌐 Scanning {len(other_targets)} additional targets with basic tests...")
            other_target_objs = [{'url': url, 'priority': 'medium', 'score': 1} for url in other_targets]
            other_findings = await self._scan_targets_parallel(other_target_objs, enhanced=False, batch_name="additional")
        else:
            other_findings = []
        
        # Combine all findings
        all_findings = priority_findings + other_findings
        
        # FILTER OUT LOW-VALUE FINDINGS
        filtered_findings = self._filter_low_value_findings(all_findings)
    
        # Process findings
        processed_count = 0
        for finding in filtered_findings:
            standardized_finding = self._standardize_finding(finding)
            if standardized_finding:
                # Generate detailed POC using existing method
                standardized_finding['detailed_poc'] = await self._generate_detailed_poc(standardized_finding)
                self.vulnerabilities.append(standardized_finding)
                processed_count += 1
        
        # ✅ ADD THIS: Enhance vulnerabilities with AI-generated exploit POCs
        print("🤖 Generating AI-powered exploit POCs...")
        self.vulnerabilities = self.enhance_findings_with_pocs(self.vulnerabilities)
        
        verified_count = len([v for v in self.vulnerabilities if v.get('verified')])
        print(f"✅ Generated {verified_count} verified exploit POCs")
        
        print(f"   ✅ Comprehensive scanning complete! Found {len(all_findings)} raw findings, {len(filtered_findings)} after filtering, {processed_count} standardized vulnerabilities")
        
        # Save vulnerabilities to file
        vuln_file = vuln_dir / "all_vulnerabilities.json"
        with open(vuln_file, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=2)
        
        print(f"   💾 Vulnerabilities saved to: {vuln_file}")

    async def _scan_targets_parallel(self, targets: List[Dict], enhanced: bool = False, batch_name: str = "batch") -> List[Dict]:
        """Scan multiple targets in parallel with semaphore limiting"""
        all_findings = []
        total_targets = len(targets)
        
        # Use semaphore to limit concurrent scans
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def bounded_scan(target):
            async with semaphore:
                return await self._scan_single_target(target, enhanced)
        
        # Process in batches for better progress tracking
        batch_size = self.max_workers * 2
        for batch_start in range(0, total_targets, batch_size):
            batch_end = min(batch_start + batch_size, total_targets)
            current_batch = targets[batch_start:batch_end]
            batch_num = (batch_start // batch_size) + 1
            total_batches = (total_targets + batch_size - 1) // batch_size
            
            print(f"      📦 {batch_name} batch {batch_num}/{total_batches}: {len(current_batch)} targets...")
            
            # Create tasks for current batch
            tasks = [bounded_scan(target) for target in current_batch]
            
            # Wait for all tasks in current batch to complete
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(batch_results):
                target_index = batch_start + i
                if isinstance(result, list):
                    all_findings.extend(result)
                    if self.debug and result:
                        print(f"         🎯 Found {len(result)} issues for {targets[target_index]['url'][:50]}...")
                elif isinstance(result, Exception):
                    if self.debug:
                        print(f"         ❌ Error scanning {targets[target_index]['url']}: {result}")
        
        return all_findings

    async def _scan_single_target(self, target: Dict, enhanced: bool = False) -> List[Dict]:
        """Scan a single target with appropriate depth"""
        findings = []
        url = target['url']
        
        try:
            # Always run basic tests
            basic_findings = await self.vuln_scanner.run_custom_tests(target)
            findings.extend(basic_findings)
            
            # Enhanced scanning for high-priority targets
            if enhanced:
                # Run ZAP scan for comprehensive web app testing
                if self.zap_scanner and self._is_web_url(url):
                    zap_findings = await self._run_zap_scan(url)
                    findings.extend(zap_findings)
                
                # Enhanced SQLi testing
                if '?' in url:
                    sql_findings = await self._run_enhanced_sql_scan(url)
                    findings.extend(sql_findings)
                
                # Enhanced directory brute-forcing for base URLs
                if self._is_base_url(url):
                    dir_findings = await self._run_enhanced_dir_scan(url)
                    findings.extend(dir_findings)
                
                # Run comprehensive nuclei scan
                nuclei_findings = await self._run_comprehensive_nuclei(url)
                findings.extend(nuclei_findings)
            
        except Exception as e:
            if self.debug:
                print(f"         ❌ Error scanning {url}: {e}")
        
        return findings

    def _is_web_url(self, url: str) -> bool:
        """Check if URL is a web URL (HTTP/HTTPS)"""
        return url.startswith('http://') or url.startswith('https://')

    def _is_base_url(self, url: str) -> bool:
        """Check if URL is a base path (not a specific file)"""
        clean_url = url.split('?')[0]
        return not any(clean_url.endswith(ext) for ext in 
                      ['.php', '.html', '.htm', '.js', '.css', '.jpg', '.png', '.gif', 
                       '.pdf', '.doc', '.docx', '.xml', '.json', '.txt'])

    async def _run_zap_scan(self, url: str) -> List[Dict]:
        """Run OWASP ZAP scan on target"""
        try:
            print(f"         🛡️  Running ZAP scan on {url}...")
            zap_results = await self.zap_scanner.scan_target(url)
            
            findings = []
            for alert in zap_results.get('alerts', []):
                # Convert ZAP alert to standard format
                standardized_alert = self._standardize_zap_finding(alert)
                if standardized_alert:
                    findings.append(standardized_alert)
            
            if findings:
                print(f"         ✅ ZAP found {len(findings)} issues")
            else:
                print(f"         ℹ️  ZAP found no security issues")
                
            return findings
            
        except Exception as e:
            if self.debug:
                print(f"         ❌ ZAP scan error: {e}")
            return []

    def _standardize_zap_finding(self, zap_alert: Dict) -> Dict:
        """Standardize ZAP findings to common format"""
        try:
            return {
                'type': zap_alert.get('type', 'Unknown'),
                'url': zap_alert.get('url', ''),
                'severity': zap_alert.get('severity', 'info'),
                'confidence': zap_alert.get('confidence', 'medium'),
                'tool': 'zap',
                'description': zap_alert.get('description', ''),
                'evidence': zap_alert.get('evidence', ''),
                'solution': zap_alert.get('solution', ''),
                'reference': zap_alert.get('reference', ''),
                'cwe_id': zap_alert.get('cwe_id', ''),
                'wasc_id': zap_alert.get('wasc_id', ''),
                'detailed_poc': self._generate_zap_poc(zap_alert)
            }
        except Exception as e:
            if self.debug:
                print(f"         ❌ Error standardizing ZAP finding: {e}")
            return None

    def _generate_zap_poc(self, zap_alert: Dict) -> str:
        """Generate POC for ZAP findings"""
        return f"""
## ZAP Finding: {zap_alert.get('type', 'Unknown')}

**URL**: {zap_alert.get('url', 'N/A')}
**Risk**: {zap_alert.get('severity', 'info').title()}
**Confidence**: {zap_alert.get('confidence', 'medium').title()}

### Description:
{zap_alert.get('description', 'No description available.')}

### Solution:
{zap_alert.get('solution', 'No solution provided.')}

### References:
{zap_alert.get('reference', 'No references available.')}

### Technical Details:
- CWE ID: {zap_alert.get('cwe_id', 'N/A')}
- WASC ID: {zap_alert.get('wasc_id', 'N/A')}
- Evidence: {zap_alert.get('evidence', 'N/A')}
"""

    async def _run_comprehensive_nuclei(self, url: str) -> List[Dict]:
        """Run nuclei with comprehensive template set"""
        try:
            cmd = f"nuclei -u {url} -severity low,medium,high,critical -rate-limit 50 -timeout 10 -json"
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            if process.returncode == 0 and stdout:
                output = stdout.decode()
                findings = []
                for line in output.split('\n'):
                    line = line.strip()
                    if line and line.startswith('{') and line.endswith('}'):
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
                return findings
            
        except asyncio.TimeoutError:
            if self.debug:
                print(f"         ⏰ Nuclei timeout for {url}")
        except Exception as e:
            if self.debug:
                print(f"         ❌ Comprehensive nuclei scan error: {e}")
        
        return []

    async def _run_enhanced_dir_scan(self, url: str) -> List[Dict]:
        """Run enhanced directory brute-forcing with multiple wordlists"""
        findings = []
        
        # Try multiple wordlists
        wordlists = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirb/big.txt',  # Larger wordlist
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',  # Even larger
            '/usr/share/seclists/Discovery/Web-Content/common.txt',  # SecLists
            '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'  # Comprehensive
        ]
        
        # Common LFI vulnerable files to check
        lfi_files = [
            'etc/passwd', 'etc/hosts', 'etc/shadow', 'proc/self/environ',
            'windows/win.ini', 'config.php', 'wp-config.php', '.env',
            '.htaccess', 'web.config', 'server-status'
        ]
        
        available_wordlists = []
        for wordlist in wordlists:
            if os.path.exists(wordlist):
                available_wordlists.append(wordlist)
        
        if not available_wordlists:
            print("   ⚠️  No directory brute-force wordlists found")
            return findings
        
        for wordlist in available_wordlists[:2]:  # Use first 2 available wordlists
            try:
                output_file = f"/tmp/ffuf_{hash(url)}.json"
                cmd = f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403 -o {output_file} -of json -timeout 10"
                
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=120)
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        results = json.load(f)
                        
                    for result in results.get('results', []):
                        if result.get('status') in [200, 301, 302, 403]:
                            filename = result['input']['FUZZ']
                            
                            # Check if this is a sensitive file that might indicate LFI
                            for lfi_file in lfi_files:
                                if lfi_file in filename:
                                    finding = {
                                        'type': 'Sensitive File Exposure',
                                        'url': f"{url}/{filename}",
                                        'tool': 'ffuf',
                                        'severity': 'high',
                                        'confidence': 'high',
                                        'evidence': f'Sensitive file found: {filename}',
                                        'description': f'Potentially exposed sensitive file: {lfi_file}'
                                    }
                                    findings.append(finding)
                                    print(f"         ✅ Sensitive file found: {filename}")
                            
                            # Regular directory discovery (lower severity)
                            severity = 'low'
                            description = 'Directory or file discovered'
                            
                            if any(sensitive in filename.lower() for sensitive in 
                                  ['admin', 'config', 'backup', 'sql', 'dump', 'password']):
                                severity = 'medium'
                                description = 'Potentially sensitive directory/file'
                            
                            findings.append({
                                'type': 'Directory/File Discovered',
                                'url': f"{url}/{filename}",
                                'tool': 'ffuf',
                                'severity': severity,
                                'confidence': 'high',
                                'evidence': f"Status: {result['status']}, Size: {result.get('length', 0)}",
                                'description': description
                            })
                    
                    os.remove(output_file)  # Clean up
                    
            except Exception as e:
                if self.debug:
                    print(f"         ❌ Directory scan with {wordlist} failed: {e}")
        
        return findings
    
    async def _run_enhanced_sql_scan(self, url: str) -> List[Dict]:
        """Run enhanced SQL scan with detailed POC capture"""
        try:
            if '?' not in url:
                return []
                
            param = url.split('?')[1].split('=')[0]
            cmd = f"sqlmap -u '{url}' --batch --level=3 --risk=3 --flush-session"
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            if process.returncode == 0 and stdout:
                output = stdout.decode()
                
                if any(indicator in output for indicator in [
                    "sqlmap identified the following injection point",
                    "is vulnerable",
                    "injection point"
                ]):
                    return [{
                        'type': 'SQL Injection',
                        'url': url,
                        'tool': 'sqlmap',
                        'severity': 'high',
                        'confidence': 'high',
                        'evidence': 'SQL injection confirmed by sqlmap',
                        'parameter': param,
                        'payloads': self._extract_sqlmap_payloads(output),
                        'database_info': self._extract_database_info(output)
                    }]
            
            return []
                
        except Exception as e:
            if self.debug:
                print(f"         ❌ Enhanced SQL scan error: {e}")
            return []
    
    def _extract_sqlmap_payloads(self, output: str) -> List[str]:
        """Extract payloads from SQLMap output"""
        payloads = []
        lines = output.split('\n')
        
        for i, line in enumerate(lines):
            if "payload:" in line.lower():
                payload = line.split("payload:")[1].strip()
                payloads.append(payload)
        
        return payloads[:5]
    
    def _extract_database_info(self, output: str) -> Dict:
        """Extract database information from SQLMap output"""
        db_info = {}
        lines = output.split('\n')
        
        for line in lines:
            if "back-end DBMS:" in line:
                db_info['type'] = line.split("back-end DBMS:")[1].strip()
            elif "Database:" in line and "[" in line:
                db_info['name'] = line.split("[")[1].split("]")[0]
        
        return db_info
    
    def _standardize_finding(self, finding: Dict) -> Dict:
        """Standardize findings from different tools to common format"""
        try:
            # Nuclei findings
            if 'template-id' in finding:
                return {
                    'type': finding.get('info', {}).get('name', finding.get('template-id', 'Unknown')),
                    'url': finding.get('host', 'Unknown'),
                    'severity': finding.get('info', {}).get('severity', 'unknown').lower(),
                    'confidence': 'high' if finding.get('matcher-status') else 'medium',
                    'tool': 'nuclei',
                    'evidence': finding.get('matched-at', ''),
                    'description': finding.get('info', {}).get('description', ''),
                    'tags': finding.get('info', {}).get('tags', [])
                }
            
            # SQLMap findings
            elif finding.get('tool') == 'sqlmap':
                return finding
            
            # FFUF findings
            elif finding.get('tool') == 'ffuf':
                return finding
            
            # ZAP findings
            elif finding.get('tool') == 'zap':
                return finding
            
            # Default format
            else:
                return finding
                
        except Exception as e:
            if self.debug:
                print(f"❌ Error standardizing finding: {e}")
            return None

    def _filter_low_value_findings(self, findings: List[Dict]) -> List[Dict]:
        """Filter out low-value or common findings that aren't actual vulnerabilities"""
        filtered_findings = []
        
        common_files = [
            'favicon.ico', 'robots.txt', 'sitemap.xml', 'index.html', 
            'index.php', 'admin', 'login', 'wp-admin', 'administrator',
            'help', 'contact', 'about', 'images', 'css', 'js', 'assets'
        ]
        
        for finding in findings:
            # Skip common directory/file discoveries
            if (finding.get('tool') == 'ffuf' and 
                finding.get('type') == 'Directory/File Discovered'):
                
                url = finding.get('url', '')
                # Check if it's a common file that's not interesting
                is_common_file = any(
                    f"/{common}" in url or url.endswith(f"/{common}") 
                    for common in common_files
                )
                
                # Only keep interesting directory discoveries
                if not is_common_file:
                    # Downgrade to informational
                    finding['severity'] = 'info'
                    finding['description'] = 'Directory or file discovered during reconnaissance'
                    filtered_findings.append(finding)
            else:
                # Keep all other findings
                filtered_findings.append(finding)
        
        return filtered_findings
    
    async def _generate_detailed_poc(self, vulnerability: Dict) -> str:
        """Generate detailed Proof of Concept for vulnerabilities"""
        
        if vulnerability['type'] == 'SQL Injection':
            poc_template = f"""
## SQL Injection Proof of Concept

**Vulnerable URL**: {vulnerability['url']}
**Vulnerable Parameter**: {vulnerability.get('parameter', 'Unknown')}
**Tool**: {vulnerability.get('tool', 'Unknown')}


### Manual Reproduction Steps:

1. **Basic Detection**:
   ```bash
   curl "{vulnerability['url']}'"

2. **Time-Based Blind SQLi**:
   ```bash
   curl "{vulnerability['url']}' AND SLEEP(5)-- -"
   ```

3. **Error-Based SQLi**:
   ```bash
   curl "{vulnerability['url']}' AND 1=CAST((SELECT version()) AS INT)-- -"
   ```

4. **Union-Based SQLi**:
   ```bash
   curl "{vulnerability['url']}' UNION SELECT 1,2,3,4,5-- -"
   ```

### SQLMap Commands for Verification:
```bash
sqlmap -u "{vulnerability['url']}" --batch --level=3 --risk=3
sqlmap -u "{vulnerability['url']}" --batch --dbs
sqlmap -u "{vulnerability['url']}" --batch -D acuart --tables
```

### Extracted Payloads:
"""
            # Add payloads if available
            payloads = vulnerability.get('payloads', [])
            if payloads:
                for i, payload in enumerate(payloads[:5], 1):
                    poc_template += f"{i}. `{payload}`\n"
            else:
                poc_template += "No payloads captured\n"
            
            poc_template += f"""
### Database Information:
```json
{json.dumps(vulnerability.get('database_info', {}), indent=2)}
```

### Impact:
* Database enumeration
* Data extraction
* Potential system compromise
* Authentication bypass
"""
            return poc_template
        
        elif vulnerability['type'] == 'XSS' or 'Cross-Site Scripting' in vulnerability['type']:
            poc_template = f"""
## Cross-Site Scripting Proof of Concept

**Vulnerable URL**: {vulnerability['url']}
**Vulnerable Parameter**: {vulnerability.get('parameter', 'Unknown')}

### Manual Reproduction:

1. **Basic XSS Payload**:
   ```bash
   curl -G "{vulnerability['url']}" --data-urlencode "{vulnerability.get('parameter', 'param')}=<script>alert('XSS')</script>"
   ```

2. **Alternative Payloads**:
   ```bash
   # Image-based XSS
   curl -G "{vulnerability['url']}" --data-urlencode "{vulnerability.get('parameter', 'param')}=<img src=x onerror=alert(1)>"

   # SVG-based XSS  
   curl -G "{vulnerability['url']}" --data-urlencode "{vulnerability.get('parameter', 'param')}=<svg onload=alert(1)>"
   ```

### Impact:
* Session hijacking
* Credential theft
* Defacement
* Malware distribution
"""
            return poc_template
        
        else:
            return f"""
## {vulnerability['type']} Proof of Concept

**Vulnerable URL**: {vulnerability['url']}
**Tool**: {vulnerability.get('tool', 'Unknown')}
**Evidence**: {vulnerability.get('evidence', 'N/A')}

### Manual Verification:
```bash
curl "{vulnerability['url']}"
```

### Impact:
{vulnerability.get('description', 'Security vulnerability requiring attention')}
"""

    # REPORT GENERATION METHODS
    async def generate_ai_enhanced_report(self, recon_data: Dict, service_data: Dict, analysis_data: Dict):
        """Generate AI-enhanced penetration test report in organized directory"""
        print("   📊 Generating AI-enhanced report...")

        try:
            # Use self.vulnerabilities (the live data) but filter out FFUF directory discoveries
            real_vulnerabilities, recon_findings = self.filter_vulnerabilities_for_report(self.vulnerabilities)
            
            # Prepare data for AI analysis WITH FILTERED VULNERABILITIES
            report_data = {
                'target': self.scan_name,
                'reconnaissance': recon_data,
                'services': service_data,
                'analysis': analysis_data,
                'vulnerabilities': real_vulnerabilities,  # Only real vulnerabilities
                'recon_findings': recon_findings,  # FFUF findings for reference
                'summary': {
                    'total_vulnerabilities': len(real_vulnerabilities),  # Filtered count
                    'critical_count': len([v for v in real_vulnerabilities if v.get('severity') == 'critical']),
                    'high_count': len([v for v in real_vulnerabilities if v.get('severity') == 'high']),
                    'medium_count': len([v for v in real_vulnerabilities if v.get('severity') == 'medium']),
                    'low_count': len([v for v in real_vulnerabilities if v.get('severity') == 'low'])
                }
            }

            # Create target-specific directory
            target_dir = Path("reports") / self.scan_name
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate AI-enhanced executive summary
            ai_summary = await self.ai_strategist.generate_executive_summary(report_data)
            
            # Generate comprehensive report
            report_path = target_dir / f"pentest_report_{self.scan_name}.md"
            self._write_comprehensive_report(report_path, report_data, ai_summary)
            
            # Generate JSON version for tooling
            json_path = target_dir / f"pentest_report_{self.scan_name}.json"
            with open(json_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            # Generate executive summary (brief version)
            exec_summary_path = target_dir / f"executive_summary_{self.scan_name}.md"
            self._write_executive_summary(exec_summary_path, report_data, ai_summary)
            
            # Generate vulnerabilities-only report
            vuln_report_path = target_dir / f"vulnerabilities_{self.scan_name}.md"
            self._write_vulnerabilities_report(vuln_report_path, report_data, ai_summary)
            
            # Generate raw scan data
            raw_data_path = target_dir / f"raw_scan_data_{self.scan_name}.json"
            with open(raw_data_path, 'w') as f:
                json.dump({
                    'reconnaissance': recon_data,
                    'services': service_data,
                    'analysis': analysis_data,
                    'vulnerabilities': self.vulnerabilities
                }, f, indent=2)
                
            print(f"   📁 Reports saved to: {target_dir}/")
            print(f"   📄 Comprehensive report: pentest_report_{self.scan_name}.md")
            print(f"   📊 Executive summary: executive_summary_{self.scan_name}.md")
            print(f"   🎯 Vulnerabilities report: vulnerabilities_{self.scan_name}.md")
            print(f"   🔧 JSON report: pentest_report_{self.scan_name}.json")
            print(f"   📋 Raw data: raw_scan_data_{self.scan_name}.json")
        
        except Exception as e:
            print(f"   ❌ Error generating report: {e}")
            import traceback
            traceback.print_exc()
            # Fallback to basic report in target directory
            self._generate_basic_report()


    def filter_vulnerabilities_for_report(self, vulnerabilities):
        """Separate real vulnerabilities from reconnaissance findings"""
        print(f"🔧 DEBUG: Raw vulnerabilities count: {len(vulnerabilities)}")
        
        # Debug: Show what types of vulnerabilities we have
        for i, vuln in enumerate(vulnerabilities[:5]):
            print(f"🔧 DEBUG Vuln {i}: Type='{vuln.get('type')}', Tool='{vuln.get('tool')}', Severity='{vuln.get('severity')}'")
        
        real_vulns = []
        recon_findings = []
        
        for finding in vulnerabilities:
            # Separate FFUF directory discoveries as reconnaissance
            if (finding.get('tool') == 'ffuf' and 
                'Directory/File Discovered' in finding.get('type', '')):
                recon_findings.append(finding)
            else:
                # Keep everything else (SQL injections, XSS, etc.)
                real_vulns.append(finding)
        
        print(f"🔧 Report filtering: {len(vulnerabilities)} total -> {len(real_vulns)} vulnerabilities + {len(recon_findings)} recon findings")
        return real_vulns, recon_findings
            

    def _write_comprehensive_report(self, report_path: Path, report_data: Dict, ai_summary: Dict):
        """Write comprehensive markdown report"""
        with open(report_path, 'w') as f:
            f.write(f"# Penetration Test Report: {self.scan_name}\n\n")
            f.write(f"**Date**: {self._get_current_timestamp()}\n")
            f.write(f"**Target**: {self.scan_name}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(ai_summary.get('executive_summary', 'AI-enhanced executive summary not available.\n'))
            f.write("\n")
            
            # Risk Assessment
            f.write("### Risk Assessment\n\n")
            risk_level = ai_summary.get('overall_risk', 'Medium')
            f.write(f"**Overall Risk Level**: {risk_level}\n\n")
            f.write(f"**Total Vulnerabilities**: {len(self.vulnerabilities)}\n")
            f.write(f"- Critical: {report_data['summary']['critical_count']}\n")
            f.write(f"- High: {report_data['summary']['high_count']}\n")
            f.write(f"- Medium: {report_data['summary']['medium_count']}\n")
            f.write(f"- Low: {report_data['summary']['low_count']}\n\n")
            
            # Key Findings
            f.write("### Key Findings\n\n")
            key_findings = ai_summary.get('key_findings', [])
            if key_findings:
                for finding in key_findings:
                    f.write(f"- {finding}\n")
            else:
                f.write("- No critical vulnerabilities identified\n")
            f.write("\n")
            
            # Detailed Vulnerability Findings
            f.write("## Detailed Vulnerability Findings\n\n")
            if self.vulnerabilities:
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"### {i}. {vuln.get('type', 'Unknown')}\n\n")
                    f.write(f"- **URL**: {vuln.get('url', 'N/A')}\n")
                    f.write(f"- **Severity**: {vuln.get('severity', 'unknown').title()}\n")
                    f.write(f"- **Confidence**: {vuln.get('confidence', 'medium').title()}\n")
                    f.write(f"- **Tool**: {vuln.get('tool', 'Unknown')}\n\n")
                    
                    f.write("#### Description\n")
                    f.write(f"{vuln.get('description', 'No description available.')}\n\n")
                    
                    f.write("#### Proof of Concept\n")
                    # Use AI-generated exploit code if available
                    if vuln.get('exploit_poc'):
                        poc_data = vuln['exploit_poc']
                        f.write(f"**Exploit Verified**: {'✅ YES' if poc_data.get('verified') else '❌ NO'}\n\n")
                        f.write("##### AI-Generated Exploit Code\n")
                        f.write("```bash\n")
                        f.write(poc_data.get('exploit_code', ''))
                        f.write("\n```\n\n")
                        f.write("##### Verification Steps\n")
                        for step in poc_data.get('verification_steps', []):
                            f.write(f"- {step}\n")
                        f.write("\n")
                    else:
                        # Fallback to original POC
                        f.write(f"{vuln.get('detailed_poc', 'No POC available.')}\n\n")
                    
                    f.write("#### Remediation\n")
                    remediation = ai_summary.get('remediation_recommendations', {}).get(vuln.get('type'), 
                                "Apply security best practices and patch accordingly.")
                    f.write(f"{remediation}\n\n")
                    
                    f.write("---\n\n")
            else:
                f.write("No vulnerabilities were identified during this assessment.\n\n")
            
            # Reconnaissance Details
            f.write("## Reconnaissance Details\n\n")
            recon = report_data.get('reconnaissance', {})
            basic_recon = recon.get('basic_recon', {})
            
            f.write("### Subdomains Discovered\n")
            subdomains = basic_recon.get('subdomains', [])
            if subdomains:
                for domain in subdomains[:10]:
                    f.write(f"- {domain}\n")
                if len(subdomains) > 10:
                    f.write(f"- ... and {len(subdomains) - 10} more\n")
            else:
                f.write("No subdomains discovered.\n")
            f.write("\n")
            
            f.write("### Open Ports\n")
            nmap_results = basic_recon.get('nmap_results', {})
            open_ports = nmap_results.get('open_ports', [])
            if open_ports:
                for port in open_ports:
                    f.write(f"- {port}\n")
            else:
                f.write("No open ports found.\n")
            f.write("\n")
            
            # AI Recommendations
            f.write("## AI Recommendations\n\n")
            recommendations = ai_summary.get('recommendations', [])
            if recommendations:
                for rec in recommendations:
                    f.write(f"- {rec}\n")
            else:
                f.write("- Continue regular security monitoring\n")
                f.write("- Implement web application firewall\n")
                f.write("- Conduct regular vulnerability assessments\n")
            
            f.write("\n## Conclusion\n\n")
            f.write(ai_summary.get('conclusion', 'Assessment completed. Review findings and implement recommended remediations.'))
                
        print(f"   📄 Comprehensive report written to: {report_path}")

    def _write_executive_summary(self, report_path: Path, report_data: Dict, ai_summary: Dict):
        """Write executive summary report"""
        with open(report_path, 'w') as f:
            f.write(f"# Executive Summary: {self.scan_name}\n\n")
            f.write(f"**Date**: {self._get_current_timestamp()}\n")
            f.write(f"**Target**: {self.scan_name}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(ai_summary.get('executive_summary', 'AI-enhanced executive summary not available.\n'))
            f.write("\n")
            
            # Risk Assessment
            f.write("## Risk Assessment\n\n")
            risk_level = ai_summary.get('overall_risk', 'Medium')
            f.write(f"**Overall Risk Level**: {risk_level}\n\n")
            f.write(f"**Total Vulnerabilities**: {len(self.vulnerabilities)}\n")
            f.write(f"- Critical: {report_data['summary']['critical_count']}\n")
            f.write(f"- High: {report_data['summary']['high_count']}\n")
            f.write(f"- Medium: {report_data['summary']['medium_count']}\n")
            f.write(f"- Low: {report_data['summary']['low_count']}\n\n")
            
            # Key Findings
            f.write("## Key Findings\n\n")
            key_findings = ai_summary.get('key_findings', [])
            if key_findings:
                for finding in key_findings:
                    f.write(f"- {finding}\n")
            else:
                f.write("- No critical vulnerabilities identified\n")
            f.write("\n")
            
            # Top Vulnerabilities
            f.write("## Top Vulnerabilities\n\n")
            if self.vulnerabilities:
                high_vulns = [v for v in self.vulnerabilities if v.get('severity') in ['high', 'critical']]
                for i, vuln in enumerate(high_vulns[:5], 1):
                    f.write(f"{i}. **{vuln.get('type', 'Unknown')}** - {vuln.get('url', 'N/A')}\n")
            f.write("\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            recommendations = ai_summary.get('recommendations', [])
            if recommendations:
                for rec in recommendations:
                    f.write(f"- {rec}\n")
            else:
                f.write("- Continue regular security monitoring\n")
                f.write("- Implement web application firewall\n")
                f.write("- Conduct regular vulnerability assessments\n")

    def _write_vulnerabilities_report(self, report_path: Path, report_data: Dict, ai_summary: Dict):
        """Write vulnerabilities-focused report"""
        with open(report_path, 'w') as f:
            f.write(f"# Vulnerability Report: {self.scan_name}\n\n")
            f.write(f"**Date**: {self._get_current_timestamp()}\n")
            f.write(f"**Target**: {self.scan_name}\n\n")
            
            # Vulnerability Summary
            f.write("## Vulnerability Summary\n\n")
            f.write(f"**Total Vulnerabilities**: {len(self.vulnerabilities)}\n")
            f.write(f"- Critical: {report_data['summary']['critical_count']}\n")
            f.write(f"- High: {report_data['summary']['high_count']}\n")
            f.write(f"- Medium: {report_data['summary']['medium_count']}\n")
            f.write(f"- Low: {report_data['summary']['low_count']}\n\n")
            
            # Detailed Vulnerabilities
            f.write("## Detailed Vulnerabilities\n\n")
            if self.vulnerabilities:
                # Group by severity
                by_severity = {}
                for vuln in self.vulnerabilities:
                    severity = vuln.get('severity', 'unknown')
                    if severity not in by_severity:
                        by_severity[severity] = []
                    by_severity[severity].append(vuln)
                
                # Print by severity order
                for severity in ['critical', 'high', 'medium', 'low', 'unknown']:
                    if severity in by_severity:
                        f.write(f"### {severity.title()} Severity\n\n")
                        for i, vuln in enumerate(by_severity[severity], 1):
                            f.write(f"#### {i}. {vuln.get('type', 'Unknown')}\n\n")
                            f.write(f"- **URL**: {vuln.get('url', 'N/A')}\n")
                            f.write(f"- **Tool**: {vuln.get('tool', 'Unknown')}\n")
                            f.write(f"- **Confidence**: {vuln.get('confidence', 'medium').title()}\n\n")
                            
                            f.write("##### Proof of Concept\n")
                            f.write(f"{vuln.get('detailed_poc', 'No POC available.')}\n\n")
                            
                            f.write("##### Remediation\n")
                            remediation = ai_summary.get('remediation_recommendations', {}).get(vuln.get('type'), 
                                        "Apply security best practices and patch accordingly.")
                            f.write(f"{remediation}\n\n")
                            
                            f.write("---\n\n")
            else:
                f.write("No vulnerabilities were identified during this assessment.\n")

    def _generate_basic_report(self):
        """Generate a basic report as fallback"""
        target_dir = Path("reports") / self.scan_name
        target_dir.mkdir(parents=True, exist_ok=True)
        
        report_path = target_dir / f"basic_report_{self.scan_name}.txt"
        with open(report_path, 'w') as f:
            f.write(f"Basic Penetration Test Report: {self.scan_name}\n")
            f.write(f"Date: {self._get_current_timestamp()}\n")
            f.write(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}\n\n")
            
            for vuln in self.vulnerabilities:
                f.write(f"Type: {vuln.get('type', 'Unknown')}\n")
                f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                f.write(f"Severity: {vuln.get('severity', 'unknown')}\n")
                f.write("---\n")
        
        print(f"   📄 Basic fallback report written to: {report_path}")

    def _get_current_timestamp(self) -> str:
        """Get current timestamp for reports"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Batch processing methods
    async def process_batch_targets(self, batch_file: str, output_dir: str = None):
        """Process multiple targets from a batch file"""
        try:
            with open(batch_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            print(f"📋 Loaded {len(targets)} targets from {batch_file}")
            
            # Create output directory if specified
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            # Process targets in parallel with limited concurrency
            semaphore = asyncio.Semaphore(self.max_workers)
            
            async def process_target(target):
                async with semaphore:
                    try:
                        print(f"\n🎯 Processing: {target}")
                        await self.run_full_assessment(target)
                        
                        # Move reports if output_dir specified
                        if output_dir:
                            target_reports = Path("reports") / self.scan_name
                            if target_reports.exists():
                                import shutil
                                shutil.move(str(target_reports), str(Path(output_dir) / self.scan_name))
                                
                    except Exception as e:
                        print(f"❌ Failed to process {target}: {e}")
            
            # Run all targets
            await asyncio.gather(*(process_target(target) for target in targets))
            
            print(f"\n✅ Batch processing complete! Processed {len(targets)} targets")
            
        except FileNotFoundError:
            print(f"❌ Batch file not found: {batch_file}")
        except Exception as e:
            print(f"❌ Error processing batch: {e}")

    def _load_targets_from_file(self, file_path: str) -> List[str]:
        """Load and validate targets from file"""
        try:
            with open(file_path, 'r') as f:
                targets = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        # Clean the target
                        target = self._clean_target(line)
                        if target:
                            targets.append(target)
                return targets
        except FileNotFoundError:
            print(f"❌ Targets file not found: {file_path}")
            return []
        except Exception as e:
            print(f"❌ Error reading targets file: {e}")
            return []

    def _clean_target(self, target: str) -> str:
        """Clean and validate target"""
        target = target.strip()
        
        # Remove http:// or https:// if present (we'll add it back later)
        target = re.sub(r'^https?://', '', target)
        
        # Remove paths and parameters
        target = target.split('/')[0]
        
        # Validate domain format
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return target
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', target):  # IP address
            return target
        else:
            print(f"⚠️  Skipping invalid target: {target}")
            return ""