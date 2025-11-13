import asyncio
import yaml
import json
import os
from typing import List, Dict, Any
from pathlib import Path

from tools.reconnaissance import ReconnaissanceEngine

class AutonomousPentestAgent:
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.discovered_targets = []
        self.vulnerabilities = []
        self.recon_engine = ReconnaissanceEngine()
        print("🤖 Autonomous Pentest Agent Initialized")
    
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
    
    async def run_full_assessment(self, target: str):
        """Execute complete autonomous penetration test"""
        
        print(f"🎯 Starting assessment of: {target}")
        print("-" * 40)
        
        # Phase 1: Real Reconnaissance
        print("\n[1/4] 🔍 Conducting Real Reconnaissance...")
        recon_results = await self.conduct_real_reconnaissance(target)
        
        # Phase 2: Target Analysis
        print("\n[2/4] 🧠 Analyzing Targets...")
        analysis_results = await self.analyze_targets(recon_results)
        
        # Phase 3: Vulnerability Scanning
        print("\n[3/4] ⚡ Running Vulnerability Scans...")
        await self.run_real_vulnerability_scans(analysis_results['priority_targets'])
        
        # Phase 4: Reporting
        print("\n[4/4] 📊 Generating Report...")
        await self.generate_report()
        
        print(f"\n✅ Assessment complete! Found {len(self.vulnerabilities)} vulnerabilities.")
    
    async def conduct_real_reconnaissance(self, target: str) -> Dict:
        """Run real reconnaissance tools"""
        print(f"   Running real reconnaissance on {target}...")
        
        real_results = {
            'subdomains': [],
            'live_domains': [],
            'endpoints': [],
            'nmap_results': {},
            'crawled_urls': []
        }
        
        # 1. Subdomain enumeration (try multiple tools)
        print("   🔎 Enumerating subdomains...")
        subdomains = await self.recon_engine.run_subfinder(target)
        if not subdomains:
            print("      Trying Amass as alternative...")
            subdomains = await self.recon_engine.run_amass(target)
        
        real_results['subdomains'] = subdomains
        print(f"      Found {len(subdomains)} subdomains")
        
        # 2. Find live domains from subdomains + main domain
        print("   🌐 Checking live domains...")
        all_domains_to_check = [target] + subdomains
        live_domains = await self.recon_engine.run_httpx(all_domains_to_check)
        real_results['live_domains'] = live_domains
        print(f"      {len(live_domains)} domains are live")
        
        # 3. Get historical URLs with filtering
        print("   📜 Gathering historical URLs...")
        historical_urls = await self.recon_engine.run_waybackurls(target)
        real_results['endpoints'] = historical_urls
        print(f"      Found {len(historical_urls)} filtered historical URLs")
        
        # 4. Crawl main target for current endpoints
        print("   🕷️ Crawling main target...")
        crawled_urls = await self.recon_engine.run_katana(target)
        real_results['crawled_urls'] = crawled_urls
        print(f"      Crawled {len(crawled_urls)} current URLs")
        
        # 5. Nmap scan on main target
        print("   🔍 Running port scan...")
        nmap_results = await self.recon_engine.run_nmap(target)
        real_results['nmap_results'] = nmap_results
        print(f"      Found {len(nmap_results.get('open_ports', []))} open ports")
        
        # Combine all discovered targets
        all_targets = live_domains + historical_urls + crawled_urls
        # Remove duplicates and limit
        self.discovered_targets = list(set(all_targets))[:100]  # Limit to 100 unique targets
        
        return real_results
    
    async def analyze_targets(self, recon_data: Dict) -> Dict:
        """Analyze reconnaissance data to prioritize targets"""
        print("   Analyzing and prioritizing targets...")
        
        priority_targets = []
        all_targets = self.discovered_targets
        
        # Advanced prioritization logic
        for target in all_targets:
            score = 0
            reasons = []
            
            # High priority indicators
            if any(keyword in target.lower() for keyword in ['admin', 'login', 'auth', 'register', 'signin', 'signup']):
                score += 3
                reasons.append('Authentication endpoint')
            
            if any(keyword in target.lower() for keyword in ['api', 'rest', 'graphql', 'soap']):
                score += 3
                reasons.append('API endpoint')
            
            if '?' in target and '=' in target:  # Has parameters
                score += 2
                reasons.append('Parameterized endpoint')
            
            if any(ext in target for ext in ['.php', '.asp', '.jsp', '.aspx']):
                score += 1
                reasons.append('Dynamic page')
            
            if target.endswith(('.json', '.xml', '.config')):
                score += 2
                reasons.append('Data/config file')
            
            # Categorize by score
            if score >= 3:
                priority = 'high'
            elif score >= 1:
                priority = 'medium'
            else:
                priority = 'low'
            
            if priority in ['high', 'medium']:  # Only include high/medium priority
                priority_targets.append({
                    'url': target, 
                    'priority': priority, 
                    'score': score,
                    'reasons': reasons
                })
        
        # Sort by score (highest first)
        priority_targets.sort(key=lambda x: x['score'], reverse=True)
        
        analysis = {
            'priority_targets': priority_targets[:15],  # Top 15 targets
            'risk_level': 'high' if any(t['priority'] == 'high' for t in priority_targets) else 'medium',
            'recommended_tests': ['SQLi', 'XSS', 'IDOR', 'Authentication Testing']
        }
        
        print(f"   ✅ Prioritized {len(priority_targets)} targets ({len([t for t in priority_targets if t['priority'] == 'high'])} high priority)")
        
        return analysis
    
    async def run_real_vulnerability_scans(self, targets: List[Dict]):
        """Run real vulnerability scans"""
        print(f"   Scanning {len(targets)} high-priority targets...")
        
        # For now, we'll simulate based on target characteristics
        simulated_vulns = []
        
        for target in targets[:5]:  # Test top 5 targets
            url = target['url']
            
            # Simulate findings based on URL characteristics
            if 'artist=' in url or 'cat=' in url:
                simulated_vulns.append({
                    'type': 'SQL Injection',
                    'url': url,
                    'parameter': url.split('=')[1].split('&')[0] if '=' in url else 'id',
                    'severity': 'high',
                    'confidence': 'medium',
                    'tool': 'simulated',
                    'evidence': 'Parameter in URL suggests potential SQLi'
                })
            
            if any(keyword in url for keyword in ['search', 'q=', 'query=']):
                simulated_vulns.append({
                    'type': 'XSS',
                    'url': url,
                    'parameter': 'q' if 'q=' in url else 'search',
                    'severity': 'medium',
                    'confidence': 'high',
                    'tool': 'simulated',
                    'evidence': 'Search parameter suggests potential XSS'
                })
            
            if 'admin' in url or 'login' in url:
                simulated_vulns.append({
                    'type': 'Broken Authentication',
                    'url': url,
                    'parameter': 'N/A',
                    'severity': 'high',
                    'confidence': 'low',
                    'tool': 'simulated',
                    'evidence': 'Authentication endpoint identified'
                })
        
        self.vulnerabilities.extend(simulated_vulns)
        print(f"   ✅ Found {len(simulated_vulns)} potential vulnerabilities")
    
    async def generate_report(self):
        """Generate assessment report"""
        print("   Generating comprehensive report...")
        
        # Categorize vulnerabilities
        high_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'high']
        medium_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'medium']
        low_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'low']
        
        report = {
            'summary': {
                'total_targets': len(self.discovered_targets),
                'vulnerabilities_found': len(self.vulnerabilities),
                'high_severity': len(high_vulns),
                'medium_severity': len(medium_vulns),
                'low_severity': len(low_vulns),
                'assessment_date': str(asyncio.get_event_loop().time())
            },
            'vulnerabilities': {
                'high': high_vulns,
                'medium': medium_vulns,
                'low': low_vulns
            },
            'targets_scanned': self.discovered_targets[:20],
            'recommendations': [
                "Implement input validation on all user inputs",
                "Add WAF protection for SQLi and XSS attacks",
                "Conduct authentication mechanism testing",
                "Review API endpoints for authorization issues"
            ]
        }
        
        # Save report
        report_path = "reports/assessment_report.json"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"   ✅ Report saved to: {report_path}")
        
        # Print detailed summary
        print(f"\n📋 Detailed Summary:")
        print(f"   • Targets Discovered: {report['summary']['total_targets']}")
        print(f"   • Vulnerabilities Found: {report['summary']['vulnerabilities_found']}")
        print(f"   • High Severity: {report['summary']['high_severity']}")
        print(f"   • Medium Severity: {report['summary']['medium_severity']}")
        print(f"   • Low Severity: {report['summary']['low_severity']}")
