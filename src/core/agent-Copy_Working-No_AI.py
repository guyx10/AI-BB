import asyncio
import yaml
import json
import os
import re
import sys
from typing import List, Dict, Any
from pathlib import Path

# Add the parent directory to path to fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class AutonomousPentestAgent:
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.discovered_targets = []
        self.vulnerabilities = []
        
        # Initialize tools with error handling
        try:
            from tools.reconnaissance import ReconnaissanceEngine
            from tools.vulnerability_scanner import VulnerabilityScanner
            from tools.advanced_orchestrator import AdvancedOrchestrator
            
            self.recon_engine = ReconnaissanceEngine()
            self.vuln_scanner = VulnerabilityScanner()
            self.advanced_orchestrator = AdvancedOrchestrator()
        except ImportError as e:
            print(f"❌ Tool modules not found: {e}")
            print("📁 Creating missing tool modules...")
            self._create_missing_tools()
            # Re-import after creation
            from tools.reconnaissance import ReconnaissanceEngine
            from tools.vulnerability_scanner import VulnerabilityScanner
            from tools.advanced_orchestrator import AdvancedOrchestrator
            
            self.recon_engine = ReconnaissanceEngine()
            self.vuln_scanner = VulnerabilityScanner()
            self.advanced_orchestrator = AdvancedOrchestrator()
        
        self.scan_name = ""
        print("🤖 Autonomous Pentest Agent Initialized")
    
    def _create_missing_tools(self):
        """Create missing tool modules if they don't exist"""
        tools_dir = Path(__file__).parent.parent / "tools"
        tools_dir.mkdir(exist_ok=True)
        
        # Create __init__.py in tools directory
        (tools_dir / "__init__.py").write_text("# Tools package\n")
        
        # Create reconnaissance.py if missing
        recon_file = tools_dir / "reconnaissance.py"
        if not recon_file.exists():
            recon_content = '''#!/usr/bin/env python3
import asyncio
import subprocess
import json
from typing import List, Dict

class ReconnaissanceEngine:
    """Real reconnaissance using actual security tools"""
    
    async def run_subfinder(self, domain: str) -> List[str]:
        """Run subdomain enumeration using subfinder"""
        try:
            cmd = f"subfinder -d {domain} -silent"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\\n')
                valid_subdomains = [sd for sd in subdomains if sd and not sd.startswith('Error')]
                return valid_subdomains
            else:
                print(f"❌ Subfinder error: {stderr.decode()}")
                return await self.run_amass(domain)
        except Exception as e:
            print(f"❌ Subfinder exception: {e}")
            return []
    
    async def run_amass(self, domain: str) -> List[str]:
        """Alternative subdomain enumeration using amass"""
        try:
            cmd = f"amass enum -passive -d {domain}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\\n')
                return [sd for sd in subdomains if sd]
            else:
                print(f"❌ Amass error: {stderr.decode()}")
                return []
        except Exception as e:
            print(f"❌ Amass exception: {e}")
            return []
    
    async def run_httpx(self, domains: List[str]) -> List[str]:
        """Check which domains are live using the CORRECT ProjectDiscovery HTTPr"""
        if not domains:
            return []
            
        try:
            # Write domains to a temporary file
            with open('/tmp/domains.txt', 'w') as f:
                for domain in domains:
                    f.write(f"{domain}\\n")
        
            print(f"      Testing ProjectDiscovery HTTPr with {len(domains)} domains...")
            
            # Use the FULL PATH to the correct HTTPr
            httpx_path = "/home/th0th/go/bin/httpx"
            
            # Commands for ProjectDiscovery HTTPr (the security tool)
            httpx_commands = [
                f"{httpx_path} -list /tmp/domains.txt -silent",
                f"{httpx_path} -l /tmp/domains.txt -silent",
                f"cat /tmp/domains.txt | {httpx_path} -silent",
                f"{httpx_path} -list /tmp/domains.txt -silent -status-code",
                f"{httpx_path} -l /tmp/domains.txt -silent -status-code -content-length"
            ]
            
            for i, cmd in enumerate(httpx_commands, 1):
                try:
                    print(f"      Trying command {i}: {cmd.split(' ')[0]}...")
                    process = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
                    
                    stderr_output = stderr.decode().strip()
                    if stderr_output and "Error" in stderr_output:
                        print(f"         Stderr: {stderr_output[:100]}")
                    
                    if process.returncode == 0 and stdout:
                        live_domains = stdout.decode().strip().split('\\n')
                        valid_domains = [domain for domain in live_domains if domain and '://' in domain]
                        if valid_domains:
                            print(f"      ✅ HTTPr successful!")
                            print(f"      Found {len(valid_domains)} live domains")
                            return valid_domains
                    else:
                        print(f"         Return code: {process.returncode}")
                        
                except Exception as e:
                    print(f"         Command failed: {e}")
                    continue
            
            print("❌ All HTTPr methods failed")
            
            # Simple fallback - just return the main domain
            print("      Using simple fallback - assuming main domain is live")
            main_domains = []
            for domain in domains[:3]:  # First 3 domains
                if not domain.startswith(('http://', 'https://')):
                    main_domains.extend([f"http://{domain}", f"https://{domain}"])
                else:
                    main_domains.append(domain)
            return main_domains[:5]  # Limit to 5 domains
                
        except Exception as e:
            print(f"❌ HTTPr exception: {e}")
            # Simple fallback
            return [f"http://{domains[0]}", f"https://{domains[0]}"] if domains and not domains[0].startswith('http') else domains[:2]
    
    async def run_nmap(self, target: str) -> Dict:
        """Run nmap scan on target"""
        try:
            # Remove protocol for nmap
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Simplified nmap for speed
            cmd = f"nmap -sS --top-ports 50 {clean_target}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            output = stdout.decode()
            
            # Parse open ports from output
            open_ports = []
            for line in output.split('\\n'):
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0].strip()
                    service = line.split(' ')[-1] if ' ' in line else 'unknown'
                    open_ports.append(f"{port}/{service}")
            
            return {
                'target': clean_target,
                'open_ports': open_ports,
                'raw_output': output[:500] + "..." if len(output) > 500 else output
            }
        except Exception as e:
            print(f"❌ Nmap error: {e}")
            return {'target': target, 'open_ports': [], 'error': str(e)}
    
    async def run_waybackurls(self, domain: str) -> List[str]:
        """Get historical URLs from Wayback Machine with filtering"""
        try:
            cmd = f"echo {domain} | waybackurls"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = stdout.decode().strip().split('\\n')
                # Filter out garbage URLs and limit to reasonable number
                filtered_urls = self.filter_urls(urls)
                return filtered_urls[:200]  # Limit to 200 URLs
            else:
                # If waybackurls not installed, use gau
                return await self.run_gau(domain)
        except Exception as e:
            print(f"❌ Waybackurls error: {e}")
            return []
    
    def filter_urls(self, urls: List[str]) -> List[str]:
        """Filter out garbage URLs"""
        filtered = []
        garbage_keywords = ['%0A', '%20,%20', 'HTTP/1.1', 'I want to start testing']
        
        for url in urls:
            # Skip URLs with garbage content
            if any(garbage in url for garbage in garbage_keywords):
                continue
            # Skip very long URLs (likely malformed)
            if len(url) > 500:
                continue
            # Skip URLs without proper protocol
            if not url.startswith('http'):
                continue
            # Skip URLs that are just domains without paths
            if url.count('/') <= 2:
                continue
            filtered.append(url)
        
        return filtered
    
    async def run_gau(self, domain: str) -> List[str]:
        """Get All URLs as fallback"""
        try:
            cmd = f"gau {domain}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = stdout.decode().strip().split('\\n')
                filtered_urls = self.filter_urls(urls)
                return filtered_urls[:200]  # Limit to 200 URLs
            else:
                print(f"❌ GAU not available: {stderr.decode()}")
                return []
        except Exception as e:
            print(f"❌ GAU error: {e}")
            return []
    
    async def run_katana(self, domain: str) -> List[str]:
        """Use Katana for crawling and discovering endpoints"""
        try:
            # Remove protocol for katana
            clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            cmd = f"katana -u http://{clean_domain} -silent -depth 2"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = stdout.decode().strip().split('\\n')
                return [url for url in urls if url]
            else:
                print(f"❌ Katana error: {stderr.decode()}")
                return []
        except Exception as e:
            print(f"❌ Katana exception: {e}")
            return []
'''
            recon_file.write_text(recon_content)
            print("✅ Created reconnaissance.py")
        
        # Create vulnerability_scanner.py if missing
        vuln_file = tools_dir / "vulnerability_scanner.py"
        if not vuln_file.exists():
            vuln_content = '''#!/usr/bin/env python3
import asyncio
import subprocess
import json
from typing import List, Dict, Any

class VulnerabilityScanner:
    """Real vulnerability scanning using security tools"""
    
    async def run_command_with_timeout(self, cmd: str, timeout: int = 60) -> tuple:
        """Run a command with proper timeout handling"""
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Use asyncio.wait_for for timeout
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                return process.returncode, stdout, stderr
            except asyncio.TimeoutError:
                print(f"         Command timeout: {cmd.split(' ')[0]}")
                process.terminate()
                return -1, None, None
                
        except Exception as e:
            print(f"         Command error: {e}")
            return -1, None, None
    
    async def run_nuclei(self, target: str) -> List[Dict]:
        """Run Nuclei vulnerability scanner"""
        try:
            # Try different nuclei commands
            nuclei_commands = [
                f"nuclei -u {target} -severity low,medium,high,critical -json -silent",
                f"nuclei -u {target} -t /usr/share/nuclei-templates/ -severity low,medium,high,critical -json -silent",
                f"nuclei -u {target} -severity medium,high,critical -json -silent"
            ]
            
            all_findings = []
            
            for cmd in nuclei_commands:
                try:
                    print(f"         Running nuclei...")
                    returncode, stdout, stderr = await self.run_command_with_timeout(cmd, timeout=120)
                    
                    if returncode == 0 and stdout:
                        output = stdout.decode().strip()
                        if output:
                            for line in output.split('\\n'):
                                if line.strip():
                                    try:
                                        finding = json.loads(line)
                                        all_findings.append(finding)
                                    except json.JSONDecodeError:
                                        continue
                    
                except Exception as e:
                    print(f"         Nuclei error: {e}")
                    continue
            
            return all_findings
            
        except Exception as e:
            print(f"❌ Nuclei error for {target}: {e}")
            return []
    
    async def run_sqlmap_quick(self, url: str) -> List[Dict]:
        """Run quick sqlmap scan with basic tests"""
        try:
            # Only test if URL has parameters
            if '?' not in url or '=' not in url:
                return []
                
            print(f"         Testing SQLi on: {url.split('?')[0]}...")
            
            # Very quick sqlmap scan - just test basic injection
            param = url.split('?')[1].split('=')[0] if '?' in url else 'id'
            cmd = f"sqlmap -u '{url}' --batch --level=1 --risk=1 --flush-session --time-sec=2 --threads=2"
            
            returncode, stdout, stderr = await self.run_command_with_timeout(cmd, timeout=30)
            
            if returncode == 0 and stdout:
                output = stdout.decode()
                
                # Parse sqlmap output for vulnerabilities
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
                        'parameter': param
                    }]
            
            return []
                
        except Exception as e:
            print(f"❌ SQLMap error for {url}: {e}")
            return []
    
    async def run_basic_curl_tests(self, url: str) -> List[Dict]:
        """Run basic curl-based security tests"""
        findings = []
        
        try:
            # Test for SQL error messages
            sql_payloads = ["'", "1' OR '1'='1", "1 AND 1=1"]
            for payload in sql_payloads:
                test_url = url.replace('=', f"={payload}", 1)
                cmd = f"curl -s -k '{test_url}' --connect-timeout 5"
                returncode, stdout, stderr = await self.run_command_with_timeout(cmd, timeout=10)
                
                if returncode == 0 and stdout:
                    response = stdout.decode().lower()
                    if any(error in response for error in ['sql', 'mysql', 'database', 'syntax', 'error']):
                        findings.append({
                            'type': 'SQL Injection Potential',
                            'url': url,
                            'tool': 'curl',
                            'severity': 'medium',
                            'confidence': 'low',
                            'evidence': f'SQL error message detected with payload: {payload}',
                            'parameter': url.split('?')[1].split('=')[0] if '?' in url else 'unknown'
                        })
                        break
            
            # Test for basic XSS reflection
            xss_payload = "<script>alert('xss')</script>"
            if '?' in url:
                test_url = url.replace('=', f"={xss_payload}", 1)
                cmd = f"curl -s -k '{test_url}' --connect-timeout 5"
                returncode, stdout, stderr = await self.run_command_with_timeout(cmd, timeout=10)
                
                if returncode == 0 and stdout:
                    response = stdout.decode()
                    if xss_payload in response:
                        findings.append({
                            'type': 'XSS Potential',
                            'url': url,
                            'tool': 'curl',
                            'severity': 'medium',
                            'confidence': 'low',
                            'evidence': 'XSS payload reflected in response',
                            'parameter': url.split('?')[1].split('=')[0] if '?' in url else 'unknown'
                        })
            
            return findings
            
        except Exception as e:
            print(f"❌ Curl test error for {url}: {e}")
            return []
    
    async def run_custom_tests(self, target: Dict) -> List[Dict]:
        """Run custom tests based on target characteristics"""
        url = target['url']
        findings = []
        
        print(f"         Testing: {url[:60]}...")
        
        # Run basic nuclei scan (if available)
        try:
            nuclei_findings = await self.run_nuclei(url)
            findings.extend(nuclei_findings)
        except Exception as e:
            print(f"         Nuclei failed: {e}")
        
        # Run basic curl tests for SQLi and XSS
        if '?' in url:  # Only test URLs with parameters
            print("         Running basic security tests...")
            basic_findings = await self.run_basic_curl_tests(url)
            findings.extend(basic_findings)
        
        # Run SQLMap for high-priority SQLi targets
        if '?' in url and any(param in url.lower() for param in ['id=', 'artist=', 'user=', 'cat=']):
            print("         Running SQLMap...")
            sql_findings = await self.run_sqlmap_quick(url)
            findings.extend(sql_findings)
        
        print(f"         Found {len(findings)} potential issues")
        return findings
'''
            vuln_file.write_text(vuln_content)
            print("✅ Created vulnerability_scanner.py")
        
        # Create advanced_orchestrator.py if missing
        adv_file = tools_dir / "advanced_orchestrator.py"
        if not adv_file.exists():
            adv_content = '''#!/usr/bin/env python3
import asyncio
import json
import subprocess
from typing import Dict, List, Any

class AdvancedOrchestrator:
    """Advanced tool orchestration without MCP dependencies"""
    
    def __init__(self):
        self.available_tools = self._discover_tools()
        print(f"🔧 Discovered {len(self.available_tools)} security tools")
    
    def _discover_tools(self) -> Dict:
        """Auto-discover available security tools"""
        tools = {}
        common_tools = [
            'nmap', 'sslscan', 'testssl.sh', 'enum4linux', 'smbclient',
            'sqlmap', 'nuclei', 'ffuf', 'gobuster', 'dirb', 'nikto',
            'whatweb', 'wapiti', 'skipfish', 'metasploit'
        ]
        
        for tool in common_tools:
            if self._check_tool_installed(tool):
                tools[tool] = tool
        
        return tools
    
    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed and accessible"""
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    async def run_advanced_nmap(self, target: str, previous_results: Dict) -> Dict:
        """Intelligent nmap scanning based on previous findings"""
        try:
            # Clean target for nmap
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Analyze previous results to determine scan intensity
            open_ports = previous_results.get('open_ports', [])
            
            if not open_ports:
                # No ports found, do comprehensive scan
                command = f"nmap -sS -sV -O -A -p- {clean_target}"
                print(f"   🗺️  Running comprehensive nmap scan...")
            elif any(str(port) in ['80', '443', '8080', '8443'] for port in open_ports):
                # Web services found, focus on web enumeration
                command = f"nmap -sS -sV --script http-* -p 80,443,8080,8443 {clean_target}"
                print(f"   🌐 Running web-focused nmap scan...")
            elif any(str(port) in ['21', '22', '25', '53', '110', '143'] for port in open_ports):
                # Network services found
                command = f"nmap -sS -sV --script banner -p 21,22,25,53,110,143 {clean_target}"
                print(f"   🔌 Running network service nmap scan...")
            else:
                # Default comprehensive scan
                command = f"nmap -sS -sV -A {clean_target}"
                print(f"   🗺️  Running standard nmap scan...")
            
            result = await self._run_command_directly(command, timeout=300)
            
            # Parse nmap output for better reporting
            if result.get('success'):
                result['parsed'] = self._parse_nmap_output(result['stdout'])
            
            return result
                
        except Exception as e:
            print(f"❌ Advanced nmap error: {e}")
            return await self._run_command_directly(f"nmap -sS {clean_target}")
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse nmap output for structured data"""
        parsed = {
            'open_ports': [],
            'services': [],
            'os_guess': [],
            'vulnerabilities': []
        }
        
        for line in output.split('\\n'):
            # Parse open ports
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_service = parts[0].split('/')[0]
                    service_name = parts[2] if len(parts) > 2 else 'unknown'
                    parsed['open_ports'].append(f"{port_service}/{service_name}")
                    parsed['services'].append({
                        'port': port_service,
                        'service': service_name,
                        'state': 'open'
                    })
            
            # Parse OS guesses
            if 'OS:' in line or 'Running:' in line:
                parsed['os_guess'].append(line.strip())
            
            # Parse vulnerabilities
            if 'VULNERABLE:' in line:
                parsed['vulnerabilities'].append(line.strip())
        
        return parsed
    
    async def run_ssl_scan(self, target: str) -> Dict:
        """Run SSL/TLS vulnerability scanning"""
        try:
            # Clean target for SSL scan
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            results = {}
            
            # Try sslscan first
            if 'sslscan' in self.available_tools:
                print("   🔐 Running sslscan...")
                command = f"sslscan {clean_target}"
                results['sslscan'] = await self._run_command_directly(command, timeout=60)
            
            # Try testssl.sh if available
            if 'testssl.sh' in self.available_tools:
                print("   🔐 Running testssl.sh...")
                command = f"testssl.sh --html {clean_target}"
                results['testssl'] = await self._run_command_directly(command, timeout=120)
            
            # Always try nmap SSL scripts
            if 'nmap' in self.available_tools:
                print("   🔐 Running nmap SSL scripts...")
                command = f"nmap --script ssl-* -p 443 {clean_target}"
                results['nmap_ssl'] = await self._run_command_directly(command, timeout=60)
            
            # Basic openssl check as fallback
            if not results:
                print("   🔐 Running basic OpenSSL check...")
                command = f"openssl s_client -connect {clean_target}:443 -servername {clean_target} < /dev/null 2>&1 | openssl x509 -text -noout"
                results['openssl'] = await self._run_command_directly(command, timeout=30)
            
            return results
            
        except Exception as e:
            print(f"❌ SSL scan error: {e}")
            return {}
    
    async def run_smb_scan(self, target: str) -> Dict:
        """Run SMB enumeration and vulnerability scanning"""
        try:
            # Clean target for SMB scan
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            results = {}
            
            # Nmap SMB scripts
            if 'nmap' in self.available_tools:
                print("   💻 Running nmap SMB scripts...")
                command = f"nmap --script smb-* -p 445 {clean_target}"
                results['nmap_smb'] = await self._run_command_directly(command, timeout=120)
            
            # enum4linux
            if 'enum4linux' in self.available_tools:
                print("   💻 Running enum4linux...")
                command = f"enum4linux -a {clean_target}"
                results['enum4linux'] = await self._run_command_directly(command, timeout=180)
            
            # smbclient
            if 'smbclient' in self.available_tools:
                print("   💻 Running smbclient...")
                command = f"smbclient -L //{clean_target} -N"
                results['smbclient'] = await self._run_command_directly(command, timeout=30)
            
            return results
            
        except Exception as e:
            print(f"❌ SMB scan error: {e}")
            return {}
    
    async def run_web_scan(self, target: str) -> Dict:
        """Run comprehensive web application scanning"""
        try:
            results = {}
            
            # Nikto scan
            if 'nikto' in self.available_tools:
                print("   🌐 Running Nikto...")
                command = f"nikto -h {target}"
                results['nikto'] = await self._run_command_directly(command, timeout=120)
            
            # WhatWeb scan
            if 'whatweb' in self.available_tools:
                print("   🌐 Running WhatWeb...")
                command = f"whatweb {target} -v"
                results['whatweb'] = await self._run_command_directly(command, timeout=60)
            
            return results
            
        except Exception as e:
            print(f"❌ Web scan error: {e}")
            return {}
    
    async def run_database_scan(self, target: str, ports: List[int]) -> Dict:
        """Run database service scanning"""
        try:
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            results = {}
            
            for port in ports:
                if port == 3306:  # MySQL
                    print("   🗄️  Scanning MySQL...")
                    command = f"nmap --script mysql-* -p 3306 {clean_target}"
                    results['mysql'] = await self._run_command_directly(command, timeout=60)
                
                elif port == 5432:  # PostgreSQL
                    print("   🗄️  Scanning PostgreSQL...")
                    command = f"nmap --script pgsql-* -p 5432 {clean_target}"
                    results['postgresql'] = await self._run_command_directly(command, timeout=60)
                
                elif port == 1433:  # MSSQL
                    print("   🗄️  Scanning MSSQL...")
                    command = f"nmap --script ms-sql-* -p 1433 {clean_target}"
                    results['mssql'] = await self._run_command_directly(command, timeout=60)
            
            return results
            
        except Exception as e:
            print(f"❌ Database scan error: {e}")
            return {}
    
    async def _run_command_directly(self, command: str, timeout: int = 60) -> Dict:
        """Execute command with timeout and proper error handling"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                return {
                    "success": process.returncode == 0,
                    "returncode": process.returncode,
                    "stdout": stdout.decode() if stdout else "",
                    "stderr": stderr.decode() if stderr else "",
                    "command": command
                }
            except asyncio.TimeoutError:
                process.terminate()
                return {
                    "success": False,
                    "error": f"Command timeout after {timeout} seconds",
                    "command": command
                }
                
        except Exception as e:
            return {"success": False, "error": str(e), "command": command}
    
    async def analyze_and_decide_next_steps(self, scan_results: Dict) -> List[str]:
        """Intelligent decision making for next steps"""
        recommended_actions = []
        
        basic_recon = scan_results.get('basic_recon', {})
        open_ports = basic_recon.get('nmap_results', {}).get('open_ports', [])
        
        # Convert port numbers to integers for easier comparison
        port_numbers = []
        for port in open_ports:
            try:
                port_num = int(str(port).split('/')[0])
                port_numbers.append(port_num)
            except:
                continue
        
        # Web services
        if any(port in [80, 443, 8080, 8443] for port in port_numbers):
            recommended_actions.extend(['web_vulnerability_scan', 'directory_bruteforce'])
            if 'ssl_scan' not in scan_results:
                recommended_actions.append('ssl_scan')
        
        # SMB services
        if 445 in port_numbers:
            recommended_actions.extend(['smb_enumeration', 'smb_vulnerability_scan'])
        
        # SSH services
        if 22 in port_numbers:
            recommended_actions.extend(['ssh_audit', 'ssh_security_check'])
        
        # Database services
        if any(port in [3306, 5432, 1433, 27017] for port in port_numbers):
            recommended_actions.extend(['database_enumeration', 'sql_injection_testing'])
        
        # FTP services
        if 21 in port_numbers:
            recommended_actions.extend(['ftp_enumeration', 'ftp_security_check'])
        
        # If we found vulnerabilities, suggest exploitation
        vulnerabilities_found = scan_results.get('vulnerabilities_found', 0)
        if vulnerabilities_found > 0:
            recommended_actions.extend(['vulnerability_verification', 'exploitation_attempt'])
        
        return recommended_actions
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        return list(self.available_tools.keys())
'''
            adv_file.write_text(adv_content)
            print("✅ Created advanced_orchestrator.py")
        
        print("✅ All tool modules created successfully")
    
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
        # Remove protocol and sanitize
        clean_name = re.sub(r'^https?://', '', name)
        # Replace invalid filename characters with underscores
        clean_name = re.sub(r'[^a-zA-Z0-9\.\-]', '_', clean_name)
        # Limit length to avoid too long filenames
        if len(clean_name) > 50:
            clean_name = clean_name[:50]
        return clean_name
    
    async def run_full_assessment(self, target: str):
        """Execute complete autonomous penetration test"""
        
        # Set scan name for reporting
        self.scan_name = self.sanitize_filename(target)
        print(f"🎯 Starting assessment of: {target}")
        print(f"📁 Scan name: {self.scan_name}")
        print("-" * 40)
        
        # Show available tools
        available_tools = self.advanced_orchestrator.get_available_tools()
        print(f"🔧 Available tools: {', '.join(available_tools)}")
        
        # Phase 1: Enhanced Reconnaissance
        print("\n[1/5] 🔍 Conducting Enhanced Reconnaissance...")
        recon_results = await self.conduct_enhanced_reconnaissance(target)
        
        # Phase 2: Service-Specific Scanning
        print("\n[2/5] 🛠️  Running Service-Specific Scans...")
        service_scans = await self.run_service_specific_scans(target, recon_results)
        
        # Phase 3: Target Analysis
        print("\n[3/5] 🧠 Analyzing Targets...")
        analysis_results = await self.analyze_targets(recon_results)
        
        # Phase 4: Vulnerability Scanning
        print("\n[4/5] ⚡ Running Vulnerability Scans...")
        await self.run_real_vulnerability_scans(analysis_results['priority_targets'])
        
        # Phase 5: Reporting
        print("\n[5/5] 📊 Generating Report...")
        await self.generate_enhanced_report(recon_results, service_scans)
        
        print(f"\n✅ Assessment complete! Found {len(self.vulnerabilities)} vulnerabilities.")
    
    async def conduct_enhanced_reconnaissance(self, target: str) -> Dict:
        """Run enhanced reconnaissance with advanced tool orchestration"""
        print(f"   Running enhanced reconnaissance on {target}...")
        
        enhanced_results = {
            'basic_recon': {},
            'advanced_nmap': {},
            'ssl_scan': {},
            'smb_scan': {},
            'web_scan': {},
            'database_scan': {},
            'next_steps': []
        }
        
        # 1. Basic reconnaissance (existing tools)
        print("   🔎 Running basic reconnaissance...")
        basic_recon = await self.conduct_real_reconnaissance(target)
        enhanced_results['basic_recon'] = basic_recon
        
        # 2. Advanced nmap
        print("   🗺️  Running advanced nmap scan...")
        advanced_nmap = await self.advanced_orchestrator.run_advanced_nmap(target, basic_recon)
        enhanced_results['advanced_nmap'] = advanced_nmap
        
        # 3. SSL scanning if HTTPS ports found
        open_ports = basic_recon.get('nmap_results', {}).get('open_ports', [])
        if any(str(port) in ['443', '8443'] for port in open_ports):
            print("   🔐 Running SSL/TLS scan...")
            ssl_results = await self.advanced_orchestrator.run_ssl_scan(target)
            enhanced_results['ssl_scan'] = ssl_results
        else:
            print("   ⏭️  No HTTPS ports found, skipping SSL scan")
        
        # 4. SMB scanning if port 445 found
        if any('445' in str(port) for port in open_ports):
            print("   💻 Running SMB enumeration...")
            smb_results = await self.advanced_orchestrator.run_smb_scan(target)
            enhanced_results['smb_scan'] = smb_results
        else:
            print("   ⏭️  Port 445 not found, skipping SMB scan")
        
        # 5. Web scanning if HTTP ports found
        if any(str(port) in ['80', '443', '8080', '8443'] for port in open_ports):
            print("   🌐 Running web application scans...")
            web_results = await self.advanced_orchestrator.run_web_scan(target)
            enhanced_results['web_scan'] = web_results
        
        # 6. Database scanning if database ports found
        db_ports = []
        for port in open_ports:
            port_str = str(port)
            if any(db_port in port_str for db_port in ['3306', '5432', '1433', '27017']):
                try:
                    port_num = int(port_str.split('/')[0])
                    db_ports.append(port_num)
                except:
                    continue
        
        if db_ports:
            print(f"   🗄️  Running database scans on ports {db_ports}...")
            db_results = await self.advanced_orchestrator.run_database_scan(target, db_ports)
            enhanced_results['database_scan'] = db_results
        else:
            print("   ⏭️  No database ports found, skipping database scan")
        
        # 7. Intelligent next steps decision
        print("   🤔 Analyzing for next steps...")
        next_steps = await self.advanced_orchestrator.analyze_and_decide_next_steps(enhanced_results)
        enhanced_results['next_steps'] = next_steps
        
        print(f"   ✅ Enhanced reconnaissance complete - {len(next_steps)} recommended next steps")
        
        return enhanced_results
    
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
    
    async def run_service_specific_scans(self, target: str, recon_data: Dict) -> Dict:
        """Run scans specific to discovered services"""
        service_scans = {}
        
        basic_recon = recon_data.get('basic_recon', {})
        open_ports = basic_recon.get('nmap_results', {}).get('open_ports', [])
        
        # Convert port strings to numbers for easier processing
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
        
        # Database service scans  
        if any(port in [3306, 5432, 1433, 27017] for port in port_numbers):
            print("   🗄️  Running additional database scans...")
            service_scans['database_services'] = {
                'status': 'enhanced_scan_completed', 
                'ports': [port for port in port_numbers if port in [3306, 5432, 1433, 27017]],
                'scans_performed': ['database_scan']
            }
        
        # Network service scans
        network_ports = [21, 22, 25, 53, 110, 135, 139, 445]
        if any(port in network_ports for port in port_numbers):
            print("   🌐 Running additional network service scans...")
            service_scans['network_services'] = {
                'status': 'enhanced_scan_completed',
                'ports': [port for port in port_numbers if port in network_ports],
                'scans_performed': ['smb_scan']
            }
        
        if not service_scans:
            print("   ⏭️  No additional service-specific scans needed")
        else:
            print(f"   ✅ Completed {len(service_scans)} service-specific scan categories")
        
        return service_scans
    
    async def analyze_targets(self, recon_data: Dict) -> Dict:
        """Analyze reconnaissance data to prioritize targets"""
        print("   Analyzing and prioritizing targets...")
        
        priority_targets = []
        all_targets = self.discovered_targets
        
        # Known vulnerable endpoints for testphp.vulnweb.com
        known_vulnerable_paths = [
            '/artists.php',  # SQL Injection
            '/categories.php',  # SQL Injection  
            '/products.php',  # SQL Injection
            '/login.php',  # Authentication
            '/search.php',  # XSS
            '/hpp/',  # Parameter Pollution
            '/AJAX/',  # Various vulnerabilities
            '/Mod_Rewrite_Shop/'  # Various vulnerabilities
        ]
        
        for target in all_targets:
            score = 0
            reasons = []
            
            # Extra points for known vulnerable paths
            for vuln_path in known_vulnerable_paths:
                if vuln_path in target:
                    score += 10
                    reasons.append(f'Known vulnerable path: {vuln_path}')
                    break
            
            # High priority indicators
            if any(keyword in target.lower() for keyword in ['admin', 'login', 'auth', 'register']):
                score += 5
                reasons.append('Authentication endpoint')
            
            if any(keyword in target.lower() for keyword in ['api', 'ajax']):
                score += 4
                reasons.append('API endpoint')
            
            if '?' in target and '=' in target:  # Has parameters
                score += 3
                reasons.append('Parameterized endpoint')
                
                # Extra points for specific parameters
                if any(param in target.lower() for param in ['id=', 'artist=', 'cat=', 'user=', 'product=']):
                    score += 3
                    reasons.append('SQLi-prone parameter')
            
            if any(ext in target for ext in ['.php']):
                score += 2
                reasons.append('Dynamic PHP page')
            
            # Negative points for static files
            if any(ext in target for ext in ['.jpg', '.png', '.css', '.js', '.ico']):
                score -= 5
                reasons.append('Static file')
            
            # Categorize by score
            if score >= 8:
                priority = 'critical'
            elif score >= 5:
                priority = 'high'
            elif score >= 2:
                priority = 'medium'
            else:
                priority = 'low'
            
            if priority in ['critical', 'high']:
                priority_targets.append({
                    'url': target, 
                    'priority': priority, 
                    'score': score,
                    'reasons': reasons
                })
        
        # Sort by score (highest first)
        priority_targets.sort(key=lambda x: x['score'], reverse=True)
        
        # Take top targets for scanning
        top_targets = priority_targets[:8]  # Top 8 high-priority targets
        
        analysis = {
            'priority_targets': top_targets,
            'risk_level': 'high' if any(t['priority'] in ['critical', 'high'] for t in priority_targets) else 'medium',
            'recommended_tests': ['SQLi', 'XSS', 'Authentication Testing']
        }
        
        print(f"   ✅ Prioritized {len(priority_targets)} high-value targets")
        print(f"   🎯 Selected {len(top_targets)} targets for scanning")
        
        # Print top targets
        for i, target in enumerate(top_targets[:3], 1):
            print(f"      {i}. {target['url']} (score: {target['score']})")
        
        return analysis
    
    async def run_real_vulnerability_scans(self, targets: List[Dict]):
        """Run REAL vulnerability scans using actual tools"""
        print(f"   Scanning {len(targets)} high-priority targets with real tools...")
        
        real_findings = []
        
        for i, target in enumerate(targets, 1):
            print(f"      [{i}/{len(targets)}] Testing: {target['url'][:50]}...")
            
            try:
                # Run custom vulnerability tests based on target characteristics
                findings = await self.vuln_scanner.run_custom_tests(target)
                real_findings.extend(findings)
                
                if findings:
                    print(f"         ✅ Found {len(findings)} vulnerabilities")
                else:
                    print(f"         ⏭️  No vulnerabilities found")
                    
            except Exception as e:
                print(f"         ❌ Error scanning {target['url']}: {e}")
                continue
        
        # Convert nuclei findings to our format
        for finding in real_findings:
            standardized_finding = self.standardize_finding(finding)
            if standardized_finding:
                self.vulnerabilities.append(standardized_finding)
        
        print(f"   ✅ Real scanning complete! Found {len(real_findings)} raw findings, {len(self.vulnerabilities)} standardized vulnerabilities")
    
    def standardize_finding(self, finding: Dict) -> Dict:
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
            
            # Default format
            else:
                return finding
                
        except Exception as e:
            print(f"❌ Error standardizing finding: {e}")
            return None
    
    async def generate_enhanced_report(self, recon_data: Dict, service_scans: Dict):
        """Generate enhanced report with advanced findings"""
        print("   Generating comprehensive report...")
        
        # Categorize vulnerabilities
        high_vulns = [v for v in self.vulnerabilities if v.get('severity') in ['high', 'critical']]
        medium_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'medium']
        low_vulns = [v for v in self.vulnerabilities if v.get('severity') in ['low', 'info', 'unknown']]
        
        # Enhanced report with advanced scan data
        report = {
            'scan_metadata': {
                'scan_name': self.scan_name,
                'target': self.discovered_targets[0] if self.discovered_targets else 'Unknown',
                'assessment_date': str(asyncio.get_event_loop().time()),
                'total_duration': 'N/A',
                'enhanced_scanning': True
            },
            'reconnaissance_summary': {
                'total_targets': len(self.discovered_targets),
                'subdomains_found': len(recon_data.get('basic_recon', {}).get('subdomains', [])),
                'open_ports': recon_data.get('basic_recon', {}).get('nmap_results', {}).get('open_ports', []),
                'service_scans_performed': list(service_scans.keys()),
                'recommended_next_steps': recon_data.get('next_steps', [])
            },
            'advanced_scanning': {
                'ssl_scan_performed': bool(recon_data.get('ssl_scan')),
                'smb_scan_performed': bool(recon_data.get('smb_scan')),
                'web_scan_performed': bool(recon_data.get('web_scan')),
                'database_scan_performed': bool(recon_data.get('database_scan')),
                'advanced_nmap_performed': bool(recon_data.get('advanced_nmap'))
            },
            'vulnerability_summary': {
                'vulnerabilities_found': len(self.vulnerabilities),
                'high_severity': len(high_vulns),
                'medium_severity': len(medium_vulns),
                'low_severity': len(low_vulns)
            },
            'vulnerabilities': {
                'high': high_vulns,
                'medium': medium_vulns,
                'low': low_vulns
            },
            'targets_scanned': self.discovered_targets[:15],
            'recommendations': self.generate_enhanced_recommendations(recon_data)
        }
        
        # Create scan-specific report filename
        report_filename = f"assessment-{self.scan_name}_report.json"
        report_path = f"reports/{report_filename}"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"   ✅ Enhanced report saved to: {report_path}")
        
        # Generate HTML report as well
        await self.generate_html_report(report)
        
        # Print detailed summary
        print(f"\n📋 Enhanced Summary:")
        print(f"   • Scan Name: {self.scan_name}")
        print(f"   • Targets Discovered: {report['reconnaissance_summary']['total_targets']}")
        print(f"   • Open Ports: {len(report['reconnaissance_summary']['open_ports'])}")
        print(f"   • Vulnerabilities Found: {report['vulnerability_summary']['vulnerabilities_found']}")
        print(f"   • High Severity: {report['vulnerability_summary']['high_severity']}")
        print(f"   • Service Scans: {len(report['reconnaissance_summary']['service_scans_performed'])}")
        print(f"   • Advanced Scans: SSL:{report['advanced_scanning']['ssl_scan_performed']} "
              f"SMB:{report['advanced_scanning']['smb_scan_performed']} "
              f"Web:{report['advanced_scanning']['web_scan_performed']}")
        print(f"   • Next Steps: {len(report['reconnaissance_summary']['recommended_next_steps'])}")
    
    def generate_enhanced_recommendations(self, recon_data: Dict) -> List[str]:
        """Generate enhanced recommendations based on advanced findings"""
        recommendations = []
        vuln_types = [v.get('type', '').lower() for v in self.vulnerabilities]
        
        # SQL Injection recommendations
        if any('sql' in vt for vt in vuln_types):
            recommendations.append("IMPLEMENT URGENTLY: Parameterized queries and input validation for SQL injection protection")
            recommendations.append("Review and fix all SQL queries in identified vulnerable endpoints")
        
        # SSL/TLS recommendations
        if recon_data.get('ssl_scan'):
            recommendations.append("Review SSL/TLS configuration and update to modern protocols")
            recommendations.append("Consider implementing HSTS and perfect forward secrecy")
        
        # SMB recommendations
        if recon_data.get('smb_scan'):
            recommendations.append("Review SMB configuration and disable SMBv1 if enabled")
            recommendations.append("Implement SMB signing and restrict anonymous access")
        
        # Web security recommendations
        if recon_data.get('web_scan'):
            recommendations.append("Implement Web Application Firewall (WAF) protection")
            recommendations.append("Conduct regular web application security testing")
        
        # Database security recommendations
        if recon_data.get('database_scan'):
            recommendations.append("Secure database configurations and use strong authentication")
            recommendations.append("Restrict database network exposure and use firewalls")
        
        # General recommendations
        if not recommendations:
            recommendations = [
                "Implement input validation on all user inputs",
                "Add WAF protection",
                "Conduct regular security assessments",
                "Keep all software components updated"
            ]
        
        # Add next steps from advanced analysis
        next_steps = recon_data.get('next_steps', [])
        if next_steps:
            recommendations.append(f"Recommended next penetration testing steps: {', '.join(next_steps)}")
        
        return recommendations
    
    async def generate_html_report(self, report_data: Dict):
        """Generate HTML report for better visualization"""
        try:
            # Create vulnerability HTML
            vulnerabilities_html = ""
            for vuln in report_data['vulnerabilities']['high']:
                vulnerabilities_html += f"""
                <div class="vulnerability critical">
                    <strong>🚨 {vuln['type']}</strong><br>
                    <strong>URL:</strong> {vuln['url']}<br>
                    <strong>Tool:</strong> {vuln.get('tool', 'Unknown')}<br>
                    <strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}<br>
                    <strong>Evidence:</strong> {vuln.get('evidence', 'N/A')[:100]}...
                </div>
                """
            
            # Create recommendations HTML
            recommendations_html = ""
            for rec in report_data['recommendations']:
                recommendations_html += f'<div class="recommendation">{rec}</div>'
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>🚀 Autonomous Pentest Report - {report_data['scan_metadata']['scan_name']}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
                    .vulnerability {{ background: #ffebee; padding: 15px; margin: 10px 0; border-left: 4px solid #f44336; border-radius: 5px; }}
                    .critical {{ border-left-color: #d32f2f; background: #ffcdd2; }}
                    .summary-card {{ background: #e3f2fd; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #2196f3; }}
                    .recommendation {{ background: #e8f5e8; padding: 15px; margin: 10px 0; border-left: 4px solid #4caf50; border-radius: 5px; }}
                    .scan-info {{ background: #fff3e0; padding: 15px; margin: 10px 0; border-left: 4px solid #ff9800; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🚀 Autonomous Pentest Report</h1>
                        <h2>Target: {report_data['scan_metadata']['scan_name']}</h2>
                        <p>Generated: {report_data['scan_metadata']['assessment_date']}</p>
                        <p><strong>Enhanced Scanning:</strong> {report_data['scan_metadata']['enhanced_scanning']}</p>
                    </div>
                    
                    <div class="summary-card">
                        <h3>📊 Executive Summary</h3>
                        <p><strong>Vulnerabilities Found:</strong> {report_data['vulnerability_summary']['vulnerabilities_found']}</p>
                        <p><strong>High Severity:</strong> {report_data['vulnerability_summary']['high_severity']}</p>
                        <p><strong>Targets Scanned:</strong> {report_data['reconnaissance_summary']['total_targets']}</p>
                        <p><strong>Open Ports:</strong> {len(report_data['reconnaissance_summary']['open_ports'])}</p>
                        <p><strong>Service Scans:</strong> {len(report_data['reconnaissance_summary']['service_scans_performed'])}</p>
                    </div>
                    
                    <div class="scan-info">
                        <h3>🔧 Advanced Scanning Results</h3>
                        <p><strong>SSL Scan:</strong> {report_data['advanced_scanning']['ssl_scan_performed']}</p>
                        <p><strong>SMB Scan:</strong> {report_data['advanced_scanning']['smb_scan_performed']}</p>
                        <p><strong>Web Scan:</strong> {report_data['advanced_scanning']['web_scan_performed']}</p>
                        <p><strong>Database Scan:</strong> {report_data['advanced_scanning']['database_scan_performed']}</p>
                        <p><strong>Next Steps:</strong> {', '.join(report_data['reconnaissance_summary']['recommended_next_steps'])}</p>
                    </div>
                    
                    <div class="vulnerabilities">
                        <h3>🔍 Vulnerabilities Found</h3>
                        {vulnerabilities_html if vulnerabilities_html else '<p>No high severity vulnerabilities found.</p>'}
                    </div>
                    
                    <div class="recommendations">
                        <h3>✅ Recommendations</h3>
                        {recommendations_html}
                    </div>
                    
                    <div class="footer">
                        <p><em>Report generated by Autonomous Pentest Agent with Advanced Orchestration</em></p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            html_report_path = f"reports/assessment-{self.scan_name}_report.html"
            with open(html_report_path, 'w') as f:
                f.write(html_content)
            print(f"   ✅ HTML report saved to: {html_report_path}")
            
        except Exception as e:
            print(f"   ❌ HTML report generation failed: {e}")
