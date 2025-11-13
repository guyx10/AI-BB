#!/usr/bin/env python3
import asyncio
import json
import subprocess
from typing import Dict, List, Any

class AdvancedOrchestrator:
    """Advanced tool orchestration with comprehensive service detection"""
    
    def __init__(self):
        self.available_tools = self._discover_tools()
        print(f"🔧 Discovered {len(self.available_tools)} security tools")
    
    def _discover_tools(self) -> Dict:
        """Auto-discover available security tools"""
        tools = {}
        common_tools = [
            'nmap', 'sslscan', 'testssl.sh', 'enum4linux', 'smbclient',
            'sqlmap', 'nuclei', 'ffuf', 'gobuster', 'dirb', 'nikto',
            'whatweb', 'wapiti', 'skipfish', 'metasploit', 'nc', 'ftp'
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
    
    def _detect_services_from_ports(self, open_ports: List) -> Dict[str, List]:
        """Comprehensive service detection from nmap port results"""
        services = {
            'web': [], 'ftp': [], 'ssh': [], 'database': [], 
            'smb': [], 'email': [], 'dns': [], 'misc': []
        }
        
        # Comprehensive service-port mapping
        service_mappings = {
            'web': [
                # Standard web ports
                ('80', 'http'), ('443', 'https'), ('8080', 'http-alt'), ('8443', 'https-alt'),
                ('8000', 'http-alt'), ('8888', 'http-alt'), ('9080', 'websphere'),
                ('9090', 'websm'), ('7443', 'oracle-https'), ('9443', 'tungsten-https'),
                # Common web service names
                'http', 'https', 'http-alt', 'https-alt', 'www', 'www-http', 'web'
            ],
            'ftp': [
                # FTP ports and variations
                ('21', 'ftp'), ('2121', 'ftp'), ('2121', 'cient'), ('2021', 'ftp'),
                ('8021', 'ftp'), ('990', 'ftps'), ('989', 'ftps-data'),
                # FTP service names
                'ftp', 'ftps', 'ftp-data'
            ],
            'ssh': [
                # SSH ports and variations
                ('22', 'ssh'), ('2222', 'ssh'), ('222', 'ssh'), ('22222', 'ssh'),
                ('2221', 'ssh'), ('2200', 'ssh'), ('2299', 'ssh'),
                # SSH service names
                'ssh', 'sshl', 'secure-shell'
            ],
            'database': [
                # Database ports
                ('3306', 'mysql'), ('5432', 'postgresql'), ('1433', 'mssql'), 
                ('1521', 'oracle'), ('27017', 'mongodb'), ('6379', 'redis'),
                ('5984', 'couchdb'), ('9200', 'elasticsearch'), ('9300', 'elasticsearch'),
                # Database service names
                'mysql', 'postgresql', 'postgres', 'mssql', 'oracle', 'mongodb',
                'redis', 'couchdb', 'elasticsearch'
            ],
            'smb': [
                # SMB/NetBIOS ports
                ('445', 'microsoft-ds'), ('139', 'netbios-ssn'), ('135', 'msrpc'),
                # SMB service names
                'microsoft-ds', 'netbios-ssn', 'msrpc', 'smb', 'samba'
            ],
            'email': [
                # Email ports
                ('25', 'smtp'), ('587', 'smtp'), ('465', 'smtps'), ('110', 'pop3'),
                ('995', 'pop3s'), ('143', 'imap'), ('993', 'imaps'),
                # Email service names
                'smtp', 'smtps', 'pop3', 'pop3s', 'imap', 'imaps'
            ],
            'dns': [
                # DNS ports
                ('53', 'domain'), ('5353', 'zeroconf'),
                # DNS service names
                'domain', 'dns', 'zeroconf'
            ],
            'misc': [
                # Other important services
                ('23', 'telnet'), ('69', 'tftp'), ('161', 'snmp'), ('162', 'snmptrap'),
                ('389', 'ldap'), ('636', 'ldaps'), ('1433', 'ms-sql-s'),
                ('3389', 'rdp'), ('5900', 'vnc'), ('5901', 'vnc-1')
            ]
        }
        
        for port_entry in open_ports:
            port_str = str(port_entry)
            
            # Parse port/service combination (e.g., "2121/ftp" or "8443/https-alt")
            port_num = port_str.split('/')[0] if '/' in port_str else port_str
            service_name = port_str.split('/')[1].lower() if '/' in port_str else 'unknown'
            
            # Check each service category
            found = False
            for category, mappings in service_mappings.items():
                for mapping in mappings:
                    if isinstance(mapping, tuple):
                        # Check both port and service name
                        if port_num == mapping[0] or service_name == mapping[1]:
                            services[category].append({
                                'port': port_num,
                                'service': service_name,
                                'original': port_entry
                            })
                            found = True
                            break
                    else:
                        # Check service name only
                        if service_name == mapping:
                            services[category].append({
                                'port': port_num,
                                'service': service_name,
                                'original': port_entry
                            })
                            found = True
                            break
                if found:
                    break
            
            # If no specific service found, add to misc with analysis
            if not found and service_name != 'unknown':
                services['misc'].append({
                    'port': port_num,
                    'service': service_name,
                    'original': port_entry
                })
        
        return services

    def _extract_port_numbers(self, open_ports: List) -> List[int]:
        """Extract just port numbers from nmap results"""
        port_numbers = []
        for port_entry in open_ports:
            port_str = str(port_entry)
            try:
                port_num = int(port_str.split('/')[0])
                port_numbers.append(port_num)
            except (ValueError, IndexError):
                continue
        return port_numbers

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
            else:
                # Use service detection to determine focus
                services_found = self._detect_services_from_ports(open_ports)
                
                if services_found['web']:
                    # Web services found, focus on web enumeration
                    web_ports = [s['port'] for s in services_found['web']]
                    port_range = ','.join(web_ports)
                    command = f"nmap -sS -sV --script http-* -p {port_range} {clean_target}"
                    print(f"   🌐 Running web-focused nmap scan on ports {port_range}...")
                elif services_found['ssh'] or services_found['ftp']:
                    # Network services found
                    network_ports = [s['port'] for s in services_found['ssh'] + services_found['ftp']]
                    port_range = ','.join(network_ports[:10])  # Limit to first 10 ports
                    command = f"nmap -sS -sV --script banner -p {port_range} {clean_target}"
                    print(f"   🔌 Running network service nmap scan on ports {port_range}...")
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
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            return await self._run_command_directly(f"nmap -sS {clean_target}")
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse nmap output for structured data"""
        parsed = {
            'open_ports': [],
            'services': [],
            'os_guess': [],
            'vulnerabilities': []
        }
        
        for line in output.split('\n'):
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
            
            # Directory brute force
            if 'gobuster' in self.available_tools:
                print("   🌐 Running directory brute force...")
                command = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q"
                results['gobuster'] = await self._run_command_directly(command, timeout=180)
            
            return results
            
        except Exception as e:
            print(f"❌ Web scan error: {e}")
            return {}

    async def run_ftp_scan(self, target: str, ftp_services: List[Dict]) -> Dict:
        """Run FTP-specific scans on discovered FTP services"""
        results = {}
        clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        for ftp_service in ftp_services:
            port = ftp_service['port']
            service_name = ftp_service['service']
            print(f"   📁 Scanning {service_name} on port {port}...")
            
            # Nmap FTP scripts
            if 'nmap' in self.available_tools:
                cmd = f"nmap --script ftp-* -p {port} {clean_target}"
                results[f'nmap_ftp_{port}'] = await self._run_command_directly(cmd, timeout=60)
            
            # Try anonymous FTP login
            if 'ftp' in self.available_tools:
                anonymous_cmd = f"ftp -n {clean_target} {port} << EOF\nuser anonymous anonymous@example.com\nquit\nEOF"
                results[f'ftp_anonymous_{port}'] = await self._run_command_directly(anonymous_cmd, timeout=30)
            
            # Banner grabbing with netcat
            if 'nc' in self.available_tools:
                banner_cmd = f"echo 'QUIT' | nc -w 5 {clean_target} {port}"
                results[f'ftp_banner_{port}'] = await self._run_command_directly(banner_cmd, timeout=10)
        
        return results

    async def run_ssh_scan(self, target: str, ssh_services: List[Dict]) -> Dict:
        """Run SSH-specific scans on discovered SSH services"""
        results = {}
        clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        for ssh_service in ssh_services:
            port = ssh_service['port']
            service_name = ssh_service['service']
            print(f"   🔑 Scanning {service_name} on port {port}...")
            
            # Nmap SSH scripts
            if 'nmap' in self.available_tools:
                cmd = f"nmap --script ssh-* -p {port} {clean_target}"
                results[f'nmap_ssh_{port}'] = await self._run_command_directly(cmd, timeout=60)
            
            # SSH version scan
            if 'nc' in self.available_tools:
                banner_cmd = f"nc -w 5 {clean_target} {port} < /dev/null"
                results[f'ssh_banner_{port}'] = await self._run_command_directly(banner_cmd, timeout=10)
            
            # SSH security checks
            if 'nmap' in self.available_tools:
                security_cmd = f"nmap --script ssh2-enum-algos,ssh-hostkey -p {port} {clean_target}"
                results[f'ssh_security_{port}'] = await self._run_command_directly(security_cmd, timeout=30)
        
        return results
    
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
                
                elif port == 27017:  # MongoDB
                    print("   🗄️  Scanning MongoDB...")
                    command = f"nmap --script mongodb-* -p 27017 {clean_target}"
                    results['mongodb'] = await self._run_command_directly(command, timeout=60)
            
            return results
            
        except Exception as e:
            print(f"❌ Database scan error: {e}")
            return {}

    async def run_service_specific_scans_enhanced(self, target: str, services_found: Dict) -> Dict:
        """Run scans specific to discovered services"""
        service_scans = {}
        
        # Web service scans
        if services_found['web']:
            print("   🌐 Running enhanced web service scans...")
            web_results = await self.run_web_scan(target)
            service_scans['web_services'] = {
                'services': services_found['web'],
                'scans_performed': ['web_scan', 'ssl_scan'],
                'results': web_results
            }
        
        # FTP service scans
        if services_found['ftp']:
            print("   📁 Running FTP service scans...")
            ftp_results = await self.run_ftp_scan(target, services_found['ftp'])
            service_scans['ftp_services'] = {
                'services': services_found['ftp'],
                'scans_performed': ['ftp_enumeration', 'ftp_security_check'],
                'results': ftp_results
            }
        
        # SSH service scans
        if services_found['ssh']:
            print("   🔑 Running SSH service scans...")
            ssh_results = await self.run_ssh_scan(target, services_found['ssh'])
            service_scans['ssh_services'] = {
                'services': services_found['ssh'],
                'scans_performed': ['ssh_audit', 'ssh_security_check'],
                'results': ssh_results
            }
        
        # Database service scans
        if services_found['database']:
            db_ports = [int(s['port']) for s in services_found['database']]
            print("   🗄️  Running database service scans...")
            db_results = await self.run_database_scan(target, db_ports)
            service_scans['database_services'] = {
                'services': services_found['database'],
                'scans_performed': ['database_enumeration'],
                'results': db_results
            }
        
        # SMB service scans
        if services_found['smb']:
            print("   💻 Running SMB service scans...")
            smb_results = await self.run_smb_scan(target)
            service_scans['smb_services'] = {
                'services': services_found['smb'],
                'scans_performed': ['smb_enumeration'],
                'results': smb_results
            }
        
        return service_scans
    
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
        """Intelligent decision making with comprehensive service detection"""
        recommended_actions = []
        
        basic_recon = scan_results.get('basic_recon', {})
        nmap_results = basic_recon.get('nmap_results', {})
        open_ports = nmap_results.get('open_ports', [])
        
        # Comprehensive service detection
        services_found = self._detect_services_from_ports(open_ports)
        
        # Print service discovery summary
        print(f"   🔍 Comprehensive Service Discovery:")
        for category, services in services_found.items():
            if services:
                service_list = [f"{s['port']}/{s['service']}" for s in services]
                print(f"      • {category.upper()}: {', '.join(service_list)}")
        
        # Web services (any HTTP/HTTPS service)
        if services_found['web']:
            recommended_actions.extend(['web_vulnerability_scan', 'directory_bruteforce'])
            if any(service['service'] in ['https', 'https-alt'] for service in services_found['web']):
                if 'ssl_scan' not in scan_results:
                    recommended_actions.append('ssl_scan')
            print("   🌐 Web services detected - adding web application testing")
        
        # FTP services (any FTP service on any port)
        if services_found['ftp']:
            recommended_actions.extend(['ftp_enumeration', 'ftp_security_check'])
            print(f"   📁 FTP services detected on ports: {[s['port'] for s in services_found['ftp']]}")
        
        # SSH services (any SSH service on any port)
        if services_found['ssh']:
            recommended_actions.extend(['ssh_audit', 'ssh_security_check'])
            print(f"   🔑 SSH services detected on ports: {[s['port'] for s in services_found['ssh']]}")
        
        # Database services
        if services_found['database']:
            recommended_actions.extend(['database_enumeration', 'sql_injection_testing'])
            db_types = [s['service'] for s in services_found['database']]
            print(f"   🗄️  Database services detected: {', '.join(db_types)}")
        
        # SMB services
        if services_found['smb']:
            recommended_actions.extend(['smb_enumeration', 'smb_vulnerability_scan'])
            print("   💻 SMB services detected - adding network enumeration")
        
        # Email services
        if services_found['email']:
            recommended_actions.extend(['email_service_testing', 'smtp_enumeration'])
            print("   📧 Email services detected - adding email service testing")
        
        # DNS services
        if services_found['dns']:
            recommended_actions.extend(['dns_enumeration', 'dns_zone_transfer_test'])
            print("   🌐 DNS services detected - adding DNS enumeration")
        
        # Handle miscellaneous services
        if services_found['misc']:
            misc_services = [f"{s['port']}/{s['service']}" for s in services_found['misc']]
            print(f"   🔧 Miscellaneous services found: {', '.join(misc_services)}")
            recommended_actions.extend(['service_specific_scanning', 'banner_grabbing'])
        
        # If we found vulnerabilities, suggest exploitation
        vulnerabilities_found = scan_results.get('vulnerabilities_found', 0)
        if vulnerabilities_found > 0:
            recommended_actions.extend(['vulnerability_verification', 'exploitation_attempt'])
        
        # Remove duplicates
        recommended_actions = list(set(recommended_actions))
        
        print(f"   🎯 Recommended actions: {recommended_actions}")
        return recommended_actions
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        return list(self.available_tools.keys())