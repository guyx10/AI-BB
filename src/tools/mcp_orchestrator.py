#!/usr/bin/env python3
import asyncio
import json
import subprocess
from typing import Dict, List, Any

class MCPOrchestrator:
    """MCP-based tool orchestration for advanced penetration testing"""
    
    def __init__(self):
        self.tools_available = {}
        self.mcp_connected = False
    
    async def connect_to_villager(self):
        """Connect to Villager MCP server for Kali tools with better error handling"""
        try:
            # First check if villager is installed
            check_result = await self._run_command_directly("python -c \"import villager\"")
            if check_result.get('returncode') != 0:
                print("❌ Villager not installed - using direct tool execution")
                return False
            
            server_params = {
                "command": "python",
                "args": ["-m", "villager.mcp_server"]
            }
            
            # Try to connect to villager
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            
            stdio_params = StdioServerParameters(**server_params)
            
            async with stdio_client(stdio_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self.session = session
                    self.mcp_connected = True
                    print("✅ Connected to Villager MCP Server")
                    return True
                    
        except ImportError as e:
            print("❌ MCP libraries not installed - using direct tools")
            return False
        except Exception as e:
            print(f"❌ Failed to connect to Villager: {e}")
            return False
    
    async def run_advanced_nmap(self, target: str, previous_results: Dict) -> Dict:
        """Intelligent nmap scanning based on previous findings"""
        try:
            # Analyze previous results to determine scan intensity
            open_ports = previous_results.get('open_ports', [])
            
            if not open_ports:
                # No ports found, do comprehensive scan
                command = f"nmap -sS -sV -O -A -p- {target}"
            elif any(str(port) in ['80', '443', '8080', '8443'] for port in open_ports):
                # Web services found, focus on web enumeration
                command = f"nmap -sS -sV --script http-* -p 80,443,8080,8443 {target}"
            elif any(str(port) in ['21', '22', '25', '53', '110', '143'] for port in open_ports):
                # Network services found
                command = f"nmap -sS -sV --script banner -p 21,22,25,53,110,143 {target}"
            else:
                # Default comprehensive scan
                command = f"nmap -sS -sV -A {target}"
            
            if self.mcp_connected:
                result = await self.session.call_tool(
                    "nmap_scan",
                    {"target": target, "command": command}
                )
                return result
            else:
                # Fallback to direct execution
                print(f"   🛠️  Running direct: {command.split(' ')[0]}")
                return await self._run_command_directly(command)
                
        except Exception as e:
            print(f"❌ Advanced nmap error: {e}")
            return await self._run_command_directly(f"nmap -sS {target}")
    
    async def run_ssl_scan(self, target: str) -> Dict:
        """Run SSL/TLS vulnerability scanning"""
        try:
            # Clean target for SSL scan
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            commands = [
                f"sslscan {clean_target}",
                f"nmap --script ssl-* -p 443 {clean_target}",
                f"openssl s_client -connect {clean_target}:443 -servername {clean_target} < /dev/null"
            ]
            
            results = {}
            for cmd in commands:
                try:
                    if self.mcp_connected:
                        result = await self.session.call_tool(
                            "ssl_scan", 
                            {"target": clean_target, "tool": cmd.split()[0]}
                        )
                        results[cmd.split()[0]] = result
                    else:
                        print(f"   🛠️  Running direct: {cmd.split(' ')[0]}")
                        result = await self._run_command_directly(cmd)
                        results[cmd.split()[0]] = result
                except Exception as e:
                    continue
            
            return results
        except Exception as e:
            print(f"❌ SSL scan error: {e}")
            return {}
    
    async def run_smb_scan(self, target: str) -> Dict:
        """Run SMB enumeration and vulnerability scanning"""
        try:
            # Clean target for SMB scan
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            commands = [
                f"nmap --script smb-* -p 445 {clean_target}",
                f"enum4linux -a {clean_target}",
                f"smbclient -L //{clean_target} -N"
            ]
            
            results = {}
            for cmd in commands:
                try:
                    if self.mcp_connected:
                        result = await self.session.call_tool(
                            "smb_scan",
                            {"target": clean_target, "command": cmd}
                        )
                        results[cmd.split()[0]] = result
                    else:
                        print(f"   🛠️  Running direct: {cmd.split(' ')[0]}")
                        result = await self._run_command_directly(cmd)
                        results[cmd.split()[0]] = result
                except Exception as e:
                    continue
            
            return results
        except Exception as e:
            print(f"❌ SMB scan error: {e}")
            return {}
    
    async def run_metasploit_scan(self, target: str, service_info: Dict) -> Dict:
        """Run targeted Metasploit scans based on service discovery"""
        try:
            results = {}
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Web services
            if any(port in service_info.get('web_ports', []) for port in [80, 443, 8080, 8443]):
                msf_commands = [
                    f"use auxiliary/scanner/http/http_version",
                    f"set RHOSTS {clean_target}",
                    f"run"
                ]
                results['http_scan'] = await self._run_metasploit_module(msf_commands)
            
            # SMB services
            if 445 in service_info.get('open_ports', []):
                msf_commands = [
                    f"use auxiliary/scanner/smb/smb_version", 
                    f"set RHOSTS {clean_target}",
                    f"run"
                ]
                results['smb_scan'] = await self._run_metasploit_module(msf_commands)
            
            return results
        except Exception as e:
            print(f"❌ Metasploit scan error: {e}")
            return {}
    
    async def _run_metasploit_module(self, commands: List[str]) -> Dict:
        """Execute Metasploit module"""
        try:
            # Create a temporary rc file
            rc_file = "/tmp/msf_commands.rc"
            with open(rc_file, 'w') as f:
                for cmd in commands:
                    f.write(f"{cmd}\n")
            
            command = f"msfconsole -q -r {rc_file}"
            return await self._run_command_directly(command)
        except Exception as e:
            return {"error": str(e)}
    
    async def _run_command_directly(self, command: str, timeout: int = 60) -> Dict:
        """Fallback command execution with timeout"""
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
        """AI-powered decision making for next steps"""
        # Basic rule-based decisions
        recommended_actions = []
        
        basic_recon = scan_results.get('basic_recon', {})
        open_ports = basic_recon.get('nmap_results', {}).get('open_ports', [])
        
        # Web services
        if any(str(port) in ['80', '443', '8080', '8443'] for port in open_ports):
            recommended_actions.extend(['web_vulnerability_scan', 'directory_bruteforce', 'subdomain_enumeration'])
        
        # SMB services
        if any('445' in str(port) for port in open_ports):
            recommended_actions.extend(['smb_enumeration', 'smb_vulnerability_scan'])
        
        # SSH services
        if any('22' in str(port) for port in open_ports):
            recommended_actions.extend(['ssh_audit', 'ssh_bruteforce'])
        
        # Database services
        if any(str(port) in ['3306', '5432', '1433', '27017'] for port in open_ports):
            recommended_actions.extend(['database_enumeration', 'sql_injection_testing'])
        
        # If we found vulnerabilities, suggest exploitation
        if scan_results.get('vulnerabilities_found', 0) > 0:
            recommended_actions.extend(['vulnerability_exploitation', 'privilege_escalation_testing'])
        
        return recommended_actions
