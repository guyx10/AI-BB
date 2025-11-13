import subprocess
import asyncio
from typing import Dict, List

class ToolOrchestrator:
    """Orchestrates security tools execution"""
    
    async def run_command(self, command: str) -> Dict:
        """Run a shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'returncode': process.returncode
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def nmap_scan(self, target: str) -> Dict:
        """Run nmap scan"""
        command = f"nmap -sV {target}"
        return await self.run_command(command)
    
    async def subdomain_enum(self, domain: str) -> Dict:
        """Run subdomain enumeration"""
        command = f"subfinder -d {domain}"
        return await self.run_command(command)
