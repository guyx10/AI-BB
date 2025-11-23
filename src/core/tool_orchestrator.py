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


    def setup_vulnerability_tools(self):
        """Setup and configure vulnerability scanning tools"""
        tools = {}
        
        # Check for Nuclei
        if self.check_tool_available('nuclei'):
            tools['nuclei'] = {
                'command': 'nuclei',
                'version': self.get_tool_version('nuclei'),
                'enabled': True
            }
            self.logger.info("✅ Nuclei is available")
        else:
            self.logger.warning("❌ Nuclei not found. Installing...")
            self.install_nuclei()
        
        # Check for other tools...
        return tools

    def install_nuclei(self):
        """Install Nuclei if not available"""
        try:
            self.logger.info("📥 Installing Nuclei...")
            install_cmd = "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
            result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info("✅ Nuclei installed successfully")
                # Update templates
                update_cmd = "nuclei -update-templates"
                subprocess.run(update_cmd, shell=True, capture_output=True)
                self.logger.info("✅ Nuclei templates updated")
            else:
                self.logger.error(f"❌ Failed to install Nuclei: {result.stderr}")
        except Exception as e:
            self.logger.error(f"❌ Nuclei installation failed: {e}")