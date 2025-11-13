#!/usr/bin/env python3
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
                subdomains = stdout.decode().strip().split('\n')
                valid_subdomains = [sd for sd in subdomains if sd and not sd.startswith('Error')]
                return valid_subdomains
            else:
                print(f"❌ Subfinder error: {stderr.decode()}")
                # Try alternative approach
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
                subdomains = stdout.decode().strip().split('\n')
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
                    f.write(f"{domain}\n")
        
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
                        live_domains = stdout.decode().strip().split('\n')
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
            for line in output.split('\n'):
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
                urls = stdout.decode().strip().split('\n')
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
                urls = stdout.decode().strip().split('\n')
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
            clean_domain = domain.replace('http://', '').replace('https://', '')
            cmd = f"katana -u http://{clean_domain} -silent -depth 2"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = stdout.decode().strip().split('\n')
                return [url for url in urls if url]
            else:
                print(f"❌ Katana error: {stderr.decode()}")
                return []
        except Exception as e:
            print(f"❌ Katana exception: {e}")
            return []
