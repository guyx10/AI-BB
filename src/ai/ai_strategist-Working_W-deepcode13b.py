#!/usr/bin/env python3
"""
AI Strategist for Autonomous Pentest Agent
Enhanced with proper Ollama error handling
"""
import aiohttp
import json
import asyncio
from typing import Dict, Any, List
import logging

class AIStrategist:
    def __init__(self, config: Dict):
        self.config = config
        self.ai_config = config.get('ai', {})
        self.primary_provider = self.ai_config.get('primary_provider', 'ollama')
        self.local_model = self.ai_config.get('local_model', 'codellama:13b')
        self.temperature = self.ai_config.get('temperature', 0.1)
        self.max_tokens = self.ai_config.get('max_tokens', 4000)
        
        # Ollama configuration
        self.ollama_base_url = "http://localhost:11434"
        
        # DeepSeek configuration (if using API)
        self.deepseek_api_key = self.ai_config.get('deepseek_api_key', '')
        self.deepseek_base_url = "https://api.deepseek.com"
        
        self.session = None
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def check_ollama_availability(self) -> bool:
        """Check if Ollama is available and the model is loaded"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            # Check if Ollama service is running
            async with self.session.get(f"{self.ollama_base_url}/api/tags") as response:
                if response.status == 200:
                    data = await response.json()
                    models = data.get('models', [])
                    
                    # Check if our desired model is available
                    model_available = any(
                        model.get('name', '').startswith(self.local_model) 
                        for model in models
                    )
                    
                    if model_available:
                        print(f"✅ Ollama connected - Model '{self.local_model}' available")
                    else:
                        print(f"⚠️  Ollama connected but model '{self.local_model}' not found")
                        print(f"   Available models: {[m.get('name', '') for m in models]}")
                    
                    return model_available
                else:
                    print(f"❌ Ollama service error: {response.status}")
                    return False
                    
        except aiohttp.ClientError as e:
            print(f"❌ Cannot connect to Ollama: {e}")
            return False
        except Exception as e:
            print(f"❌ Ollama check error: {e}")
            return False

    async def analyze_scan_results(self, scan_data: Dict) -> Dict[str, Any]:
        """AI analysis of scan results with fallback to rule-based analysis"""
        try:
            # Try AI analysis first
            if await self.check_ollama_availability():
                ai_analysis = await self._analyze_with_ollama(scan_data)
                if ai_analysis:
                    return ai_analysis
            
            # Fallback to rule-based analysis
            return self._rule_based_analysis(scan_data)
            
        except Exception as e:
            print(f"❌ AI analysis failed, using rule-based: {e}")
            return self._rule_based_analysis(scan_data)

    async def _analyze_with_ollama(self, scan_data: Dict) -> Dict[str, Any]:
        """Analyze scan results using Ollama"""
        try:
            prompt = self._build_analysis_prompt(scan_data)
            
            payload = {
                "model": self.local_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                }
            }
            
            async with self.session.post(f"{self.ollama_base_url}/api/generate", json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    analysis_text = result.get('response', '')
                    return self._parse_ai_response(analysis_text, scan_data)
                else:
                    print(f"❌ Ollama API error: {response.status}")
                    return None
                    
        except Exception as e:
            print(f"❌ Ollama analysis error: {e}")
            return None

    def _build_analysis_prompt(self, scan_data: Dict) -> str:
        """Build prompt for AI analysis"""
        basic_recon = scan_data.get('basic_recon', {})
        vulnerabilities_found = scan_data.get('vulnerabilities_found', 0)
        services_detected = scan_data.get('services_detected', {})
        
        prompt = f"""As a cybersecurity expert, analyze these penetration testing results:

RECONNAISSANCE DATA:
- Subdomains discovered: {len(basic_recon.get('subdomains', []))}
- Live domains: {len(basic_recon.get('live_domains', []))}
- Open ports: {len(basic_recon.get('nmap_results', {}).get('open_ports', []))}
- Historical URLs: {len(basic_recon.get('endpoints', []))}
- Crawled URLs: {len(basic_recon.get('crawled_urls', []))}

SERVICES DETECTED:
{json.dumps(services_detected, indent=2)}

VULNERABILITIES FOUND: {vulnerabilities_found}

Please provide a structured analysis with:
1. Risk assessment (Low/Medium/High/Critical)
2. 3-5 immediate actions to take
3. Priority targets for further testing
4. Exploitation strategy
5. Key findings

Format your response as JSON:
{{
    "risk_assessment": "Medium",
    "immediate_actions": ["action1", "action2"],
    "priority_targets": ["url1", "url2"],
    "exploitation_strategy": "brief strategy",
    "key_findings": ["finding1", "finding2"]
}}

Provide only the JSON response:"""

        return prompt

    def _parse_ai_response(self, response_text: str, scan_data: Dict) -> Dict[str, Any]:
        """Parse AI response and extract structured data"""
        try:
            # Try to extract JSON from response
            lines = response_text.strip().split('\n')
            json_start = None
            json_end = None
            
            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    json_start = i
                if json_start is not None and line.strip().endswith('}'):
                    json_end = i + 1
                    break
            
            if json_start is not None and json_end is not None:
                json_text = '\n'.join(lines[json_start:json_end])
                ai_data = json.loads(json_text)
            else:
                # Fallback: try to parse the entire response
                ai_data = json.loads(response_text)
            
            # Ensure all required fields exist
            default_analysis = self._rule_based_analysis(scan_data)
            
            return {
                "risk_assessment": ai_data.get("risk_assessment", default_analysis["risk_assessment"]),
                "immediate_actions": ai_data.get("immediate_actions", default_analysis["immediate_actions"]),
                "priority_targets": ai_data.get("priority_targets", default_analysis["priority_targets"]),
                "exploitation_strategy": ai_data.get("exploitation_strategy", default_analysis["exploitation_strategy"]),
                "key_findings": ai_data.get("key_findings", default_analysis["key_findings"])
            }
            
        except json.JSONDecodeError:
            print("❌ Failed to parse AI response as JSON, using rule-based analysis")
            return self._rule_based_analysis(scan_data)
        except Exception as e:
            print(f"❌ Error parsing AI response: {e}")
            return self._rule_based_analysis(scan_data)

    def _rule_based_analysis(self, scan_data: Dict) -> Dict[str, Any]:
        """Rule-based fallback analysis when AI is unavailable"""
        basic_recon = scan_data.get('basic_recon', {})
        vulnerabilities_found = scan_data.get('vulnerabilities_found', 0)
        services_detected = scan_data.get('services_detected', {})
        
        # Determine risk level
        open_ports = basic_recon.get('nmap_results', {}).get('open_ports', [])
        web_services = services_detected.get('web', [])
        
        risk_level = "Low"
        if vulnerabilities_found > 5:
            risk_level = "High"
        elif vulnerabilities_found > 2:
            risk_level = "Medium"
        elif web_services or open_ports:
            risk_level = "Medium"
        
        # Priority targets (first 5 live domains)
        live_domains = basic_recon.get('live_domains', [])[:5]
        
        immediate_actions = [
            "Run comprehensive vulnerability scanning",
            "Test for SQL injection on parameterized URLs",
            "Check for XSS vulnerabilities",
            "Scan for exposed sensitive files",
            "Test authentication mechanisms"
        ]
        
        return {
            "risk_assessment": risk_level,
            "immediate_actions": immediate_actions,
            "priority_targets": live_domains,
            "exploitation_strategy": "Focus on web application testing and service enumeration",
            "key_findings": [
                f"Discovered {len(live_domains)} live targets",
                f"Found {len(open_ports)} open ports",
                f"Identified {vulnerabilities_found} potential vulnerabilities"
            ]
        }

    async def generate_executive_summary(self, report_data: Dict) -> Dict[str, Any]:
        """Generate AI-enhanced executive summary"""
        try:
            if await self.check_ollama_availability():
                prompt = self._build_executive_summary_prompt(report_data)
                
                payload = {
                    "model": self.local_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # More creative for summaries
                        "num_predict": 2000
                    }
                }
                
                async with self.session.post(f"{self.ollama_base_url}/api/generate", json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        summary_text = result.get('response', '')
                        return self._parse_executive_summary(summary_text, report_data)
            
            # Fallback to basic summary
            return self._generate_basic_executive_summary(report_data)
            
        except Exception as e:
            print(f"❌ AI executive summary failed: {e}")
            return self._generate_basic_executive_summary(report_data)

    def _build_executive_summary_prompt(self, report_data: Dict) -> str:
        """Build prompt for executive summary"""
        summary = report_data.get('summary', {})
        vulnerabilities = report_data.get('vulnerabilities', [])
        
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        
        prompt = f"""Create an executive summary for a penetration test report:

TARGET: {report_data.get('target', 'Unknown')}
TOTAL VULNERABILITIES: {summary.get('total_vulnerabilities', 0)}
- Critical: {len(critical_vulns)}
- High: {len(high_vulns)}
- Medium: {summary.get('medium_count', 0)}
- Low: {summary.get('low_count', 0)}

Provide a concise executive summary suitable for management, including:
1. Overall risk assessment
2. Key security findings
3. Business impact
4. Top recommendations

Format as JSON:
{{
    "executive_summary": "2-3 paragraph summary",
    "overall_risk": "Low/Medium/High/Critical",
    "key_findings": ["finding1", "finding2"],
    "recommendations": ["rec1", "rec2"],
    "remediation_recommendations": {{"VulnerabilityType": "Remediation advice"}}
}}

Provide only the JSON response:"""

        return prompt

    def _parse_executive_summary(self, response_text: str, report_data: Dict) -> Dict[str, Any]:
        """Parse executive summary response"""
        try:
            # Extract JSON from response
            lines = response_text.strip().split('\n')
            json_text = None
            
            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    json_text = '\n'.join(lines[i:])
                    break
            
            if json_text:
                ai_summary = json.loads(json_text)
            else:
                ai_summary = json.loads(response_text)
            
            # Merge with basic summary as fallback
            basic_summary = self._generate_basic_executive_summary(report_data)
            
            return {
                "executive_summary": ai_summary.get("executive_summary", basic_summary["executive_summary"]),
                "overall_risk": ai_summary.get("overall_risk", basic_summary["overall_risk"]),
                "key_findings": ai_summary.get("key_findings", basic_summary["key_findings"]),
                "recommendations": ai_summary.get("recommendations", basic_summary["recommendations"]),
                "remediation_recommendations": ai_summary.get("remediation_recommendations", basic_summary["remediation_recommendations"]),
                "conclusion": ai_summary.get("conclusion", basic_summary["conclusion"])
            }
            
        except json.JSONDecodeError:
            print("❌ Failed to parse AI executive summary, using basic version")
            return self._generate_basic_executive_summary(report_data)

    def _generate_basic_executive_summary(self, report_data: Dict) -> Dict[str, Any]:
        """Generate basic executive summary"""
        summary = report_data.get('summary', {})
        vulnerabilities = report_data.get('vulnerabilities', [])
        
        critical_count = summary.get('critical_count', 0)
        high_count = summary.get('high_count', 0)
        
        overall_risk = "Low"
        if critical_count > 0:
            overall_risk = "Critical"
        elif high_count > 0:
            overall_risk = "High"
        elif summary.get('total_vulnerabilities', 0) > 0:
            overall_risk = "Medium"
        
        executive_summary = f"""
This penetration test assessment of {report_data.get('target', 'the target')} identified {summary.get('total_vulnerabilities', 0)} security vulnerabilities. 
The overall risk level is assessed as {overall_risk}. Critical findings require immediate attention to prevent potential security breaches.
"""
        
        key_findings = []
        if critical_count > 0:
            key_findings.append(f"{critical_count} critical vulnerabilities requiring immediate remediation")
        if high_count > 0:
            key_findings.append(f"{high_count} high-severity vulnerabilities that should be addressed promptly")
        
        if not key_findings and vulnerabilities:
            key_findings.append(f"Found {len(vulnerabilities)} security issues requiring review")
        
        if not key_findings:
            key_findings.append("No critical vulnerabilities identified during this assessment")
        
        return {
            "executive_summary": executive_summary.strip(),
            "overall_risk": overall_risk,
            "key_findings": key_findings,
            "recommendations": [
                "Address critical and high-severity vulnerabilities immediately",
                "Implement regular security assessments",
                "Establish patch management procedures",
                "Conduct security awareness training"
            ],
            "remediation_recommendations": {
                "SQL Injection": "Use parameterized queries and input validation",
                "XSS": "Implement output encoding and Content Security Policy",
                "Directory Traversal": "Validate and sanitize file path inputs"
            },
            "conclusion": "Regular security assessments are recommended to maintain a strong security posture."
        }