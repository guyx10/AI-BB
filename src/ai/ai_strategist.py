#!/usr/bin/env python3
"""
Enhanced AI Strategist with Model Specialization - FIXED VERSION
"""
import aiohttp
import json
import asyncio
from typing import Dict, Any, List
import logging

class AIStrategist:
    def __init__(self, config: Dict):
        self._model_cache = {}
        self._cache_timeout = 300  # 5 minutes

        async def check_model_availability(self, model: str) -> bool:
            if model in self._model_cache:
                cached_time, available = self._model_cache[model]
                if time.time() - cached_time < self._cache_timeout:
                    return available        
        self.config = config
        self.ai_config = config.get('ai', {})
        self.primary_provider = self.ai_config.get('primary_provider', 'ollama')
        self.rate_limiter = asyncio.Semaphore(
        self.config.get('limits', {}).get('max_requests_per_minute', 30) // 2
)
        
        # Model specialization
        self.strategy_model = self.ai_config.get('strategy_model', 'mistral:7b-instruct')
        self.code_model = self.ai_config.get('code_model', 'deepseek-coder:6.7b')
        self.fallback_model = self.ai_config.get('fallback_model', 'codellama:13b')
        
        self.temperature = self.ai_config.get('temperature', 0.3)
        self.max_tokens = self.ai_config.get('max_tokens', 4000)
        
        self.ollama_base_url = "http://localhost:11434"
        self.session = None
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def check_ollama_availability(self) -> bool:  # FIXED: Add this method
        """Check if Ollama is available and models are loaded"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.get(f"{self.ollama_base_url}/api/tags") as response:
                if response.status == 200:
                    data = await response.json()
                    models = data.get('models', [])
                    
                    # Check if our desired models are available
                    available_models = [m.get('name', '') for m in models]
                    strategy_available = any(self.strategy_model in model for model in available_models)
                    code_available = any(self.code_model in model for model in available_models)
                    fallback_available = any(self.fallback_model in model for model in available_models)
                    
                    if self.strategy_model and strategy_available:
                        print(f"✅ {self.strategy_model} available")
                    if self.code_model and code_available:
                        print(f"✅ {self.code_model} available")
                    if self.fallback_model and fallback_available:
                        print(f"✅ {self.fallback_model} available")
                    
                    return bool(models)
                return False
        except Exception as e:
            print(f"❌ Cannot connect to Ollama: {e}")
            return False

    async def check_model_availability(self, model: str) -> bool:
        """Check if specific model is available"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.get(f"{self.ollama_base_url}/api/tags") as response:
                if response.status == 200:
                    data = await response.json()
                    models = data.get('models', [])
                    return any(model in m.get('name', '') for m in models)
                return False
        except Exception as e:
            print(f"❌ Model availability check failed: {e}")
            return False

    async def analyze_scan_results(self, scan_data: Dict) -> Dict[str, Any]:
        """AI analysis with model specialization"""
        print("🔧 [AI] Starting analysis...")
        try:
            # Try strategy model first
            print("🔧 [AI] Checking strategy model...")
            if await self.check_model_availability(self.strategy_model):
                print("🔧 [AI] Using strategy model...")
                analysis = await self._analyze_with_model(scan_data, self.strategy_model, "strategic")
                if analysis and analysis.get('risk_assessment') != 'unknown':
                    print("✅ [AI] Strategy model analysis completed")
                    return analysis
            
        # Fallback to code model
            print("🔧 [AI] Checking code model...")
            if await self.check_model_availability(self.code_model):
                print("🔧 [AI] Using code model...")
                analysis = await self._analyze_with_model(scan_data, self.code_model, "technical")
                if analysis:
                    print("✅ [AI] Code model analysis completed")
                    return analysis
            
            # Final fallback
            print("🔧 [AI] Checking fallback model...")
            if await self.check_model_availability(self.fallback_model):
                print("🔧 [AI] Using fallback model...")
                analysis = await self._analyze_with_model(scan_data, self.fallback_model, "general")
                if analysis:
                    print("✅ [AI] Fallback model analysis completed")
                    return analysis
        
            # Ultimate fallback
            print("🔧 [AI] Using rule-based analysis...")
            return self._rule_based_analysis(scan_data)
        
        except Exception as e:
            print(f"❌ [AI] Analysis failed: {e}")
            return self._rule_based_analysis(scan_data)

    async def _analyze_with_model(self, scan_data: Dict, model: str, analysis_type: str) -> Dict[str, Any]:
        """Analyze with specific model and prompt optimization"""
        print(f"🔧 [AI] Analyzing with {model} ({analysis_type})...")
        
        # Add retry logic with proper implementation
        for attempt in range(3):
            try:
                if analysis_type == "strategic":
                    prompt = self._build_strategic_prompt(scan_data)
                elif analysis_type == "technical":
                    prompt = self._build_technical_prompt(scan_data)
                else:
                    prompt = self._build_general_prompt(scan_data)
                
                print(f"🔧 [AI] Sending request to Ollama...")
                payload = {
                    "model": model,
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
                        print(f"🔧 [AI] Received response, parsing...")
                        return self._parse_ai_response(analysis_text, scan_data)
                    else:
                        print(f"❌ [AI] API error: {response.status}")
                        if attempt == 2:  # Last attempt
                            return None
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        
            except aiohttp.ClientError as e:
                print(f"❌ [AI] Connection error on attempt {attempt + 1}: {e}")
                if attempt == 2:
                    return None
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except Exception as e:
                print(f"❌ [AI] Analysis error: {e}")
                return None
        
        return None

    def _parse_ai_response(self, response_text: str, scan_data: Dict) -> Dict[str, Any]:
        """Parse AI response and extract structured data"""
        try:
            # Use robust JSON extraction
            ai_data = self._extract_json_from_response(response_text)
            
            if not ai_data:
                print("❌ No JSON found in AI response")
                return self._rule_based_analysis(scan_data)
            
            # Ensure all required fields exist
            default_analysis = self._rule_based_analysis(scan_data)
            
            return {
                "risk_assessment": ai_data.get("risk_assessment", default_analysis["risk_assessment"]),
                "immediate_actions": ai_data.get("immediate_actions", default_analysis["immediate_actions"]),
                "priority_targets": ai_data.get("priority_targets", default_analysis["priority_targets"]),
                "exploitation_strategy": ai_data.get("exploitation_strategy", default_analysis["exploitation_strategy"]),
                "key_findings": ai_data.get("key_findings", default_analysis["key_findings"])
            }
            
        except Exception as e:
            print(f"❌ Error parsing AI response: {e}")
            return self._rule_based_analysis(scan_data)

    def _build_technical_prompt(self, scan_data: Dict) -> str:
        """DeepSeek-optimized prompt for technical analysis"""
        basic_recon = scan_data.get('basic_recon', {})
        
        prompt = f"""As a security engineer, provide TECHNICAL exploitation guidance:

SCAN RESULTS:
- Open ports: {basic_recon.get('nmap_results', {}).get('open_ports', [])}
- Services: {json.dumps(scan_data.get('services_detected', {}), indent=2)}

Provide EXPLOITATION TECHNIQUES for each service:

For each open port/service, suggest:
1. Specific vulnerability scanners to run
2. Manual testing procedures  
3. Common misconfigurations to check
4. Proof-of-concept commands
5. Privilege escalation paths

Example format:
Port 22 (SSH): 
- Test: hydra -L users.txt -P passwords.txt ssh://target -t 4
- Check: ssh_config weaknesses, authorized_keys permissions
- Escalation: sudo -l, SUID binaries

Port 80 (HTTP):
- Tools: nuclei, sqlmap, ffuf
- Tests: SQLi: ' OR '1'='1, XSS: <script>alert()</script>
- Directories: /admin, /backup, /.git

Format as JSON with technical specifics:"""

        return prompt

    def _build_strategic_prompt(self, scan_data: Dict) -> str:
        """Enhanced prompt with actual vulnerability data"""
        basic_recon = scan_data.get('basic_recon', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Extract SQL injections from passed vulnerabilities
        sql_injections = [v for v in vulnerabilities if 'SQL Injection' in v.get('type', '')]
        
        services_detected = scan_data.get('services_detected', {})
        bug_bounty_recon = scan_data.get('bug_bounty_recon', {})
        
        prompt = f"""As a senior penetration tester, analyze these ACTUAL FINDINGS:

CRITICAL VULNERABILITIES FOUND:
- SQL Injections: {len(sql_injections)}
- Total vulnerabilities: {len(vulnerabilities)}
- Open ports: {len(basic_recon.get('nmap_results', {}).get('open_ports', []))}

SQL INJECTION ENDPOINTS:
{json.dumps([v.get('url', '') for v in sql_injections[:5]], indent=2)}

TARGET ASSESSMENT DATA:
- Subdomains discovered: {len(basic_recon.get('subdomains', []))}
- Live endpoints: {len(basic_recon.get('live_domains', []))}
- Open ports: {len(basic_recon.get('nmap_results', {}).get('open_ports', []))}
- Web services: {len(services_detected.get('web', []))}
- Database services: {len(services_detected.get('database', []))}
- Bug bounty findings: {len(bug_bounty_recon.get('quick_wins', []))}

PORT DETAILS:
{json.dumps(basic_recon.get('nmap_results', {}).get('open_ports', []), indent=2)}

BUG BOUNTY INSIGHTS:
{json.dumps(bug_bounty_recon.get('quick_wins', []), indent=2)}

FOCUS ON THESE CRITICAL AREAS:
1. SQL Injection testing on parameterized endpoints
2. Database enumeration through discovered SQLi vectors
3. Authentication bypass on login/signup pages
4. Sensitive data exposure in discovered directories

Provide a CONCRETE penetration testing strategy with:

1. IMMEDIATE ACTIONS (3-5 specific technical tests to run next)
2. EXPLOITATION PRIORITIES (rank services by attack potential)
3. BUSINESS IMPACT ANALYSIS (what could actually be compromised)
4. REMEDIATION TIMELINE (critical vs important fixes)

Format as JSON:
{{
    "risk_assessment": "Low/Medium/High/Critical",
    "immediate_actions": [
        "Specific technical action 1",
        "Specific technical action 2"
    ],
    "exploitation_priorities": [
        {{"service": "HTTP", "priority": "High", "reason": "Multiple SQL injection vectors found"}}
    ],
    "business_impact": "Specific business risks",
    "remediation_timeline": {{
        "critical": ["SQL injection fixes", "Authentication vulnerabilities"],
        "important": ["Directory traversal", "Information disclosure"]
    }},
    "next_phases": ["Database enumeration", "Privilege escalation testing"]
}}

Be technical and specific - avoid generic security advice."""

        return prompt  # FIXED: This was incorrectly indented before

    def _build_general_prompt(self, scan_data: Dict) -> str:
        """General purpose prompt for fallback"""
        basic_recon = scan_data.get('basic_recon', {})
        
        prompt = f"""Analyze security scan results:

FINDINGS:
- Subdomains: {len(basic_recon.get('subdomains', []))}
- Live hosts: {len(basic_recon.get('live_domains', []))} 
- Open ports: {len(basic_recon.get('nmap_results', {}).get('open_ports', []))}
- Services: {json.dumps(scan_data.get('services_detected', {}), indent=2)}

Provide specific recommendations for penetration testing next steps.

JSON format:"""

        return prompt

    async def generate_executive_summary(self, report_data: Dict) -> Dict[str, Any]:
        """Generate executive summary with model specialization"""
        try:
            # Ensure we have a session
            if not self.session or self.session.closed:
                self.session = aiohttp.ClientSession()
                
            # Use strategy model for executive summaries
            if await self.check_model_availability(self.strategy_model):
                prompt = self._build_executive_summary_prompt(report_data)
                
                payload = {
                    "model": self.strategy_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,  # More deterministic for reports
                        "num_predict": 3000
                    }
                }
                
                async with self.session.post(f"{self.ollama_base_url}/api/generate", json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        summary_text = result.get('response', '')
                        return self._parse_executive_summary(summary_text, report_data)
            
            return self._generate_basic_executive_summary(report_data)
            
        except Exception as e:
            print(f"❌ AI executive summary failed: {e}")
            return self._generate_basic_executive_summary(report_data)

    def _build_executive_summary_prompt(self, report_data: Dict) -> str:
        """Enhanced executive summary prompt with explicit JSON formatting"""
        summary = report_data.get('summary', {})
        vulnerabilities = report_data.get('vulnerabilities', [])
        
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        
        prompt = f"""Create a CONCISE executive summary for technical management. Return ONLY valid JSON, no other text.

SCAN RESULTS:
- Target: {report_data.get('target', 'Unknown')}
- Critical vulnerabilities: {len(critical_vulns)}
- High severity: {len(high_vulns)}
- Total findings: {summary.get('total_vulnerabilities', 0)}
- SQL Injections found: {len([v for v in vulnerabilities if 'sql' in v.get('type', '').lower()])}

CRITICAL FINDINGS:
{json.dumps([v for v in vulnerabilities if v.get('severity') in ['critical', 'high']][:5], indent=2)}

Return EXACTLY this JSON structure:
{{
    "executive_summary": "Brief 2-3 sentence overview",
    "overall_risk": "Low/Medium/High/Critical",
    "key_findings": [
        "Finding 1 with specific details",
        "Finding 2 with specific details"
    ],
    "recommendations": [
        "Specific action 1",
        "Specific action 2"
    ],
    "remediation_recommendations": {{
        "SQL Injection": "Use parameterized queries",
        "Other vulnerabilities": "Specific fixes"
    }},
    "conclusion": "Final assessment statement"
}}"""
        return prompt

    def _parse_executive_summary(self, response_text: str, report_data: Dict) -> Dict[str, Any]:
        """Parse executive summary response with robust JSON extraction"""
        try:
            # Enhanced JSON extraction with better error handling
            ai_summary = self._extract_json_from_response(response_text)
            
            if not ai_summary:
                print("❌ No JSON found in AI executive summary response, using basic summary")
                print(f"🔧 Raw AI response: {response_text[:500]}...")  # Debug first 500 chars
                return self._generate_basic_executive_summary(report_data)
            
            # More flexible field mapping
            basic_summary = self._generate_basic_executive_summary(report_data)
            
            return {
                "executive_summary": ai_summary.get("executive_summary", 
                                  ai_summary.get("summary", 
                                  ai_summary.get("overview", basic_summary["executive_summary"]))),
                "overall_risk": ai_summary.get("overall_risk", 
                              ai_summary.get("risk_level", 
                              ai_summary.get("risk", basic_summary["overall_risk"]))),
                "key_findings": ai_summary.get("key_findings", 
                              ai_summary.get("findings", 
                              ai_summary.get("critical_findings", basic_summary["key_findings"]))),
                "recommendations": ai_summary.get("recommendations", 
                                 ai_summary.get("actions", 
                                 ai_summary.get("next_steps", basic_summary["recommendations"]))),
                "remediation_recommendations": ai_summary.get("remediation_recommendations", 
                                             ai_summary.get("remediation", 
                                             ai_summary.get("fixes", basic_summary["remediation_recommendations"]))),
                "conclusion": ai_summary.get("conclusion", 
                            ai_summary.get("summary", 
                            basic_summary["conclusion"]))
            }
            
        except Exception as e:
            print(f"❌ Error parsing AI executive summary: {e}")
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
    
    def _extract_json_from_response(self, response_text: str) -> Dict:
        """More robust JSON extraction from AI responses"""
        try:
            # Clean the response
            cleaned = response_text.strip()
            
            # Multiple strategies to find JSON
            strategies = [
                # Strategy 1: Direct JSON parse
                lambda: json.loads(cleaned),
                # Strategy 2: Extract between ```json and ```
                lambda: json.loads(cleaned.split('```json')[1].split('```')[0].strip()),
                # Strategy 3: Extract between ``` and ```
                lambda: json.loads(cleaned.split('```')[1].strip()),
                # Strategy 4: Find first { and last }
                lambda: json.loads(cleaned[cleaned.find('{'):cleaned.rfind('}')+1]),
                # Strategy 5: Find lines that look like JSON
                lambda: self._extract_json_from_lines(cleaned.split('\n'))
            ]
            
            for strategy in strategies:
                try:
                    return strategy()
                except:
                    continue
                    
            return {}
        except Exception as e:
            print(f"❌ All JSON extraction strategies failed: {e}")
            return {}

    def _extract_json_from_lines(self, lines: List[str]) -> Dict:
        """Extract JSON from individual lines"""
        json_candidates = []
        in_json = False
        json_block = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                json_candidates.append(line)
            elif line.startswith('{'):
                in_json = True
                json_block.append(line)
            elif line.endswith('}') and in_json:
                json_block.append(line)
                json_candidates.append('\n'.join(json_block))
                in_json = False
                json_block = []
            elif in_json:
                json_block.append(line)
        
        for candidate in json_candidates:
            try:
                return json.loads(candidate)
            except:
                continue
        
        return {}