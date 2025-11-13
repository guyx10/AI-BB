#!/usr/bin/env python3
"""
OWASP ZAP Scanner Integration
"""
import asyncio
import json
import time
from typing import List, Dict, Any
import subprocess

class ZAPScanner:
    def __init__(self, config: Dict):
        self.config = config.get('zap', {})
        self.zap_path = self.config.get('path', 'zap')
        self.port = self.config.get('port', 8080)
        self.api_key = self.config.get('api_key', '')
        self.max_duration = self.config.get('max_scan_duration', 60)
        
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Run comprehensive ZAP scan on target"""
        print(f"   🎯 Starting ZAP scan for: {target}")
        
        try:
            # Run ZAP baseline scan
            results = await self._run_baseline_scan(target)
            
            # If we have more time, run active scan
            if self.max_duration > 120:  # Only if we have sufficient time
                active_results = await self._run_active_scan(target)
                results['active_scan'] = active_results
            
            return results
            
        except Exception as e:
            print(f"   ❌ ZAP scan error: {e}")
            return {'error': str(e), 'alerts': []}
    
    async def _run_baseline_scan(self, target: str) -> Dict[str, Any]:
        """Run ZAP baseline scan (quick scan)"""
        cmd = [
            self.zap_path, 'baseline.py',
            '-t', target,
            '-d', '-m', str(self.max_duration),
            '-P', str(self.port),
            '-J',  # JSON output
            '-j'   # Short format
        ]
        
        if self.api_key:
            cmd.extend(['-I', self.api_key])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.max_duration + 30)
            
            if process.returncode == 0 and stdout:
                return self._parse_zap_output(stdout.decode())
            else:
                return {'alerts': [], 'error': stderr.decode() if stderr else 'Unknown error'}
                
        except asyncio.TimeoutError:
            return {'alerts': [], 'error': 'ZAP scan timeout'}
        except Exception as e:
            return {'alerts': [], 'error': str(e)}
    
    async def _run_active_scan(self, target: str) -> Dict[str, Any]:
        """Run ZAP active scan (comprehensive but slower)"""
        cmd = [
            self.zap_path, 'active-scan.py',
            '-t', target,
            '-d', '-m', str(min(self.max_duration, 300)),  # Max 5 minutes for active
            '-P', str(self.port),
            '-J'  # JSON output
        ]
        
        if self.api_key:
            cmd.extend(['-I', self.api_key])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=min(self.max_duration, 300) + 30)
            
            if process.returncode == 0 and stdout:
                return self._parse_zap_output(stdout.decode())
            else:
                return {'alerts': [], 'error': stderr.decode() if stderr else 'Unknown error'}
                
        except asyncio.TimeoutError:
            return {'alerts': [], 'error': 'ZAP active scan timeout'}
        except Exception as e:
            return {'alerts': [], 'error': str(e)}
    
    def _parse_zap_output(self, output: str) -> Dict[str, Any]:
        """Parse ZAP CLI JSON output"""
        try:
            data = json.loads(output)
            alerts = data.get('alerts', [])
            
            # Convert ZAP alerts to our format
            findings = []
            for alert in alerts:
                findings.append({
                    'type': alert.get('name', 'Unknown'),
                    'url': alert.get('url', ''),
                    'severity': self._convert_zap_severity(alert.get('risk', 'Informational')),
                    'confidence': self._convert_zap_confidence(alert.get('confidence', 'Medium')),
                    'tool': 'zap',
                    'description': alert.get('description', ''),
                    'solution': alert.get('solution', ''),
                    'reference': alert.get('reference', ''),
                    'evidence': alert.get('evidence', ''),
                    'cwe_id': alert.get('cweid', ''),
                    'wasc_id': alert.get('wascid', '')
                })
            
            return {
                'alerts': findings,
                'scan_duration': data.get('scan_duration', 0),
                'total_alerts': len(findings),
                'risk_summary': self._generate_risk_summary(findings)
            }
            
        except json.JSONDecodeError:
            # Try to extract alerts from text output
            return {'alerts': [], 'error': 'Failed to parse ZAP output'}
    
    def _convert_zap_severity(self, risk: str) -> str:
        """Convert ZAP risk to standard severity"""
        risk_map = {
            'High': 'high',
            'Medium': 'medium', 
            'Low': 'low',
            'Informational': 'info'
        }
        return risk_map.get(risk, 'info')
    
    def _convert_zap_confidence(self, confidence: str) -> str:
        """Convert ZAP confidence to standard confidence"""
        confidence_map = {
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low'
        }
        return confidence_map.get(confidence, 'medium')
    
    def _generate_risk_summary(self, alerts: List[Dict]) -> Dict[str, int]:
        """Generate risk summary from alerts"""
        summary = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for alert in alerts:
            severity = alert.get('severity', 'info')
            if severity in summary:
                summary[severity] += 1
        return summary