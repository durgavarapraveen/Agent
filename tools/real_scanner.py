import subprocess
import json
import logging
import re
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class DockerScanner:
    """Real security scanner using Docker containers"""
    
    def __init__(self):
        self.docker_available = self._check_docker()
    
    def _check_docker(self) -> bool:
        try:
            subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    async def nmap_scan(self, target: str) -> Dict[str, Any]:
        """Port scanning using nmap"""
        if not self.docker_available:
            return {"status": "error", "error": "Docker not available"}
        
        parsed = urlparse(target)
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        
        try:
            cmd = [
                "docker", "run", "--rm",
                "nmap/nmap:latest",
                f"-sV -p 1-10000 --top-ports 100 {domain}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            ports = []
            services = []
            
            # Parse nmap output
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if match:
                    port = int(match.group(1))
                    service = match.group(2)
                    ports.append(port)
                    services.append(service.upper())
            
            return {
                "status": "success",
                "target": target,
                "ports": sorted(set(ports)),
                "services": list(set(services)),
                "raw_output": result.stdout
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "target": target, "error": "Scan timeout"}
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def sqlmap_scan(self, target: str) -> Dict[str, Any]:
        """SQL injection scanning"""
        if not self.docker_available:
            return {"status": "error", "error": "Docker not available"}
        
        try:
            cmd = [
                "docker", "run", "--rm",
                "sqlmap/sqlmap:latest",
                f"--url={target} --batch --risk=1 --level=1 --identify-waf"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            vulnerabilities = []
            
            if "SQL injection" in result.stdout:
                vulnerabilities.append({
                    "type": "SQL Injection",
                    "severity": "CRITICAL",
                    "confidence": 0.95
                })
            
            return {
                "status": "success",
                "target": target,
                "vulnerabilities": vulnerabilities,
                "raw_output": result.stdout
            }
        except Exception as e:
            logger.error(f"SQLMap scan failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def zaproxy_scan(self, target: str) -> Dict[str, Any]:
        """OWASP ZAP scanning"""
        if not self.docker_available:
            return {"status": "error", "error": "Docker not available"}
        
        try:
            cmd = [
                "docker", "run", "--rm",
                "-v", "/tmp:/zap/wrk:rw",
                "owasp/zap2docker-stable",
                f"zap-baseline.py -t {target} -r /tmp/zap-report.md"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            findings = []
            
            # Parse ZAP output for common vulnerabilities
            if "X-Frame-Options" in result.stdout:
                findings.append({
                    "type": "Missing X-Frame-Options",
                    "severity": "MEDIUM",
                    "description": "Clickjacking vulnerability"
                })
            
            if "X-Content-Type-Options" in result.stdout:
                findings.append({
                    "type": "Missing X-Content-Type-Options",
                    "severity": "MEDIUM",
                    "description": "MIME type sniffing"
                })
            
            if "Strict-Transport-Security" in result.stdout:
                findings.append({
                    "type": "Missing HSTS",
                    "severity": "MEDIUM",
                    "description": "No HTTPS enforcement"
                })
            
            return {
                "status": "success",
                "target": target,
                "findings": findings,
                "raw_output": result.stdout
            }
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def dependency_check(self, target_url: str) -> Dict[str, Any]:
        """Scan for vulnerable dependencies"""
        try:
            cmd = [
                "docker", "run", "--rm",
                "owasp/dependency-check:latest",
                "--scan / --format JSON --project Test"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    vulnerabilities = data.get("reportSchema", {}).get("vulnerabilities", [])
                    
                    return {
                        "status": "success",
                        "target": target_url,
                        "vulnerabilities": vulnerabilities,
                        "count": len(vulnerabilities)
                    }
                except json.JSONDecodeError:
                    pass
            
            return {
                "status": "success",
                "target": target_url,
                "vulnerabilities": [],
                "count": 0
            }
        except Exception as e:
            logger.error(f"Dependency check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def nikto_scan(self, target: str) -> Dict[str, Any]:
        """Web server scanning with Nikto"""
        if not self.docker_available:
            return {"status": "error", "error": "Docker not available"}
        
        try:
            cmd = [
                "docker", "run", "--rm",
                "secfigo/nikto:latest",
                f"-h {target} -o /tmp/nikto-report.txt"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            findings = []
            
            # Parse Nikto output
            for line in result.stdout.split('\n'):
                if "+" in line and ("[" in line):
                    findings.append({
                        "raw": line.strip(),
                        "severity": "MEDIUM"
                    })
            
            return {
                "status": "success",
                "target": target,
                "findings": findings,
                "finding_count": len(findings)
            }
        except Exception as e:
            logger.error(f"Nikto scan failed: {e}")
            return {"status": "error", "error": str(e)}


# Fallback implementations (when Docker not available)

class LocalScanner:
    """Fallback scanning without Docker - uses Python libraries"""
    
    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """Quick vulnerability scan without Docker"""
        import httpx
        
        findings = []
        
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(target, follow_redirects=True)
                headers = response.headers
                
                # Check security headers
                missing_headers = []
                
                security_headers = {
                    "X-Frame-Options": "Clickjacking protection",
                    "X-Content-Type-Options": "MIME type sniffing",
                    "Content-Security-Policy": "XSS protection",
                    "Strict-Transport-Security": "HTTPS enforcement",
                    "X-XSS-Protection": "XSS filtering"
                }
                
                for header, description in security_headers.items():
                    if header not in headers:
                        findings.append({
                            "type": f"Missing {header}",
                            "severity": "MEDIUM",
                            "description": description,
                            "confidence": 0.95
                        })
                
                # Check for common vulnerabilities
                content = response.text
                
                if "debug=true" in content or "DEBUG" in content:
                    findings.append({
                        "type": "Debug Mode Enabled",
                        "severity": "HIGH",
                        "description": "Application running in debug mode",
                        "confidence": 0.85
                    })
                
                if re.search(r"password\s*=", content, re.IGNORECASE):
                    findings.append({
                        "type": "Hardcoded Credentials",
                        "severity": "CRITICAL",
                        "description": "Possible hardcoded credentials in HTML",
                        "confidence": 0.70
                    })
                
                if "sql" in content.lower() or "database" in content.lower():
                    findings.append({
                        "type": "Potential SQL Injection",
                        "severity": "HIGH",
                        "description": "SQL keywords found in response",
                        "confidence": 0.60
                    })
                
                return {
                    "status": "success",
                    "target": target,
                    "findings": findings,
                    "status_code": response.status_code,
                    "method": "Local Quick Scan"
                }
        
        except Exception as e:
            logger.error(f"Quick scan failed: {e}")
            return {
                "status": "error",
                "target": target,
                "error": str(e)
            }