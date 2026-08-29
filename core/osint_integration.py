"""
OSINT Integration Module
Connects OSINT engines to central_brain for autonomous reconnaissance phases.

This file shows how to integrate:
- osint_engine.py (Employee enumeration, GitHub scanning, DNS intelligence)
- threat_intel.py (Threat feed integration)
- subdomain_enum.py (Advanced subdomain discovery)

Usage in central_brain:
- Create reconnaissance phases that spawn OSINT agents
- Pass objectives to OSINTOrchestrator
- Collect findings into shared_context
"""

import logging
import asyncio
from typing import Dict, List, Optional
from datetime import datetime

from core.osint_engine import OSINTEngine, EmployeeEnumerator, GitHubScanner, DNSMailIntelligence
from core.threat_intel import ThreatIntelligenceEngine, AbuseChIntelligence
from core.subdomain_enum import SubdomainEnumerationEngine, CertificateTransparencyScanner
from core.shared_context import SharedContext

logger = logging.getLogger(__name__)


class OSINTAgentSpec:
    """OSINT agent specification for spawning from central_brain."""

    def __init__(self, agent_type: str, objective: str, target_domain: str, 
                 company_name: Optional[str] = None):
        self.agent_type = agent_type  # employee_enum, github_scan, dns_intel, subdomain_enum, threat_intel
        self.objective = objective
        self.target_domain = target_domain
        self.company_name = company_name
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        """Convert to dict for task storage."""
        return {
            'agent_type': self.agent_type,
            'objective': self.objective,
            'target_domain': self.target_domain,
            'company_name': self.company_name,
            'created_at': self.created_at
        }


class OSINTOrchestrator:
    """Orchestrates OSINT modules and manages OSINT agents."""

    def __init__(self, shared_context: SharedContext):
        self.ctx = shared_context
        self.osint_engine = OSINTEngine()
        self.threat_engine = ThreatIntelligenceEngine()
        self.subdomain_engine = SubdomainEnumerationEngine()

    async def spawn_employee_enumeration_agent(self, domain: str, company_name: str) -> Dict:
        """Spawn agent to enumerate employees."""
        logger.info(f"[OSINTOrchestrator] Spawning employee enumeration agent for {domain}")
        
        spec = OSINTAgentSpec(
            agent_type="employee_enum",
            objective=f"Discover all employee email addresses and roles for {domain}. "
                     f"Use LinkedIn scraping, company website analysis, and email pattern inference.",
            target_domain=domain,
            company_name=company_name
        )
        
        # Execute employee enumeration
        employees = await self.osint_engine.employee_enum.enumerate_from_company_site(domain)
        
        # Save to shared context
        self.ctx.update('discovered_employees', employees)
        
        return {
            'spec': spec.to_dict(),
            'results': {
                'employees_found': len(employees),
                'emails': [e.email for e in employees[:10]]  # Sample
            }
        }

    async def spawn_github_scanning_agent(self, company_name: str) -> Dict:
        """Spawn agent to scan GitHub repositories."""
        logger.info(f"[OSINTOrchestrator] Spawning GitHub scanner agent for {company_name}")
        
        spec = OSINTAgentSpec(
            agent_type="github_scan",
            objective=f"Scan public GitHub repositories for {company_name}. "
                     f"Find hardcoded credentials, API keys, internal endpoints, and secrets.",
            target_domain=company_name,
            company_name=company_name
        )
        
        # Find repos
        repos = await self.osint_engine.github_scanner.find_organization_repos(company_name)
        
        # Scan repos for credentials
        all_creds = []
        for repo in repos[:5]:  # Limit to first 5
            creds = await self.osint_engine.github_scanner.scan_repository(company_name, repo)
            all_creds.extend(creds)
        
        # Save to shared context
        self.ctx.update('leaked_credentials', all_creds)
        
        return {
            'spec': spec.to_dict(),
            'results': {
                'repos_scanned': len(repos),
                'credentials_found': len(all_creds),
                'severity_breakdown': self._count_by_severity(all_creds)
            }
        }

    async def spawn_dns_intelligence_agent(self, domain: str) -> Dict:
        """Spawn agent to analyze DNS and mail infrastructure."""
        logger.info(f"[OSINTOrchestrator] Spawning DNS intelligence agent for {domain}")
        
        spec = OSINTAgentSpec(
            agent_type="dns_intel",
            objective=f"Analyze DNS and mail infrastructure for {domain}. "
                     f"Discover MX records, SPF/DKIM/DMARC policies, mail server versions.",
            target_domain=domain
        )
        
        # Analyze domain
        dns_intel = await self.osint_engine.dns_intel.analyze_domain(domain)
        
        # Save to shared context
        self.ctx.update('domain_intelligence', dns_intel)
        
        return {
            'spec': spec.to_dict(),
            'results': {
                'mx_records': dns_intel.mx_records,
                'spf_policy': dns_intel.spf_policy,
                'dkim_enabled': dns_intel.dkim_enabled,
                'dmarc_policy': dns_intel.dmarc_policy
            }
        }

    async def spawn_subdomain_enumeration_agent(self, domain: str) -> Dict:
        """Spawn agent to discover subdomains and virtual hosts."""
        logger.info(f"[OSINTOrchestrator] Spawning subdomain enumeration agent for {domain}")
        
        spec = OSINTAgentSpec(
            agent_type="subdomain_enum",
            objective=f"Discover all subdomains of {domain}. "
                     f"Use Certificate Transparency logs, CDN analysis, cloud storage enumeration, "
                     f"and virtual host detection to map complete attack surface.",
            target_domain=domain
        )
        
        # Discover attack surface
        results = await self.subdomain_engine.discover_attack_surface(domain)
        
        # Save to shared context
        self.ctx.update('discovered_subdomains', results['subdomains'])
        self.ctx.update('cloud_buckets', results['cloud_buckets'])
        
        return {
            'spec': spec.to_dict(),
            'results': {
                'subdomains_found': len(results['subdomains']),
                'cloud_buckets_found': len(results['cloud_buckets']),
                'virtual_hosts_found': len(results['virtual_hosts']),
                'sample_subdomains': [s.name for s in results['subdomains'][:10]]
            }
        }

    async def spawn_threat_intelligence_agent(self, discovered_assets: Dict) -> Dict:
        """Spawn agent to correlate findings with threat intelligence."""
        logger.info("[OSINTOrchestrator] Spawning threat intelligence agent")
        
        spec = OSINTAgentSpec(
            agent_type="threat_intel",
            objective="Load threat intelligence feeds (Shodan, Censys, abuse.ch). "
                     "Correlate discovered assets with threat intelligence to identify "
                     "compromised services and command & control servers.",
            target_domain="global"
        )
        
        # Load threat feeds
        feed_results = await self.threat_engine.load_threat_feeds()
        
        # Correlate with findings
        correlations = await self.threat_engine.correlate_with_findings(discovered_assets)
        
        # Save to shared context
        self.ctx.update('threat_correlations', correlations)
        
        # Generate summary
        summary = self.threat_engine.generate_threat_summary()
        
        return {
            'spec': spec.to_dict(),
            'results': {
                'feeds_loaded': feed_results,
                'threat_correlations': len(correlations),
                'threat_summary': summary
            }
        }

    async def run_phase_osint_reconnaissance(self, domain: str, company_name: str) -> Dict:
        """Run complete OSINT reconnaissance phase."""
        logger.info(f"[OSINTOrchestrator] Starting OSINT reconnaissance for {domain}")
        
        phase_results = {
            'phase': 'osint_reconnaissance',
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'agents': []
        }
        
        try:
            # 1. Employee enumeration
            logger.info("[OSINTOrchestrator] Phase 1: Employee Enumeration")
            emp_result = await self.spawn_employee_enumeration_agent(domain, company_name)
            phase_results['agents'].append(emp_result)
            
            # 2. GitHub scanning
            logger.info("[OSINTOrchestrator] Phase 2: GitHub Scanning")
            github_result = await self.spawn_github_scanning_agent(company_name)
            phase_results['agents'].append(github_result)
            
            # 3. DNS intelligence
            logger.info("[OSINTOrchestrator] Phase 3: DNS Intelligence")
            dns_result = await self.spawn_dns_intelligence_agent(domain)
            phase_results['agents'].append(dns_result)
            
            # 4. Subdomain enumeration
            logger.info("[OSINTOrchestrator] Phase 4: Subdomain Enumeration")
            subdomain_result = await self.spawn_subdomain_enumeration_agent(domain)
            phase_results['agents'].append(subdomain_result)
            
            # 5. Threat intelligence correlation
            logger.info("[OSINTOrchestrator] Phase 5: Threat Intelligence")
            discovered = {
                'ips': self.ctx.get('discovered_ips', []),
                'domains': self.ctx.get('discovered_domains', [])
            }
            threat_result = await self.spawn_threat_intelligence_agent(discovered)
            phase_results['agents'].append(threat_result)
            
            logger.info(f"[OSINTOrchestrator] OSINT reconnaissance complete: {len(phase_results['agents'])} agents")
            
        except Exception as e:
            logger.error(f"[OSINTOrchestrator] Phase failed: {e}")
            phase_results['error'] = str(e)
        
        return phase_results

    def generate_osint_summary_report(self) -> Dict:
        """Generate summary of all OSINT findings."""
        emp_summary = self.osint_engine.generate_osint_summary()
        ctx_employees = getattr(self.ctx, "discovered_employees", []) or self.ctx.get("discovered_employees", []) or []
        ctx_creds = getattr(self.ctx, "leaked_credentials", []) or self.ctx.get("leaked_credentials", []) or []
        
        if len(ctx_employees) > emp_summary.get('total_employees', 0):
            emp_summary['total_employees'] = len(ctx_employees)
        if len(ctx_creds) > emp_summary.get('leaked_credentials_count', 0):
            emp_summary['leaked_credentials_count'] = len(ctx_creds)

        return {
            'osint_summary': {
                'employees': emp_summary,
                'threats': self.threat_engine.generate_threat_summary(),
                'subdomains': self.subdomain_engine.generate_attack_surface_report(
                    getattr(self.ctx, 'target_domain', None) or self.ctx.get('target_domain', 'unknown')
                ),
                'timestamp': datetime.now().isoformat()
            }
        }

    @staticmethod
    def _count_by_severity(credentials: List) -> Dict[str, int]:
        """Count credentials by severity."""
        counts = {}
        for cred in credentials:
            severity = getattr(cred, 'severity', 'unknown')
            counts[severity] = counts.get(severity, 0) + 1
        return counts


class OSINTCapabilityResolver:
    """Maps OSINT objectives to capabilities and tools."""

    OSINT_CAPABILITIES = {
        'employee_enumeration': {
            'description': 'Discover employee email addresses and roles',
            'tools': ['browser', 'http_request', 'dns_lookup'],
            'max_steps': 10
        },
        'github_scanning': {
            'description': 'Scan public GitHub repositories for secrets',
            'tools': ['http_request'],
            'max_steps': 15
        },
        'dns_intelligence': {
            'description': 'Analyze DNS and mail infrastructure',
            'tools': ['dns_lookup', 'ssl_inspect'],
            'max_steps': 8
        },
        'subdomain_enumeration': {
            'description': 'Discover all subdomains and virtual hosts',
            'tools': ['http_request', 'dns_lookup', 'ssl_inspect'],
            'max_steps': 20
        },
        'threat_intelligence': {
            'description': 'Correlate assets with threat intelligence feeds',
            'tools': ['http_request'],
            'max_steps': 12
        }
    }

    @classmethod
    def resolve_osint_objective(cls, objective: str) -> Optional[Dict]:
        """Map OSINT objective to capability and tools."""
        for cap_name, cap_spec in cls.OSINT_CAPABILITIES.items():
            if any(keyword in objective.lower() for keyword in cap_name.split('_')):
                return {
                    'capability': cap_name,
                    'description': cap_spec['description'],
                    'tools': cap_spec['tools'],
                    'max_steps': cap_spec['max_steps']
                }
        return None


# Example usage in central_brain:
"""
def _run_phase_osint(self):
    '''Run OSINT reconnaissance phase.'''
    osint_orchestrator = OSINTOrchestrator(self.ctx)
    
    domain = self.ctx.target
    company_name = self._extract_company_name(domain)
    
    results = await osint_orchestrator.run_phase_osint_reconnaissance(domain, company_name)
    
    self.logger.info(f"OSINT Phase Complete: {results}")
    
    # Update brain prompt with findings
    self.ctx.update('osint_findings', results)
"""