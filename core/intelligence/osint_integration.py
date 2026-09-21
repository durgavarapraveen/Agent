
import logging
from typing import Dict, List, Optional
from datetime import datetime

from core.intelligence.osint_engine import OSINTEngine
from core.intelligence.threat_intel import ThreatIntelligenceEngine
from core.intelligence.subdomain_enum import SubdomainEnumerationEngine
from core.memory.shared_context import SharedContextV2 as SharedContext

logger = logging.getLogger(__name__)


class OSINTAgentSpec:

    def __init__(self, agent_type: str, objective: str, target_domain: str, 
                 company_name: Optional[str] = None):
        self.agent_type = agent_type
        self.objective = objective
        self.target_domain = target_domain
        self.company_name = company_name
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            'agent_type': self.agent_type,
            'objective': self.objective,
            'target_domain': self.target_domain,
            'company_name': self.company_name,
            'created_at': self.created_at
        }


class OSINTOrchestrator:

    def __init__(self, shared_context: SharedContext):
        self.ctx = shared_context
        self.osint_engine = OSINTEngine()
        self.threat_engine = ThreatIntelligenceEngine()
        self.subdomain_engine = SubdomainEnumerationEngine()

    async def spawn_employee_enumeration_agent(self, domain: str, company_name: str) -> Dict:
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
        # Surface the discovered repos in the OSINT view — previously the repo
        # list was fetched then dropped, so the OSINT tab never showed GitHub data.
        try:
            self.ctx.update('github_repos', [
                {'name': r, 'org': company_name,
                 'url': f'https://github.com/{company_name}/{r}'}
                for r in (repos or []) if r])
        except Exception:
            pass

        return {
            'spec': spec.to_dict(),
            'results': {
                'repos_scanned': len(repos),
                'credentials_found': len(all_creds),
                'severity_breakdown': self._count_by_severity(all_creds)
            }
        }

    async def spawn_dns_intelligence_agent(self, domain: str) -> Dict:
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
        # Also merge into the main subdomains list so they appear in recon UI
        sub_names = [s.name if hasattr(s, 'name') else str(s) for s in results['subdomains']]
        self.ctx.add_subdomains(sub_names, source="osint_subdomain_enum")
        
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
        logger.info(f"[OSINTOrchestrator] Starting OSINT reconnaissance for {domain}")
        
        # Profile target for intelligent OSINT orchestration
        try:
            from core.intelligence.target_profiler import TargetProfiler
            target_url = f"https://{domain}" if not domain.startswith(("http://", "https://")) else domain
            profile = TargetProfiler.profile_target(target_url, self.ctx)
            self.ctx.update('target_profile', profile.to_dict())
            logger.info(f"[OSINTOrchestrator] Target profiling complete: type={profile.target_type.value}, score={profile.attack_surface_score}")
        except Exception as pe:
            logger.warning(f"[OSINTOrchestrator] Target profiling warning: {pe}")

        phase_results = {
            'phase': 'osint_reconnaissance',
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'agents': []
        }
        
        try:
            # Parallel: employee enum, GitHub scan, DNS intel, subdomain enum
            # all query independent data sources — run concurrently. Threat
            # intel needs the results of subdomain/domain discovery so it goes
            # after in a second wave.
            import asyncio as _asyncio
            from core.orchestration.parallel_agents import AgentTracker
            scan_id = getattr(self.ctx, "scan_id", None) or getattr(self.ctx, "_scan_id", "")

            try:
                from core.orchestration.family_scheduler import _reason
            except Exception:
                _reason = None

            async def _tracked(name: str, coro):
                aid = f"osint:{name}"
                t = AgentTracker(scan_id, agent_id=aid,
                                  label=f"OSINT: {name}", phase="osint", target=domain)
                t.start(current_step=name)
                if _reason:
                    await _reason(scan_id, aid, 1,
                                  f"Gathering OSINT: {name.replace('_', ' ')} for {domain}.",
                                  tool=name)
                try:
                    r = await coro
                    t.finish(status="completed")
                    if _reason:
                        n = len(r) if isinstance(r, (list, dict)) else 0
                        await _reason(scan_id, aid, 2,
                                      f"→ {name}: completed ({n} item(s)).",
                                      tool=name, status=1 if n else 0)
                    return r
                except Exception as e:
                    t.finish(status="failed", error=str(e))
                    if _reason:
                        await _reason(scan_id, aid, 2, f"{name} failed: {e}",
                                      tool=name, status=-1)
                    raise

            logger.info("[OSINTOrchestrator] Wave 1: employee_enum, github_scan, dns_intel, subdomain_enum (parallel)")
            wave1 = await _asyncio.gather(
                _tracked("employee_enum", self.spawn_employee_enumeration_agent(domain, company_name)),
                _tracked("github_scan",   self.spawn_github_scanning_agent(company_name)),
                _tracked("dns_intel",     self.spawn_dns_intelligence_agent(domain)),
                _tracked("subdomain_enum", self.spawn_subdomain_enumeration_agent(domain)),
                return_exceptions=True,
            )
            for r in wave1:
                if isinstance(r, dict):
                    phase_results['agents'].append(r)

            # Wave 2: threat intel — consumes the discovered assets above.
            logger.info("[OSINTOrchestrator] Wave 2: threat_intel (uses wave-1 output)")
            discovered = {
                'ips': self.ctx.get('discovered_ips', []),
                'domains': self.ctx.get('discovered_domains', [])
            }
            try:
                threat_result = await _tracked("threat_intel",
                                                 self.spawn_threat_intelligence_agent(discovered))
                phase_results['agents'].append(threat_result)
            except Exception:
                pass

            logger.info(f"[OSINTOrchestrator] OSINT reconnaissance complete: {len(phase_results['agents'])} agents")
            
        except Exception as e:
            logger.error(f"[OSINTOrchestrator] Phase failed: {e}")
            phase_results['error'] = str(e)
        
        return phase_results

    def generate_osint_summary_report(self) -> Dict:
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
        counts = {}
        for cred in credentials:
            severity = getattr(cred, 'severity', 'unknown')
            counts[severity] = counts.get(severity, 0) + 1
        return counts




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
