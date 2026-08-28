"""
Live Intelligence Test
Fetches real-time threat intelligence from NVD, GitHub, Shodan, and MITRE using API keys from .env.

Run: python test_live_intelligence.py
"""

import asyncio
import json
import sys
import os

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import get_config
from core.intelligence_fetcher import IntelligenceFetcher


async def run_live_tests():
    print("=" * 70)
    print("LIVE THREAT INTELLIGENCE TEST (NVD, GITHUB, SHODAN, MITRE)")
    print("=" * 70)

    # 1. Load API keys from .env
    config = get_config()
    nvd_key = config.get("NVD_API_KEY", "")
    github_token = config.get("GITHUB_TOKEN", "")
    shodan_key = config.get("SHODAN_API_KEY", "")

    print(f"[*] API Keys Configured:")
    print(f"    - NVD Key:     {'[SET]' if nvd_key else '[NOT SET]'}")
    print(f"    - GitHub Token: {'[SET]' if github_token else '[NOT SET]'}")
    print(f"    - Shodan Key:  {'[SET]' if shodan_key else '[NOT SET]'}")

    fetcher = IntelligenceFetcher(
        shodan_key=shodan_key,
        github_token=github_token,
        nvd_key=nvd_key
    )

    # -------------------------------------------------------------
    # TEST 1: NVD CVE Search (with API key)
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("1. NVD (NIST) CVE Search")
    print("=" * 70)
    cves = await fetcher.search_nvd("apache", "2.4.49", max_results=3)
    if cves:
        print(f"[✓] Successfully retrieved {len(cves)} CVEs from NVD:")
        for cve in cves:
            print(f"    • {cve['cve_id']} | CVSS: {cve['cvss']} ({cve['severity']})")
            print(f"      Description: {cve['description'][:120]}...")
            if cve.get('cwes'):
                print(f"      CWEs: {', '.join(cve['cwes'])}")
    else:
        print("[!] NVD search returned no results or was rate-limited.")

    # -------------------------------------------------------------
    # TEST 2: GitHub Exploit / PoC Search (with GitHub Token)
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("2. GitHub Exploit & PoC Search")
    print("=" * 70)
    exploits = await fetcher.search_github_exploits(cve_id="CVE-2021-44228", max_results=3)
    if exploits:
        print(f"[✓] Successfully retrieved {len(exploits)} exploit repos from GitHub:")
        for exp in exploits:
            print(f"    • {exp['name']} (Stars: {exp['stars']}, Language: {exp.get('language', 'N/A')})")
            print(f"      URL: {exp['url']}")
            print(f"      Reliability Score: {exp['reliability']:.2f}")
    else:
        print("[!] GitHub search returned no results.")

    # -------------------------------------------------------------
    # TEST 3: Shodan Internet Recon (with Shodan API Key)
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("3. Shodan Host Lookup")
    print("=" * 70)
    target_ip = "1.1.1.1"  # Cloudflare public DNS host lookup
    shodan_data = await fetcher.search_shodan(ip=target_ip)
    if shodan_data:
        print(f"[✓] Successfully retrieved Shodan data for IP {target_ip}:")
        print(f"    • Hostnames: {', '.join(shodan_data.get('hostnames', []))}")
        print(f"    • Organization: {shodan_data.get('org', 'N/A')} ({shodan_data.get('isp', 'N/A')})")
        print(f"    • Open Ports: {shodan_data.get('ports', [])}")
        services = shodan_data.get("services", [])
        if services:
            print(f"    • Sample Services ({len(services)} found):")
            for svc in services[:3]:
                print(f"      - Port {svc.get('port')}/{svc.get('transport')}: {svc.get('product', 'Unknown')} {svc.get('version', '')}")
    else:
        print("[!] Shodan search returned no data or API key is invalid.")

    # -------------------------------------------------------------
    # TEST 4: MITRE ATT&CK Mapping
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("4. MITRE ATT&CK Mapping")
    print("=" * 70)
    mitre_techs = await fetcher.search_mitre(technique_id="T1190")
    if mitre_techs:
        tech = mitre_techs[0]
        print(f"[✓] Technique Found: {tech['id']} - {tech['name']}")
        print(f"    • Tactic: {tech['tactic']}")
        print(f"    • Description: {tech['description'][:120]}...")
        print(f"    • Recommended Mitigations: {', '.join(tech.get('mitigations', [])[:4])}")

    print("\n" + "=" * 70)
    print("[✓] LIVE THREAT INTELLIGENCE TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_live_tests())
