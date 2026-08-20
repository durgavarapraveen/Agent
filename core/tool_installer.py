"""
ToolInstaller - Dynamically install tools at runtime.
Supports: apt, pip, go, GitHub clone.
Phase 1 of Enterprise system.
"""

import logging
import re
from typing import Dict, List, Optional

from agents.kali_executor import KaliDockerExecutor

logger = logging.getLogger(__name__)


# Known tool → install method mapping
TOOL_INSTALL_MAP = {
    # APT packages
    "nmap": {"method": "apt", "package": "nmap"},
    "masscan": {"method": "apt", "package": "masscan"},
    "sqlmap": {"method": "apt", "package": "sqlmap"},
    "nikto": {"method": "apt", "package": "nikto"},
    "hydra": {"method": "apt", "package": "hydra"},
    "john": {"method": "apt", "package": "john"},
    "hashcat": {"method": "apt", "package": "hashcat"},
    "wpscan": {"method": "apt", "package": "wpscan"},
    "dirb": {"method": "apt", "package": "dirb"},
    "gobuster": {"method": "apt", "package": "gobuster"},
    "sslscan": {"method": "apt", "package": "sslscan"},
    "whois": {"method": "apt", "package": "whois"},
    "dnsrecon": {"method": "apt", "package": "dnsrecon"},
    "dnsenum": {"method": "apt", "package": "dnsenum"},
    "fierce": {"method": "apt", "package": "fierce"},
    "dig": {"method": "apt", "package": "dnsutils"},
    "nslookup": {"method": "apt", "package": "dnsutils"},
    "host": {"method": "apt", "package": "dnsutils"},
    "whatweb": {"method": "apt", "package": "whatweb"},
    "wafw00f": {"method": "apt", "package": "wafw00f"},
    "responder": {"method": "apt", "package": "responder"},
    "enum4linux": {"method": "apt", "package": "enum4linux"},
    "netcat": {"method": "apt", "package": "netcat-openbsd"},
    "nc": {"method": "apt", "package": "netcat-openbsd"},
    "socat": {"method": "apt", "package": "socat"},
    "tcpdump": {"method": "apt", "package": "tcpdump"},
    "traceroute": {"method": "apt", "package": "traceroute"},
    "arp-scan": {"method": "apt", "package": "arp-scan"},
    "ncrack": {"method": "apt", "package": "ncrack"},
    "medusa": {"method": "apt", "package": "medusa"},
    "theharvester": {"method": "apt", "package": "theharvester"},

    # Go tools
    "subfinder": {
        "method": "go",
        "package": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "httpx": {
        "method": "go",
        "package": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "dnsx": {
        "method": "go",
        "package": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    },
    "nuclei": {
        "method": "go",
        "package": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "katana": {
        "method": "go",
        "package": "github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "naabu": {
        "method": "go",
        "package": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    "ffuf": {
        "method": "go",
        "package": "github.com/ffuf/ffuf/v2@latest",
    },
    "assetfinder": {
        "method": "go",
        "package": "github.com/tomnomnom/assetfinder@latest",
    },
    "waybackurls": {
        "method": "go",
        "package": "github.com/tomnomnom/waybackurls@latest",
    },
    "gau": {
        "method": "go",
        "package": "github.com/lc/gau/v2/cmd/gau@latest",
    },
    "dalfox": {
        "method": "go",
        "package": "github.com/hahwul/dalfox/v2@latest",
    },
    "feroxbuster": {
        "method": "go",
        "package": "github.com/epi052/feroxbuster@latest",
    },

    # Pip tools
    "arjun": {"method": "pip", "package": "arjun"},
    "dirsearch": {"method": "pip", "package": "dirsearch"},
    "paramspider": {"method": "pip", "package": "paramspider"},
    "sslyze": {"method": "pip", "package": "sslyze"},
    "pwntools": {"method": "pip", "package": "pwntools"},
    "impacket": {"method": "pip", "package": "impacket"},
    "crackmapexec": {"method": "pip", "package": "crackmapexec"},
    "bloodhound": {"method": "pip", "package": "bloodhound"},

    # GitHub clone
    "linpeas": {
        "method": "github",
        "repo": "https://github.com/carlospolop/PEASS-ng.git",
        "post_install": "chmod +x /pentesting/tools/PEASS-ng/linPEAS/linpeas.sh",
    },
    "linenum": {
        "method": "github",
        "repo": "https://github.com/rebootuser/LinEnum.git",
        "post_install": "chmod +x /pentesting/tools/LinEnum/LinEnum.sh",
    },
    "pspy": {
        "method": "github",
        "repo": "https://github.com/DominicBreuker/pspy.git",
    },
}


class ToolInstaller:
    """Install tools dynamically inside Docker container."""

    def __init__(self):
        self.installed: Dict[str, bool] = {}
        self.failed: Dict[str, str] = {}

    def is_installed(self, tool_name: str) -> bool:
        """Check if tool is already available."""
        # Check cache first
        if tool_name in self.installed:
            return self.installed[tool_name]

        # Check in Docker
        result = KaliDockerExecutor.run(
            f"which {tool_name} 2>/dev/null || command -v {tool_name} 2>/dev/null",
            timeout=10,
        )

        available = result["status"] == "success" and result.get("stdout", "").strip()
        self.installed[tool_name] = bool(available)
        return bool(available)

    def install(self, tool_name: str) -> bool:
        """
        Install a tool. Returns True if successful.
        Tries known mapping first, then guesses install method.
        """
        tool_lower = tool_name.lower().strip()

        # Already installed?
        if self.is_installed(tool_lower):
            logger.debug(f"Tool '{tool_lower}' already installed")
            return True

        # Already failed?
        if tool_lower in self.failed:
            logger.debug(f"Tool '{tool_lower}' previously failed: {self.failed[tool_lower]}")
            return False

        # Known tool?
        if tool_lower in TOOL_INSTALL_MAP:
            info = TOOL_INSTALL_MAP[tool_lower]
            method = info["method"]

            logger.info(f"Installing '{tool_lower}' via {method}...")

            if method == "apt":
                success = self._install_apt(info["package"])
            elif method == "pip":
                success = self._install_pip(info["package"])
            elif method == "go":
                success = self._install_go(info["package"], tool_lower)
            elif method == "github":
                success = self._install_github(
                    info["repo"], info.get("post_install", "")
                )
            else:
                logger.error(f"Unknown install method: {method}")
                success = False

            if success:
                self.installed[tool_lower] = True
                logger.info(f"✓ Installed '{tool_lower}'")
            else:
                self.failed[tool_lower] = f"{method} install failed"
                logger.error(f"✗ Failed to install '{tool_lower}'")

            return success

        # Unknown tool - try apt first, then pip
        logger.info(f"Unknown tool '{tool_lower}', trying apt...")
        if self._install_apt(tool_lower):
            self.installed[tool_lower] = True
            return True

        logger.info(f"apt failed for '{tool_lower}', trying pip...")
        if self._install_pip(tool_lower):
            self.installed[tool_lower] = True
            return True

        self.failed[tool_lower] = "no install method found"
        return False

    def install_multiple(self, tools: List[str]) -> Dict[str, bool]:
        """Install multiple tools. Returns {tool: success}."""
        results = {}
        for tool in tools:
            results[tool] = self.install(tool)
        return results

    def validate_tools(self, tools: List[str]) -> Dict[str, bool]:
        """Check which tools are available, install missing ones."""
        results = {}
        for tool in tools:
            if self.is_installed(tool):
                results[tool] = True
            else:
                results[tool] = self.install(tool)
        return results

    # ═══════════════════════════════════════════════════════════════
    # Install Methods
    # ═══════════════════════════════════════════════════════════════

    def _install_apt(self, package: str) -> bool:
        """Install via apt-get."""
        # Update package list first
        KaliDockerExecutor.run(
            "apt-get update -qq 2>/dev/null",
            timeout=60,
        )

        result = KaliDockerExecutor.run(
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {package} 2>&1",
            timeout=120,
        )

        return result["status"] == "success"

    def _install_pip(self, package: str) -> bool:
        """Install via pip."""
        result = KaliDockerExecutor.run(
            f"pip3 install --break-system-packages -q {package} 2>&1",
            timeout=120,
        )
        return result["status"] == "success"

    def _install_go(self, package: str, binary_name: str = "") -> bool:
        """Install via go install."""
        result = KaliDockerExecutor.run(
            f"go install -v {package} 2>&1",
            timeout=300,
        )

        if result["status"] != "success":
            return False

        # Copy to PATH
        if binary_name:
            KaliDockerExecutor.run(
                f"cp /root/go/bin/{binary_name} /usr/local/bin/ 2>/dev/null; "
                f"chmod +x /usr/local/bin/{binary_name} 2>/dev/null",
                timeout=10,
            )

        return True

    def _install_github(self, repo_url: str, post_install: str = "") -> bool:
        """Clone from GitHub."""
        # Create tools directory
        KaliDockerExecutor.run("mkdir -p /pentesting/tools", timeout=5)

        result = KaliDockerExecutor.run(
            f"cd /pentesting/tools && git clone --depth 1 {repo_url} 2>&1",
            timeout=120,
        )

        if result["status"] != "success":
            return False

        if post_install:
            KaliDockerExecutor.run(post_install, timeout=30)

        return True

    # ═══════════════════════════════════════════════════════════════
    # Status
    # ═══════════════════════════════════════════════════════════════

    def get_status(self) -> Dict:
        """Get installation status."""
        return {
            "installed": dict(self.installed),
            "failed": dict(self.failed),
            "installed_count": sum(1 for v in self.installed.values() if v),
            "failed_count": len(self.failed),
        }

    def list_available(self) -> List[str]:
        """List all known installable tools."""
        return sorted(TOOL_INSTALL_MAP.keys())