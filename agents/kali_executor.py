"""
Kali Docker Executor - Runs real Kali tools inside Docker from Windows
Auto-installs missing tools on first use
"""

import subprocess
import logging
import shlex
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class KaliDockerExecutor:
    """Executes commands inside a running Kali Docker container from Windows/Linux/Mac"""

    _container_name: Optional[str] = None
    _installed_tools: set = set()
    _checked_tools: set = set()

    # Package mapping: tool_name -> apt package name
    TOOL_PACKAGES = {
        # DNS / Subdomain
        "nmap": "nmap",
        "masscan": "masscan",
        "amass": "amass",
        "subfinder": "subfinder",
        "assetfinder": "assetfinder",
        "dnsenum": "dnsenum",
        "fierce": "fierce",
        "dnsrecon": "dnsrecon",
        "dig": "dnsutils",
        "host": "dnsutils",
        "nslookup": "dnsutils",
        "whois": "whois",
        "theharvester": "theharvester",

        # Web recon
        "gobuster": "gobuster",
        "feroxbuster": "feroxbuster",
        "dirb": "dirb",
        "dirsearch": "dirsearch",
        "ffuf": "ffuf",
        "nikto": "nikto",
        "nuclei": "nuclei",
        "wpscan": "wpscan",
        "whatweb": "whatweb",
        "wafw00f": "wafw00f",
        "httpx": "httpx-toolkit",
        "katana": "katana",
        "arjun": "arjun",
        "paramspider": "paramspider",
        "dalfox": "dalfox",

        # SSL/TLS
        "sslscan": "sslscan",
        "sslyze": "sslyze",
        "testssl.sh": "testssl.sh",

        # SMB / Network
        "enum4linux": "enum4linux",
        "enum4linux-ng": "enum4linux-ng",
        "netexec": "netexec",
        "crackmapexec": "crackmapexec",
        "responder": "responder",

        # Utilities
        "curl": "curl",
        "wget": "wget",
        "jq": "jq",
    }

    @classmethod
    def get_container(cls) -> Optional[str]:
        """Auto-detect running Kali container"""
        if cls._container_name:
            # Verify it's still running
            r = subprocess.run(
                f"docker ps --filter name={cls._container_name} --format {{{{.Names}}}}",
                shell=True, capture_output=True, text=True, timeout=5
            )
            if cls._container_name in r.stdout:
                return cls._container_name
            cls._container_name = None

        try:
            r = subprocess.run(
                "docker ps --format {{.Names}}\\t{{.Image}}",
                shell=True, capture_output=True, text=True, timeout=10
            )
            for line in r.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t")
                name = parts[0].strip()
                image = parts[1].strip().lower() if len(parts) > 1 else ""

                if "kali" in image or "kali" in name.lower():
                    cls._container_name = name
                    logger.info(f"Kali container detected: {name} (image: {image})")
                    return name

            # No Kali by image name - check /etc/os-release inside each
            for line in r.stdout.strip().split("\n"):
                name = line.split("\t")[0].strip()
                if not name:
                    continue
                check = subprocess.run(
                    f"docker exec {name} cat /etc/os-release",
                    shell=True, capture_output=True, text=True, timeout=5
                )
                if "kali" in check.stdout.lower():
                    cls._container_name = name
                    logger.info(f"Kali container detected via os-release: {name}")
                    return name

        except Exception as e:
            logger.error(f"Docker detection failed: {e}")

        logger.warning("No Kali container found. Start one with: docker run -dit --name kali kalilinux/kali-rolling")
        return None

    @classmethod
    def check_docker(cls) -> bool:
        try:
            r = subprocess.run("docker --version", shell=True, capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except:
            return False

    @classmethod
    def is_tool_installed(cls, tool: str) -> bool:
        """Check if tool exists in container"""
        if tool in cls._installed_tools:
            return True
        if tool in cls._checked_tools:
            return False

        container = cls.get_container()
        if not container:
            return False

        cls._checked_tools.add(tool)
        r = subprocess.run(
            f"docker exec {container} which {tool}",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            cls._installed_tools.add(tool)
            return True
        return False

    @classmethod
    def install_tool(cls, tool: str) -> bool:
        """Install tool via apt-get in Kali container"""
        container = cls.get_container()
        if not container:
            return False

        pkg = cls.TOOL_PACKAGES.get(tool, tool)
        logger.info(f"Installing {tool} (package: {pkg}) in Kali container...")

        # Update once per session (fast if already updated)
        subprocess.run(
            f"docker exec {container} bash -c 'apt-get update -qq 2>&1 | tail -3'",
            shell=True, capture_output=True, text=True, timeout=120
        )

        r = subprocess.run(
            f"docker exec {container} bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkg} 2>&1 | tail -3'",
            shell=True, capture_output=True, text=True, timeout=300
        )

        if cls.is_tool_installed(tool):
            logger.info(f"✓ Installed {tool}")
            return True
        else:
            logger.warning(f"✗ Failed to install {tool}: {r.stdout[:200]}")
            # Reset check flag so we don't loop
            cls._checked_tools.discard(tool)
            return False

    @classmethod
    def ensure_tool(cls, tool: str) -> bool:
        """Make sure tool is available, install if missing"""
        if cls.is_tool_installed(tool):
            return True
        return cls.install_tool(tool)

    @classmethod
    def run(cls, command: str, timeout: int = 120, auto_install: bool = True) -> Dict:
        """
        Run command inside Kali container.
        If first word is a tool that's not installed, auto-install it.
        """
        container = cls.get_container()
        if not container:
            return {
                "status": "error",
                "error": "No Kali container running",
                "stdout": "", "stderr": ""
            }

        # Extract tool name (first word)
        try:
            tool = shlex.split(command)[0]
        except:
            tool = command.split()[0] if command.split() else ""

        # Auto-install if needed
        if auto_install and tool in cls.TOOL_PACKAGES:
            if not cls.ensure_tool(tool):
                return {
                    "status": "error",
                    "error": f"Tool {tool} not available and could not be installed",
                    "stdout": "", "stderr": ""
                }

        # Execute inside container
        # Wrap in bash -c to support pipes, redirects, etc.
        escaped_cmd = command.replace('"', '\\"')
        full = f'docker exec {container} bash -c "{escaped_cmd}"'

        try:
            r = subprocess.run(
                full, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return {
                "status": "success" if r.returncode == 0 else "error",
                "returncode": r.returncode,
                "stdout": r.stdout,
                "stderr": r.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": f"Timeout {timeout}s", "stdout": "", "stderr": ""}
        except Exception as e:
            return {"status": "error", "error": str(e), "stdout": "", "stderr": ""}

    @classmethod
    def preflight(cls, required_tools: List[str] = None) -> Dict:
        """Verify Docker + Kali container + install common tools upfront"""
        result = {"docker": False, "kali": False, "container": None, "tools": {}}

        if not cls.check_docker():
            result["error"] = "Docker not installed or not running"
            return result
        result["docker"] = True

        container = cls.get_container()
        if not container:
            result["error"] = "No Kali container found. Run: docker run -dit --name kali kalilinux/kali-rolling"
            return result

        result["kali"] = True
        result["container"] = container

        # Install requested tools
        if required_tools:
            logger.info(f"Preflight: ensuring {len(required_tools)} tools available...")
            for tool in required_tools:
                result["tools"][tool] = cls.ensure_tool(tool)

        return result