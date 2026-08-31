"""
Kali Docker Executor - Runs real Kali tools inside Docker from Windows/Linux/Mac.
Auto-detects or provisions Kali Docker containers and auto-installs required tools on first use.
"""

import logging
import os
import shlex
import subprocess
from typing import Dict, List, Optional

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

        # Web recon & Scanning
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
        "playwright": "python3-playwright",

        # SSL/TLS
        "sslscan": "sslscan",
        "sslyze": "sslyze",
        "testssl.sh": "testssl.sh",

        # SMB / Network / Exploitation
        "enum4linux": "enum4linux",
        "enum4linux-ng": "enum4linux-ng",
        "netexec": "netexec",
        "crackmapexec": "crackmapexec",
        "responder": "responder",
        "hydra": "hydra",
        "commix": "commix",
        "xsser": "xsser",

        # Utilities
        "curl": "curl",
        "wget": "wget",
        "jq": "jq",
    }

    @classmethod
    def get_container(cls, auto_create: bool = True) -> Optional[str]:
        """Auto-detect or automatically launch/create Kali container"""
        if cls._container_name:
            r = subprocess.run(
                f"docker ps --filter name={cls._container_name} --format {{{{.Names}}}}",
                shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=5
            )
            if cls._container_name in r.stdout:
                return cls._container_name
            cls._container_name = None

        try:
            r = subprocess.run(
                "docker ps --format {{.Names}}\\t{{.Image}}",
                shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=10
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

            for line in r.stdout.strip().split("\n"):
                name = line.split("\t")[0].strip()
                if not name:
                    continue
                check = subprocess.run(
                    f"docker exec {name} cat /etc/os-release",
                    shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=5
                )
                if "kali" in check.stdout.lower():
                    cls._container_name = name
                    logger.info(f"Kali container detected via os-release: {name}")
                    return name

            # Check stopped containers
            r_stopped = subprocess.run(
                "docker ps -a --filter name=kali-pentesting --format {{.Names}}",
                shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=5
            )
            if "kali-pentesting" in r_stopped.stdout:
                logger.info("[KaliDockerExecutor] Starting existing stopped container 'kali-pentesting-mcp'...")
                subprocess.run("docker start kali-pentesting-mcp", shell=True, capture_output=True, timeout=10)
                cls._container_name = "kali-pentesting-mcp"
                return cls._container_name

            # Auto-create if requested and docker is available
            if auto_create and cls.check_docker():
                logger.info("[KaliDockerExecutor] Auto-creating new Kali container 'kali-pentesting-mcp'...")
                run_cmd = "docker run -dit --name kali-pentesting-mcp kalilinux/kali-rolling bash"
                r_create = subprocess.run(run_cmd, shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=60)
                if r_create.returncode == 0:
                    cls._container_name = "kali-pentesting-mcp"
                    logger.info("[KaliDockerExecutor] Successfully created Kali container 'kali-pentesting-mcp'.")
                    return cls._container_name
                else:
                    logger.error(f"[KaliDockerExecutor] Failed to create container: {r_create.stderr}")

        except Exception as e:
            logger.error(f"Docker detection/creation failed: {e}")

        logger.warning("No Kali container found and could not auto-create.")
        return None

    @classmethod
    def check_docker(cls) -> bool:
        try:
            r = subprocess.run("docker --version", shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    @classmethod
    def is_native_environment(cls) -> bool:
        """Check if we are already executing natively inside Linux/Kali."""
        import shutil
        return os.path.exists("/.dockerenv") or (os.name != "nt" and shutil.which("nmap") is not None)

    @classmethod
    def is_tool_installed(cls, tool: str, bypass_cache: bool = False) -> bool:
        """Check if tool exists in container or local environment"""
        import shutil
        if shutil.which(tool):
            return True
        if tool in cls._installed_tools:
            return True
        if not bypass_cache and tool in cls._checked_tools:
            return False

        if cls.is_native_environment():
            return shutil.which(tool) is not None

        container = cls.get_container()
        if not container:
            return False

        cls._checked_tools.add(tool)
        r = subprocess.run(
            f"docker exec {container} which {tool}",
            shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            cls._installed_tools.add(tool)
            return True
        return False

    @classmethod
    def ensure_tool(cls, tool: str) -> bool:
        """Ensure tool is installed in the Kali container or host environment."""
        if cls.is_tool_installed(tool):
            return True

        package = cls.TOOL_PACKAGES.get(tool, tool)
        container = cls.get_container()
        if not container:
            return False

        logger.info(f"[KaliDockerExecutor] Auto-installing missing tool '{tool}' (apt package: {package})...")
        try:
            # Run update and install as separate commands to avoid shell quote escaping issues on Windows
            up_res = subprocess.run(f"docker exec {container} apt-get update", shell=True, capture_output=True, timeout=120)
            if up_res.returncode != 0:
                subprocess.run(f'docker exec {container} bash -c "rm -rf /var/lib/apt/lists/* && apt-get update"', shell=True, capture_output=True, timeout=120)
            r = subprocess.run(f"docker exec {container} apt-get install -y --no-install-recommends {package}", shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=120)
            if r.returncode == 0 and cls.is_tool_installed(tool, bypass_cache=True):
                logger.info(f"[KaliDockerExecutor] Successfully installed '{tool}'")
                cls._installed_tools.add(tool)
                return True
            else:
                logger.warning(f"[KaliDockerExecutor] Failed to install '{tool}': {r.stderr}")
                return False
        except Exception as e:
            logger.error(f"[KaliDockerExecutor] Exception installing '{tool}': {e}")
            return False

    @classmethod
    def install_all_tools(cls) -> Dict[str, bool]:
        """Bulk auto-install all required tools into the Kali container."""
        container = cls.get_container(auto_create=True)
        results = {}
        packages = list(set(cls.TOOL_PACKAGES.values()))
        logger.info(f"[KaliDockerExecutor] Bulk auto-installing {len(packages)} packages into container '{container}'...")

        try:
            subprocess.run(f"docker exec {container} apt-get update", shell=True, capture_output=True, timeout=120)
            pkg_str = " ".join(packages)
            cmd = f"docker exec {container} apt-get install -y --fix-missing {pkg_str}"
            r = subprocess.run(cmd, shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=600)
            if r.returncode == 0:
                logger.info("[KaliDockerExecutor] Bulk installation completed successfully.")
            else:
                logger.warning(f"[KaliDockerExecutor] Bulk installation output: {r.stderr[:200]}")

            for tool in cls.TOOL_PACKAGES:
                installed = cls.is_tool_installed(tool)
                results[tool] = installed

        except Exception as e:
            logger.error(f"[KaliDockerExecutor] Exception during bulk tool installation: {e}")

        return results

    @classmethod
    def run(cls, command: str, timeout: int = 120, auto_install: bool = True) -> Dict:
        """
        Run command inside Kali container or native Linux environment.
        If first word is a tool that's not installed, auto-install it.
        """
        if cls.is_native_environment():
            timed_cmd = f"timeout --signal=KILL {int(timeout)}s {command}"
            try:
                r = subprocess.run(
                    timed_cmd, shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=int(timeout) + 10
                )
                if r.returncode in (124, 137):
                    return {"status": "timeout", "returncode": r.returncode,
                            "error": f"Command exceeded {timeout}s",
                            "stdout": r.stdout, "stderr": r.stderr}
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

        container = cls.get_container(auto_create=True)
        if not container:
            return {
                "status": "error",
                "error": "No Kali container running",
                "stdout": "", "stderr": ""
            }

        try:
            tool = shlex.split(command)[0]
        except Exception:
            tool = command.split()[0] if command.split() else ""

        if auto_install and tool in cls.TOOL_PACKAGES:
            if not cls.ensure_tool(tool):
                return {
                    "status": "error",
                    "error": f"Tool {tool} not available and could not be installed",
                    "stdout": "", "stderr": ""
                }

        timed_cmd = f"timeout --signal=KILL {int(timeout)}s {command}"
        escaped_cmd = timed_cmd.replace('"', '\\"')
        full = f'docker exec {container} bash -c "{escaped_cmd}"'
        grace = int(timeout) + 15

        try:
            r = subprocess.run(
                full, shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=grace
            )
            if r.returncode in (124, 137):
                return {"status": "timeout", "returncode": r.returncode,
                        "error": f"Command exceeded {timeout}s (killed in-container)",
                        "stdout": r.stdout, "stderr": r.stderr}
            return {
                "status": "success" if r.returncode == 0 else "error",
                "returncode": r.returncode,
                "stdout": r.stdout,
                "stderr": r.stderr,
            }
        except subprocess.TimeoutExpired as e:
            logger.warning(f"[Kali] subprocess backstop timeout after {grace}s: {command[:60]}")
            partial = ""
            try:
                partial = (e.stdout or b"").decode("utf-8", "ignore") if isinstance(e.stdout, bytes) else (e.stdout or "")
            except Exception:
                partial = ""
            return {"status": "timeout", "error": f"Timeout {timeout}s",
                    "stdout": partial, "stderr": ""}
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

        container = cls.get_container(auto_create=True)
        if not container:
            result["error"] = "No Kali container found and auto-creation failed."
            return result

        result["kali"] = True
        result["container"] = container

        if required_tools:
            logger.info(f"Preflight: ensuring {len(required_tools)} tools available...")
            for tool in required_tools:
                result["tools"][tool] = cls.ensure_tool(tool)

        return result