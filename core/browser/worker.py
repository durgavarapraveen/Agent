
import logging
import asyncio
import os
import shutil
import tempfile
import uuid
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class BrowserWorker:
    def __init__(self, browser_binary: str = "chromium", timeout: int = 30):
        self.browser_binary = browser_binary
        self.timeout = timeout
        self.session_id = uuid.uuid4().hex
        self._profile_dir = None
        self._process = None

    def _create_ephemeral_profile(self) -> str:
        if self._profile_dir and os.path.exists(self._profile_dir):
            return self._profile_dir
        self._profile_dir = tempfile.mkdtemp(prefix=f"browser_profile_{self.session_id}_")
        return self._profile_dir

    def _cleanup_profile(self):
        if self._profile_dir and os.path.exists(self._profile_dir):
            shutil.rmtree(self._profile_dir, ignore_errors=True)
            self._profile_dir = None

    def _build_command(self, url: str) -> list[str]:
        profile_dir = self._create_ephemeral_profile()
        return [
            self.browser_binary,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--user-data-dir={profile_dir}",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-default-apps",
            "--mute-audio",
            "--no-first-run",
            "--safebrowsing-disable-auto-update",
            "--disable-client-side-phishing-detection",
            "--disable-features=TranslateUI,BlinkGenPropertyTrees,IsolateOrigins,site-per-process",
            "--disable-web-security",
            "--disable-webrtc", 
            "--deny-permission-prompts",
            "--window-size=1280,1024",
            url
        ]

    async def _enforce_egress_policy(self, url: str) -> bool:
        try:
            from core.network.broker import NetworkBroker
            broker = NetworkBroker()
            if not broker.is_authorized(url):
                logger.warning(f"BrowserWorker: Egress blocked for {url}")
                return False
        except ImportError:
            logger.warning("BrowserWorker: NetworkBroker unavailable, assuming closed egress.")
            return False
        return True

    async def execute(self, url: str, run_timeout: Optional[int] = None) -> Dict[str, Any]:
        timeout_to_use = run_timeout or self.timeout
        
        if not await self._enforce_egress_policy(url):
            return {"status": "blocked", "reason": "egress_policy_violation", "url": url}
            
        cmd = self._build_command(url)
        logger.info(f"BrowserWorker [{self.session_id}]: Navigating to {url}")
        
        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            out, err = await asyncio.wait_for(self._process.communicate(), timeout=timeout_to_use)
            
            return {
                "status": "success",
                "exit_code": self._process.returncode,
                "stdout": (out or b"").decode("utf-8", "ignore"),
                "stderr": (err or b"").decode("utf-8", "ignore"),
                "session_id": self.session_id
            }
            
        except asyncio.TimeoutError:
            if self._process:
                try:
                    self._process.kill()
                except OSError:
                    pass
            return {"status": "timeout", "reason": f"execution exceeded {timeout_to_use}s"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}
        finally:
            self._cleanup_profile()
