
import base64
import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ScreenshotResult:
    finding_title: str
    url: str
    screenshot_path: str = ""
    base64_data: str = ""
    success: bool = False
    error: str = ""
    timestamp: float = field(default_factory=time.time)
    artifact_id: int = 0   # scan_artifacts.id when persisted to Postgres


class ScreenshotCapture:

    def __init__(self, output_dir: str = None, scan_id: str = None):
        from core.common.reports_config import reports_enabled, reports_dir
        self._reports_enabled = reports_enabled()
        self.scan_id = scan_id  # when set, captured PNGs are persisted to Postgres
        if output_dir is None:
            output_dir = str(reports_dir() / "evidence")
        self.output_dir = Path(output_dir)
        # Only touch disk if reports/ is enabled; otherwise use a tempdir for the
        # in-flight docker→host copy.
        if self._reports_enabled:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        else:
            import tempfile
            self.output_dir = Path(tempfile.mkdtemp(prefix="ag_screenshot_"))
        self.results: List[ScreenshotResult] = []
        self._browser_available: Optional[bool] = None

    def _check_browser(self) -> bool:
        if self._browser_available is not None:
            return self._browser_available

        from agents.kali_executor import KaliDockerExecutor

        for browser in ["chromium", "google-chrome", "firefox"]:
            result = KaliDockerExecutor.run(f"which {browser}", timeout=5)
            if result.get("status") == "success" and result.get("stdout", "").strip():
                self._browser_available = True
                logger.info(f"[Screenshot] Browser found: {browser}")
                return True

        # Try installing chromium
        result = KaliDockerExecutor.run(
            "apt-get install -y --no-install-recommends chromium 2>/dev/null", timeout=120
        )
        if result.get("status") == "success":
            self._browser_available = True
            return True

        # Fallback: try cutycapt or wkhtmltoimage
        for tool in ["cutycapt", "wkhtmltoimage"]:
            result = KaliDockerExecutor.run(f"which {tool}", timeout=5)
            if result.get("status") == "success" and result.get("stdout", "").strip():
                self._browser_available = True
                return True

        self._browser_available = False
        logger.warning("[Screenshot] No headless browser available")
        return False

    def _sanitize_filename(self, text: str) -> str:
        safe = re.sub(r'[^\w\-.]', '_', text)[:80]
        return safe.strip('_') or 'screenshot'

    def _capture_with_chrome(self, url: str, output_file: str, timeout: int = 15) -> bool:
        from agents.kali_executor import KaliDockerExecutor

        docker_path = f"/tmp/{os.path.basename(output_file)}"
        cmd = (
            f"timeout {timeout} chromium --headless --disable-gpu --no-sandbox "
            f"--disable-dev-shm-usage --window-size=1280,1024 "
            f"--screenshot={docker_path} '{url}' 2>/dev/null"
        )
        result = KaliDockerExecutor.run(cmd, timeout=timeout + 10)

        if result.get("status") != "success":
            # Try google-chrome
            cmd = cmd.replace("chromium", "google-chrome")
            result = KaliDockerExecutor.run(cmd, timeout=timeout + 10)

        if result.get("status") != "success":
            return False

        # Copy from container to host
        container = KaliDockerExecutor.get_container(auto_create=False)
        if container:
            import subprocess
            try:
                subprocess.run(
                    ["docker", "cp", f"{container}:{docker_path}", output_file],
                    shell=False, capture_output=True, timeout=10
                )
                return Path(output_file).exists()
            except Exception:
                pass

        return False

    def _capture_with_cutycapt(self, url: str, output_file: str, timeout: int = 15) -> bool:
        from agents.kali_executor import KaliDockerExecutor

        docker_path = f"/tmp/{os.path.basename(output_file)}"
        cmd = (
            f"timeout {timeout} cutycapt --url='{url}' "
            f"--out={docker_path} --min-width=1280 --min-height=1024 2>/dev/null"
        )
        result = KaliDockerExecutor.run(cmd, timeout=timeout + 10)

        if result.get("status") == "success":
            container = KaliDockerExecutor.get_container(auto_create=False)
            if container:
                import subprocess
                try:
                    subprocess.run(
                        ["docker", "cp", f"{container}:{docker_path}", output_file],
                        shell=False, capture_output=True, timeout=10
                    )
                    return Path(output_file).exists()
                except Exception:
                    pass
        return False

    def _capture_with_curl(self, url: str, output_file: str, timeout: int = 10) -> bool:
        from agents.kali_executor import KaliDockerExecutor

        cmd = f'curl -s -L -k --max-time {timeout} "{url}" | head -c 50000'
        result = KaliDockerExecutor.run(cmd, timeout=timeout + 5)
        if result.get("status") == "success" and result.get("stdout", "").strip():
            txt_file = output_file.replace(".png", ".html")
            try:
                Path(txt_file).write_text(result["stdout"][:50000], encoding="utf-8")
                return True
            except Exception:
                pass
        return False

    def capture_screenshot(self, url: str, finding_title: str, timeout: int = 15) -> ScreenshotResult:
        result = ScreenshotResult(finding_title=finding_title, url=url)
        safe_name = self._sanitize_filename(finding_title)
        ts = int(time.time())
        filename = f"{safe_name}_{ts}.png"
        output_file = str(self.output_dir / filename)

        if not url or not url.startswith(("http://", "https://")):
            result.error = "Invalid URL"
            return result

        if self._check_browser():
            if self._capture_with_chrome(url, output_file, timeout):
                result.screenshot_path = output_file
                result.success = True
            elif self._capture_with_cutycapt(url, output_file, timeout):
                result.screenshot_path = output_file
                result.success = True

        if not result.success:
            html_file = output_file.replace(".png", ".html")
            if self._capture_with_curl(url, html_file, timeout):
                result.screenshot_path = html_file
                result.success = True

        if result.success and result.screenshot_path:
            try:
                with open(result.screenshot_path, "rb") as f:
                    data = f.read()
                    if len(data) < 5_000_000:
                        result.base64_data = base64.b64encode(data).decode("ascii")
                # Persist to Postgres so the UI can show it.
                if self.scan_id and data:
                    try:
                        from core.database.pg_store import ScanArtifactRepo
                        ext = result.screenshot_path.rsplit(".", 1)[-1].lower()
                        mime = "image/png" if ext == "png" else (
                            "text/html" if ext == "html" else "application/octet-stream")
                        aid = ScanArtifactRepo.insert(
                            self.scan_id, "screenshot", filename, data,
                            mime_type=mime,
                            metadata={"url": url, "finding_title": finding_title})
                        result.artifact_id = aid
                    except Exception as e:
                        logger.debug(f"[Screenshot] DB persist failed: {e}")
            except Exception:
                pass

        if result.success:
            logger.info(f"[Screenshot] Captured: {finding_title} -> {result.screenshot_path}")
        else:
            result.error = "All capture methods failed"
            logger.warning(f"[Screenshot] Failed for {url}: {result.error}")

        self.results.append(result)
        return result

    def capture_findings(self, findings: List[Dict], max_screenshots: int = 20) -> List[ScreenshotResult]:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get((f.get("severity") or "INFO").upper(), 4)
        )

        captured = 0
        seen_urls = set()

        for f in sorted_findings:
            if captured >= max_screenshots:
                break

            url = f.get("target") or f.get("location") or f.get("url") or ""
            if not url or not url.startswith("http"):
                continue

            url_base = url.split("?")[0].rstrip("/")
            if url_base in seen_urls:
                continue
            seen_urls.add(url_base)

            title = f.get("title", f"Finding_{captured}")
            result = self.capture_screenshot(url, title)
            if result.success:
                f["screenshot_path"] = result.screenshot_path
                f["screenshot_base64"] = result.base64_data[:100] + "..." if result.base64_data else ""
                captured += 1

        logger.info(f"[Screenshot] Captured {captured}/{len(sorted_findings)} finding screenshots")
        return self.results

    def get_evidence_summary(self) -> Dict:
        return {
            "total_attempted": len(self.results),
            "successful": len([r for r in self.results if r.success]),
            "failed": len([r for r in self.results if not r.success]),
            "screenshots": [
                {
                    "finding": r.finding_title,
                    "url": r.url,
                    "path": r.screenshot_path,
                    "has_image": r.screenshot_path.endswith(".png"),
                }
                for r in self.results if r.success
            ],
        }
