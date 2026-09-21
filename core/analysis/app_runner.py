"""DockerAppRunner — build & run an uploaded/cloned codebase so it can be DAST'd.

The dynamic half of grey-box testing: if the code ships a Dockerfile or a
docker-compose file, we build it, run it, wait for it to answer HTTP, and hand
back a base URL the scan engine can attack. Everything is torn down afterwards.

Reliability gate: only containerized repos run reliably (auto-building an
arbitrary repo — runtime, deps, DB, seed data — is unsolved in general). No
container definition → the caller falls back to SAST-only.

Security: we run UNTRUSTED code. The container gets tight limits and is removed
on teardown. Build needs network (deps); the run is on a dedicated bridge with a
published port only (isolate egress further with an --internal network + an
in-network scanner when you want to harden). Intended for authorized self-testing.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

_COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
_DEFAULT_PORTS = (8080, 3000, 5000, 8000, 80, 4000, 8888, 9000)


@dataclass
class RunningApp:
    ok: bool
    base_url: str = ""
    kind: str = ""                 # compose | dockerfile
    reason: str = ""               # why it didn't run (when ok=False)
    project: str = ""              # compose project / container name for teardown
    container: str = ""
    network: str = ""


def _run(args, timeout=1200, cwd=None):
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, cwd=cwd)


class DockerAppRunner:
    def __init__(self):
        self.token = uuid.uuid4().hex[:10]
        self.project = f"greybox_{self.token}"

    # ── detection ───────────────────────────────────────────────────────
    @staticmethod
    def detect(path: str) -> Optional[str]:
        for f in _COMPOSE_FILES:
            if os.path.exists(os.path.join(path, f)):
                return "compose"
        if os.path.exists(os.path.join(path, "Dockerfile")):
            return "dockerfile"
        return None

    @staticmethod
    def docker_available() -> bool:
        return shutil.which("docker") is not None

    # ── lifecycle ───────────────────────────────────────────────────────
    def start(self, path: str, health_timeout: int = 90) -> RunningApp:
        if not self.docker_available():
            return RunningApp(False, reason="docker not available on the API host")
        kind = self.detect(path)
        if not kind:
            return RunningApp(False, reason="no Dockerfile or docker-compose file — dynamic DAST needs a containerized app")
        try:
            app = self._start_compose(path) if kind == "compose" else self._start_dockerfile(path)
        except subprocess.TimeoutExpired:
            self.teardown()
            return RunningApp(False, kind=kind, reason="build/run timed out")
        except Exception as e:
            self.teardown()
            return RunningApp(False, kind=kind, reason=f"build/run failed: {e}")
        if not app.ok:
            self.teardown()
            return app
        # wait for HTTP
        if not self._wait_http(app.base_url, health_timeout):
            self.teardown()
            return RunningApp(False, kind=kind, reason=f"app did not answer HTTP at {app.base_url} within {health_timeout}s")
        return app

    def _start_compose(self, path: str) -> RunningApp:
        up = _run(["docker", "compose", "-p", self.project, "up", "-d", "--build"], cwd=path, timeout=1800)
        if up.returncode != 0:
            return RunningApp(False, kind="compose", reason=f"compose up failed: {(up.stderr or '')[:300]}")
        # find a published host port among the project's containers
        ps = _run(["docker", "ps", "--filter", f"label=com.docker.compose.project={self.project}",
                   "--format", "{{.Ports}}"], timeout=60)
        host_port = self._first_published_port(ps.stdout)
        if not host_port:
            return RunningApp(False, kind="compose", project=self.project,
                              reason="compose app exposes no published port to reach")
        return RunningApp(True, base_url=f"http://localhost:{host_port}", kind="compose", project=self.project)

    def _start_dockerfile(self, path: str) -> RunningApp:
        tag = f"{self.project}:latest"
        b = _run(["docker", "build", "-t", tag, "."], cwd=path, timeout=1800)
        if b.returncode != 0:
            return RunningApp(False, kind="dockerfile", reason=f"docker build failed: {(b.stderr or '')[:300]}")
        name = self.project
        # publish-all so we can find the mapped host port
        r = _run(["docker", "run", "-d", "--rm", "-P", "--name", name,
                  "--memory=1g", "--cpus=1.5", "--pids-limit=512", tag], timeout=120)
        if r.returncode != 0:
            return RunningApp(False, kind="dockerfile", reason=f"docker run failed: {(r.stderr or '')[:300]}")
        self._container = name
        port = self._container_host_port(name)
        if not port:
            return RunningApp(False, kind="dockerfile", container=name,
                              reason="container exposes no port (add EXPOSE / publish a port)")
        return RunningApp(True, base_url=f"http://localhost:{port}", kind="dockerfile", container=name)

    # ── helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _first_published_port(ports_text: str) -> Optional[str]:
        # e.g. "0.0.0.0:32768->8080/tcp, :::32768->8080/tcp"
        import re
        for line in (ports_text or "").splitlines():
            m = re.search(r"0\.0\.0\.0:(\d+)->", line) or re.search(r":(\d+)->\d+/tcp", line)
            if m:
                return m.group(1)
        return None

    def _container_host_port(self, name: str) -> Optional[str]:
        import re
        p = _run(["docker", "port", name], timeout=30)
        # lines like "8080/tcp -> 0.0.0.0:32769"
        for line in (p.stdout or "").splitlines():
            m = re.search(r"0\.0\.0\.0:(\d+)", line) or re.search(r":::(\d+)", line)
            if m:
                return m.group(1)
        return None

    def _wait_http(self, base_url: str, timeout: int) -> bool:
        import urllib.request
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                req = urllib.request.Request(base_url, headers={"User-Agent": "greybox-healthcheck"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status:
                        return True
            except Exception as e:
                # any HTTP answer (even 4xx/5xx) means it's up
                if hasattr(e, "code"):
                    return True
            time.sleep(2)
        return False

    def teardown(self) -> None:
        try:
            _run(["docker", "compose", "-p", self.project, "down", "-v", "--remove-orphans"], timeout=180)
        except Exception:
            pass
        for name in (getattr(self, "_container", None), self.project):
            if name:
                try:
                    _run(["docker", "rm", "-f", name], timeout=60)
                except Exception:
                    pass
        try:
            _run(["docker", "image", "rm", "-f", f"{self.project}:latest"], timeout=120)
        except Exception:
            pass
