"""P0.10 — Docker socket removal guard.

Ensures that:
  1. /var/run/docker.sock is never mounted into the web container
  2. DOCKER_HOST env var does not point to the socket
  3. Docker communication uses TCP (network) not socket
  4. Runtime check blocks if socket is detected

The web container communicates with the Kali container via the
Docker API over TCP or via the `docker-compose exec` network path,
never through a raw socket mount.
"""
from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

_UNIX_SOCKET_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/docker/docker.sock",
)

_WINDOWS_PIPE_PATHS = (
    r"\\.\pipe\docker_engine",
    r"\\.\pipe\docker_engine_windows",
)


@dataclass(frozen=True)
class SocketGuardResult:
    safe: bool
    socket_found: str = ""
    docker_host_value: str = ""
    reason: str = ""


def check_socket_mount() -> SocketGuardResult:
    if sys.platform == "win32":
        check_paths = _WINDOWS_PIPE_PATHS
    else:
        check_paths = _UNIX_SOCKET_PATHS

    for path in check_paths:
        if os.path.exists(path):
            logger.critical("[DockerSocketGuard] %s is mounted — container escape risk", path)
            return SocketGuardResult(
                safe=False, socket_found=path,
                reason=f"Docker socket mounted at {path}")

    docker_host = os.environ.get("DOCKER_HOST", "")
    if docker_host and ("docker.sock" in docker_host.lower()
                        or "docker_engine" in docker_host.lower()):
        logger.critical("[DockerSocketGuard] DOCKER_HOST points to socket: %s", docker_host)
        return SocketGuardResult(
            safe=False, docker_host_value=docker_host,
            reason=f"DOCKER_HOST references socket: {docker_host}")

    return SocketGuardResult(safe=True, reason="no socket detected")


def enforce_no_socket(fail_hard: bool = False) -> SocketGuardResult:
    result = check_socket_mount()
    if not result.safe:
        msg = f"[P0.10] Docker socket violation: {result.reason}"
        if fail_hard:
            raise RuntimeError(msg)
        logger.warning(msg)
    return result


def validate_docker_compose(compose_content: str) -> Tuple[bool, str]:
    import re
    socket_mounts = re.findall(
        r"[-–]\s*[^\s:]*docker\.sock\s*:\s*\S+",
        compose_content)
    if socket_mounts:
        return False, f"found {len(socket_mounts)} docker.sock mount(s)"

    pipe_mounts = re.findall(
        r"[-–]\s*\\\\\.\\pipe\\docker_engine\S*\s*:\s*\S+",
        compose_content)
    if pipe_mounts:
        return False, f"found {len(pipe_mounts)} docker named pipe mount(s)"

    docker_host_refs = re.findall(
        r"DOCKER_HOST\s*[:=]\s*[\"']?(?:unix://|npipe://)[^\s\"']*(?:docker\.sock|docker_engine)",
        compose_content, re.IGNORECASE)
    if docker_host_refs:
        return False, f"found {len(docker_host_refs)} DOCKER_HOST socket reference(s)"

    return True, "clean"
