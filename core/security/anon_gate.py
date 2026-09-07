"""
Anonymisation kill-switch.

Refuses to let the agent start a scan unless:
  1. The process can reach the internet ONLY via the configured SOCKS5
     (Tor) proxy — direct connections must be blocked at the OS layer.
  2. The observed exit IP is different from REAL_WAN_IP (proves the
     chain of hops is up; if a VPN dropped and traffic fell back to
     your real interface, exit IP == real IP and we refuse to run).
  3. The exit is a Tor exit (check.torproject.org confirms).

Called from main.py before any tool is invoked.
"""
from __future__ import annotations

import logging
import os
import socket
from typing import Tuple

logger = logging.getLogger(__name__)


class AnonGateFailed(RuntimeError):
    """Raised when the anonymisation chain is not proven up."""


def _fetch_via_socks(url: str, timeout: float = 30.0) -> str:
    """Fetch a URL ONLY via the configured SOCKS5 proxy. If the proxy is
    down, this raises — never falls back to direct."""
    import httpx
    proxy = (os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
             or os.getenv("ALL_PROXY") or "").strip()
    if not proxy:
        raise AnonGateFailed(
            "no HTTPS_PROXY / HTTP_PROXY / ALL_PROXY set — the agent must "
            "be launched with SOCKS5 env vars pointing at the Tor container"
        )
    if not proxy.startswith("socks5"):
        raise AnonGateFailed(
            f"proxy scheme must be socks5/socks5h to prevent DNS leaks; got: {proxy!r}"
        )
    with httpx.Client(proxy=proxy, timeout=timeout) as c:
        r = c.get(url)
        r.raise_for_status()
        return r.text


def check_exit_ip() -> Tuple[str, bool]:
    """Return (exit_ip, is_tor_exit). Raises AnonGateFailed on any leak."""
    real = (os.getenv("REQUIRE_EXIT_IP_DIFFERS_FROM") or "").strip()
    if not real:
        raise AnonGateFailed(
            "REQUIRE_EXIT_IP_DIFFERS_FROM is not set — cannot verify the "
            "chain is up. Set it to your real WAN IP (curl ifconfig.me BEFORE "
            "starting the VPN chain) in .env."
        )

    exit_ip = _fetch_via_socks("https://api.ipify.org").strip()
    try:
        socket.inet_aton(exit_ip)
    except OSError:
        raise AnonGateFailed(f"ipify returned junk: {exit_ip!r}")

    if exit_ip == real:
        raise AnonGateFailed(
            f"exit IP ({exit_ip}) equals REAL_WAN_IP — the VPN/Tor chain "
            f"is DOWN or leaking. Refusing to start scan."
        )

    tor_page = _fetch_via_socks("https://check.torproject.org/")
    is_tor = "Congratulations" in tor_page or "using Tor" in tor_page.lower()
    if not is_tor:
        logger.warning(
            "[AnonGate] exit IP %s differs from real IP but is NOT a Tor "
            "exit — you are anonymised behind the VPNs only (2 hops). "
            "Continuing.", exit_ip,
        )
    else:
        logger.info("[AnonGate] chain verified: exit=%s (Tor)", exit_ip)

    return exit_ip, is_tor


def enforce_or_die() -> None:
    """Call at startup. Aborts the process if the chain is not up."""
    if os.getenv("ANON_GATE", "1").strip().lower() in ("0", "false", "no", "off"):
        logger.warning("[AnonGate] disabled via ANON_GATE=0 — traffic will "
                        "leave from your real IP")
        return
    try:
        exit_ip, is_tor = check_exit_ip()
    except Exception as e:
        logger.error("[AnonGate] STARTUP ABORTED — chain not verified: %s", e)
        raise SystemExit(2)
    print(f"[AnonGate] OK — exit IP: {exit_ip}  tor: {is_tor}")
