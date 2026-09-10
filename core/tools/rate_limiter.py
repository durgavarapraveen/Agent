
import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TargetState:
    requests_sent: int = 0
    blocks_detected: int = 0
    last_block_time: float = 0.0
    current_delay: float = 1.0  # seconds between requests
    min_delay: float = 0.5
    max_delay: float = 30.0
    consecutive_successes: int = 0
    consecutive_blocks: int = 0
    waf_detected: bool = False
    waf_type: str = ""
    is_rate_limited: bool = False


# HTTP status codes that indicate rate limiting or blocking
BLOCK_STATUS_CODES = {429, 503, 403, 406, 418}

# Response body patterns indicating WAF/rate limit
WAF_SIGNATURES = [
    ("cloudflare", "Cloudflare"),
    ("cf-ray", "Cloudflare"),
    ("attention required", "Cloudflare"),
    ("akamai", "Akamai"),
    ("access denied", "WAF"),
    ("request rate too large", "Rate Limit"),
    ("rate limit exceeded", "Rate Limit"),
    ("too many requests", "Rate Limit"),
    ("blocked", "WAF"),
    ("forbidden", "WAF"),
    ("security", "WAF"),
    ("captcha", "CAPTCHA"),
    ("challenge", "WAF Challenge"),
    ("ddos", "DDoS Protection"),
    ("incapsula", "Imperva/Incapsula"),
    ("sucuri", "Sucuri"),
    ("wordfence", "Wordfence"),
    ("modsecurity", "ModSecurity"),
    ("f5 big-ip", "F5 BIG-IP"),
    ("barracuda", "Barracuda"),
    ("fortiweb", "FortiWeb"),
    ("aws waf", "AWS WAF"),
    ("shield", "AWS Shield"),
]

# stderr patterns from tools indicating blocks
TOOL_BLOCK_PATTERNS = [
    "connection refused",
    "connection reset",
    "connection timed out",
    "too many open files",
    "no route to host",
    "network unreachable",
    "403 forbidden",
    "429 too many",
    "rate limit",
    "waf block",
    "access denied",
]


class AdaptiveRateLimiter:

    def __init__(self, default_delay: float = 1.0):
        self._targets: Dict[str, TargetState] = defaultdict(
            lambda: TargetState(current_delay=default_delay)
        )
        self._default_delay = default_delay
        self._global_block_count = 0
        self._lock = asyncio.Lock()

    def _normalize_target(self, target: str) -> str:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target if "://" in target else f"https://{target}")
            return parsed.hostname or target
        except Exception:
            return target

    def get_state(self, target: str) -> TargetState:
        host = self._normalize_target(target)
        return self._targets[host]

    def detect_block(self, target: str, status_code: int = 0,
                     stdout: str = "", stderr: str = "") -> Tuple[bool, str]:
        reasons = []

        if status_code in BLOCK_STATUS_CODES:
            if status_code == 429:
                reasons.append(f"HTTP 429 Too Many Requests")
            elif status_code == 403:
                reasons.append(f"HTTP 403 Forbidden (possible WAF)")
            elif status_code == 503:
                reasons.append(f"HTTP 503 Service Unavailable (possible rate limit)")
            else:
                reasons.append(f"HTTP {status_code} (suspicious)")

        combined = (stdout + " " + stderr).lower()

        for pattern, waf_name in WAF_SIGNATURES:
            if pattern in combined:
                reasons.append(f"{waf_name} detected")
                break

        stderr_lower = stderr.lower()
        for pattern in TOOL_BLOCK_PATTERNS:
            if pattern in stderr_lower:
                reasons.append(f"Tool error: {pattern}")
                break

        is_blocked = bool(reasons)
        reason = "; ".join(reasons) if reasons else ""
        return is_blocked, reason

    async def record_result(self, target: str, success: bool,
                            status_code: int = 0,
                            stdout: str = "", stderr: str = ""):
        host = self._normalize_target(target)
        async with self._lock:
            state = self._targets[host]
            state.requests_sent += 1

            is_blocked, reason = self.detect_block(target, status_code, stdout, stderr)

            if is_blocked:
                state.blocks_detected += 1
                state.consecutive_blocks += 1
                state.consecutive_successes = 0
                state.last_block_time = time.time()
                state.is_rate_limited = True
                self._global_block_count += 1

                # Identify WAF type
                for pattern, waf_name in WAF_SIGNATURES:
                    if pattern in (stdout + stderr).lower():
                        state.waf_detected = True
                        state.waf_type = waf_name
                        break

                # Back off: double delay (capped at max)
                old_delay = state.current_delay
                state.current_delay = min(state.current_delay * 2, state.max_delay)

                logger.warning(
                    f"[RateLimiter] Block detected on {host}: {reason} "
                    f"(delay {old_delay:.1f}s → {state.current_delay:.1f}s, "
                    f"blocks={state.blocks_detected}/{state.requests_sent})"
                )

            elif success:
                state.consecutive_successes += 1
                state.consecutive_blocks = 0

                # Slowly decrease delay after sustained success
                if state.consecutive_successes >= 5 and state.current_delay > state.min_delay:
                    old_delay = state.current_delay
                    state.current_delay = max(state.current_delay * 0.8, state.min_delay)
                    if old_delay != state.current_delay:
                        logger.info(
                            f"[RateLimiter] Easing throttle on {host}: "
                            f"{old_delay:.1f}s → {state.current_delay:.1f}s "
                            f"(after {state.consecutive_successes} successes)"
                        )
                    state.consecutive_successes = 0

    async def wait_if_needed(self, target: str):
        host = self._normalize_target(target)
        state = self._targets[host]

        if state.current_delay > 0:
            # Add jitter (10-30% random variation)
            import random
            jitter = state.current_delay * random.uniform(0.1, 0.3)
            delay = state.current_delay + jitter
            await asyncio.sleep(delay)

    def get_delay(self, target: str) -> float:
        host = self._normalize_target(target)
        return self._targets[host].current_delay

    def get_tool_flags(self, target: str, tool_name: str) -> Dict[str, str]:
        host = self._normalize_target(target)
        state = self._targets[host]
        flags = {}

        if not state.is_rate_limited and state.blocks_detected == 0:
            return flags

        delay_ms = int(state.current_delay * 1000)

        tool_lower = tool_name.lower()

        if tool_lower in ("nmap", "masscan"):
            if state.current_delay >= 5:
                flags["timing"] = "-T1"
            elif state.current_delay >= 2:
                flags["timing"] = "-T2"
            else:
                flags["timing"] = "-T3"
            flags["scan_delay"] = f"--scan-delay {delay_ms}ms"

        elif tool_lower in ("ffuf", "gobuster", "feroxbuster", "dirsearch"):
            rate = max(1, int(1000 / max(delay_ms, 100)))
            flags["rate"] = f"-rate {rate}" if tool_lower == "ffuf" else f"-t {min(rate, 5)}"
            if tool_lower == "ffuf":
                flags["delay"] = f"-p {state.current_delay:.1f}"

        elif tool_lower in ("nuclei",):
            rate = max(1, int(1000 / max(delay_ms, 200)))
            flags["rate_limit"] = f"-rl {rate}"
            flags["bulk_size"] = "-bs 1"

        elif tool_lower in ("nikto",):
            if state.current_delay >= 5:
                flags["pause"] = f"-Pause {int(state.current_delay)}"

        elif tool_lower in ("sqlmap",):
            flags["delay"] = f"--delay={state.current_delay:.1f}"
            if state.waf_detected:
                flags["tamper"] = "--tamper=between,randomcase,space2comment"
                flags["random_agent"] = "--random-agent"

        elif tool_lower in ("katana", "httpx"):
            rate = max(1, int(1000 / max(delay_ms, 200)))
            flags["rate_limit"] = f"-rl {rate}"

        if state.waf_detected:
            flags["user_agent"] = "--random-agent" if tool_lower in ("sqlmap", "nikto") else ""

        return {k: v for k, v in flags.items() if v}

    def get_summary(self) -> Dict:
        targets = {}
        for host, state in self._targets.items():
            if state.requests_sent == 0:
                continue
            targets[host] = {
                "requests": state.requests_sent,
                "blocks": state.blocks_detected,
                "block_rate": round(state.blocks_detected / max(state.requests_sent, 1), 2),
                "current_delay_sec": round(state.current_delay, 1),
                "waf_detected": state.waf_detected,
                "waf_type": state.waf_type,
                "is_rate_limited": state.is_rate_limited,
            }
        return {
            "total_blocks": self._global_block_count,
            "targets_monitored": len(targets),
            "targets": targets,
        }


# Singleton for global access
_instance: Optional[AdaptiveRateLimiter] = None


def get_rate_limiter() -> AdaptiveRateLimiter:
    global _instance
    if _instance is None:
        _instance = AdaptiveRateLimiter()
    return _instance
