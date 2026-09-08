"""
Tool Intelligence Model & Target Context.
Defines dynamic metadata profiles for tools and normalized target contexts.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from urllib.parse import urlparse
import re
import logging

logger = logging.getLogger(__name__)


class TargetContext(BaseModel):
    """Normalized target context used across tool invocations and intelligence modules"""
    raw: str
    url: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    scheme: Optional[str] = None

    @classmethod
    def from_target(cls, target: str) -> "TargetContext":
        """Parse raw target string into normalized context"""
        if not target:
            return cls(raw="")
        
        target = target.strip()
        scheme = "https"
        url = target
        port = None
        
        if "://" in target:
            parsed = urlparse(target)
            scheme = parsed.scheme or "https"
            netloc = parsed.netloc
            url = target
        else:
            netloc = target.split("/")[0]
            url = f"https://{target}"

        # IPv6-safe host+port split. `[::1]:8080` → host `::1`, port 8080.
        # The previous naive `netloc.split(":", 1)` mangled every IPv6 target
        # into `""` + garbage.
        port = None
        if netloc.startswith("[") and "]" in netloc:
            close = netloc.index("]")
            host_part = netloc[1:close]
            rest = netloc[close + 1:]
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except ValueError:
                    port = None
        elif netloc.count(":") == 1:
            host_part, port_str = netloc.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = None
        else:
            # Bare IPv6 without brackets — no port.
            host_part = netloc

        hostname = host_part
        # IP classification via stdlib — handles both v4 and v6.
        import ipaddress as _ipaddr
        ip = None
        try:
            _ip_obj = _ipaddr.ip_address(hostname)
            ip = str(_ip_obj)
        except ValueError:
            pass

        # Base domain only makes sense for DNS hostnames.
        if ip is None:
            parts = hostname.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        else:
            domain = hostname

        return cls(
            raw=target,
            url=url,
            hostname=hostname,
            domain=domain,
            ip=ip,
            port=port or (443 if scheme == "https" else 80),
            scheme=scheme
        )


class ToolProfile(BaseModel):
    """Dynamic metadata profile for any tool in the intelligence platform"""
    id: str = Field(default_factory=lambda: "")
    name: str
    description: str = ""
    source: str = "local"  # local, github, mcp, plugin, custom
    version: Optional[str] = "1.0.0"
    capabilities: List[str] = Field(default_factory=list)
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Dict[str, Any] = Field(default_factory=dict)
    adapter: Optional[str] = None
    risk_level: str = "low"  # low, medium, high, critical
    trust_score: float = 0.90  # 0.0 to 1.0
    performance_score: float = 0.85  # 0.0 to 1.0
    success_rate: float = 0.90  # 0.0 to 1.0
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    average_duration_seconds: float = 0.0
    last_tested: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data):
        super().__init__(**data)
        if not self.id:
            self.id = f"tool_{self.name.lower().strip()}"

    def update_performance(self, success: bool, duration: float, findings_count: int = 0) -> None:
        """Update metrics after tool execution"""
        self.total_executions += 1
        if success:
            self.successful_executions += 1
        else:
            self.failed_executions += 1

        self.success_rate = round(self.successful_executions / max(1, self.total_executions), 3)

        # Update average duration
        if self.average_duration_seconds == 0:
            self.average_duration_seconds = duration
        else:
            self.average_duration_seconds = round((self.average_duration_seconds * 0.7) + (duration * 0.3), 2)

        # Performance score adjusts with speed & findings
        if success:
            bonus = min(0.05, findings_count * 0.01)
            self.performance_score = min(1.0, round(self.performance_score + 0.02 + bonus, 3))
            self.trust_score = min(1.0, round(self.trust_score + 0.01, 3))
        else:
            self.performance_score = max(0.1, round(self.performance_score - 0.05, 3))
            self.trust_score = max(0.1, round(self.trust_score - 0.05, 3))

        self.last_tested = datetime.now()
        logger.info(
            f"TOOL_PERFORMANCE_UPDATED: tool={self.name} success_rate={self.success_rate} "
            f"trust_score={self.trust_score} perf_score={self.performance_score}"
        )
