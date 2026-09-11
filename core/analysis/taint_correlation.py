"""Phase 12.2 — Runtime data-flow/taint correlation.

Traces input-to-sink relationships across application layers. Correlates
runtime evidence with source paths and externally observable experiments.
Instrumentation can be disabled without destabilizing the target.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TaintType(str, Enum):
    USER_INPUT = "user_input"
    COOKIE = "cookie"
    HEADER = "header"
    URL_PARAM = "url_param"
    BODY_PARAM = "body_param"
    DATABASE = "database"
    FILE = "file"
    ENVIRONMENT = "environment"


class SinkType(str, Enum):
    SQL_QUERY = "sql_query"
    COMMAND_EXEC = "command_exec"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    HTTP_RESPONSE = "http_response"
    REDIRECT = "redirect"
    TEMPLATE_RENDER = "template_render"
    EVAL = "eval"
    LDAP_QUERY = "ldap_query"
    XML_PARSE = "xml_parse"
    DESERIALIZATION = "deserialization"


class ReachabilityLevel(str, Enum):
    STATIC = "static"
    DYNAMIC_CONFIRMED = "dynamic_confirmed"
    INFERRED = "inferred"


@dataclass
class TaintFlow:
    flow_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    source_type: TaintType = TaintType.USER_INPUT
    source_param: str = ""
    source_endpoint: str = ""
    sink_type: SinkType = SinkType.SQL_QUERY
    sink_location: str = ""
    source_file: str = ""
    source_line: int = 0
    sink_file: str = ""
    sink_line: int = 0
    intermediate_transforms: List[str] = field(default_factory=list)
    reachability: ReachabilityLevel = ReachabilityLevel.STATIC
    experiment_evidence: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source": f"{self.source_type.value}:{self.source_param}@{self.source_endpoint}",
            "sink": f"{self.sink_type.value}@{self.sink_location}",
            "reachability": self.reachability.value,
            "transforms": self.intermediate_transforms,
            "evidence_count": len(self.experiment_evidence),
        }


@dataclass
class InstrumentationConfig:
    enabled: bool = False
    trace_sql: bool = True
    trace_commands: bool = True
    trace_file_ops: bool = True
    trace_http_responses: bool = True
    trace_templates: bool = True
    max_flows_per_endpoint: int = 1000
    sampling_rate: float = 1.0


class TaintCorrelationEngine:
    """Correlate static taint analysis with runtime observations."""

    def __init__(self, config: Optional[InstrumentationConfig] = None):
        self._config = config or InstrumentationConfig()
        self._lock = threading.RLock()
        self._flows: Dict[str, TaintFlow] = {}
        self._endpoint_counts: Dict[str, int] = {}
        self._source_links: Dict[str, List[str]] = {}

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def enable(self) -> None:
        self._config.enabled = True

    def disable(self) -> None:
        self._config.enabled = False

    def record_static_flow(self, flow: TaintFlow) -> bool:
        with self._lock:
            count = self._endpoint_counts.get(flow.source_endpoint, 0)
            if count >= self._config.max_flows_per_endpoint:
                return False
            self._flows[flow.flow_id] = flow
            self._endpoint_counts[flow.source_endpoint] = count + 1
            if flow.source_file:
                self._source_links.setdefault(flow.source_file, []).append(flow.flow_id)
        return True

    def confirm_flow_runtime(self, flow_id: str, experiment_id: str) -> bool:
        with self._lock:
            flow = self._flows.get(flow_id)
            if not flow:
                return False
            flow.reachability = ReachabilityLevel.DYNAMIC_CONFIRMED
            flow.experiment_evidence.append(experiment_id)
        return True

    def query_flows(self, endpoint: str = "", sink_type: Optional[SinkType] = None,
                    reachability: Optional[ReachabilityLevel] = None) -> List[TaintFlow]:
        with self._lock:
            flows = list(self._flows.values())
        if endpoint:
            flows = [f for f in flows if f.source_endpoint == endpoint]
        if sink_type:
            flows = [f for f in flows if f.sink_type == sink_type]
        if reachability:
            flows = [f for f in flows if f.reachability == reachability]
        return flows

    def get_flows_for_source(self, source_file: str) -> List[TaintFlow]:
        with self._lock:
            flow_ids = self._source_links.get(source_file, [])
            return [self._flows[fid] for fid in flow_ids if fid in self._flows]

    def get_confirmed_flows(self) -> List[TaintFlow]:
        return self.query_flows(reachability=ReachabilityLevel.DYNAMIC_CONFIRMED)

    def export(self) -> Dict[str, Any]:
        with self._lock:
            flows = list(self._flows.values())
        return {
            "total_flows": len(flows),
            "static_only": sum(1 for f in flows if f.reachability == ReachabilityLevel.STATIC),
            "confirmed": sum(1 for f in flows if f.reachability == ReachabilityLevel.DYNAMIC_CONFIRMED),
            "inferred": sum(1 for f in flows if f.reachability == ReachabilityLevel.INFERRED),
            "enabled": self._config.enabled,
        }
