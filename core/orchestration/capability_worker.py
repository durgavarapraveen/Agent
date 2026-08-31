"""
Deterministic Capability Workers.
Executes capability-specific workflows using ToolAdapters and RetryPolicy.
No LLM calls occur in the execution loop.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from core.schemas import (
    CapabilityType, ToolResult, AgentResult, ToolExecutionStatus,
    RetryDecisionType, Finding, Evidence
)
from core.tool_adapter import ToolAdapter, ToolInvocation
from core.retry_policy import RetryPolicy
from core.exceptions import ToolValidationError

logger = logging.getLogger(__name__)


class CapabilityWorker:
    """Deterministic worker that executes capability workflows"""

    def __init__(self, agent_id: str, tool_registry: Any, shared_context: Any):
        self.agent_id = agent_id
        self.tools = tool_registry
        self.ctx = shared_context

    async def execute_capability(
        self,
        capability: CapabilityType,
        target: str,
        task_id: str,
        objective: str,
        params: Optional[Dict[str, Any]] = None
    ) -> AgentResult:
        """
        Execute deterministic workflow for the requested capability.
        Returns canonical AgentResult.
        """
        params = params or {}
        logger.info(f"CAPABILITY_SELECTED: capability={capability.value} target={target} agent_id={self.agent_id}")

        tool_results: List[ToolResult] = []
        findings: List[Finding] = []
        knowledge_ids: List[str] = []
        evidence_ids: List[str] = []

        # Determine tool sequence based on capability
        tool_chain = self._get_tool_chain_for_capability(capability)
        
        for tool_name in tool_chain:
            tool_res = await self._execute_tool_with_policy(
                tool_name=tool_name,
                capability=capability,
                target=target,
                task_id=task_id,
                params=params
            )
            tool_results.append(tool_res)

            # Ingest data and evidence into context if available
            if tool_res.data:
                self._record_extracted_data(tool_res.data, tool_name, target)

            # If tool succeeded or had partial success, we don't need to run fallbacks
            if tool_res.status in (ToolExecutionStatus.SUCCESS, ToolExecutionStatus.PARTIAL_SUCCESS, "success", "partial_success", "SUCCESS", "PARTIAL_SUCCESS"):
                break

        # Evaluate final status deterministically
        has_success = any(r.status in (ToolExecutionStatus.SUCCESS, "success", "SUCCESS") for r in tool_results)
        has_partial = any(r.status in (ToolExecutionStatus.PARTIAL_SUCCESS, "partial_success", "PARTIAL_SUCCESS") for r in tool_results)

        if has_success:
            agent_status = "completed"
        elif has_partial:
            agent_status = "partial"
        else:
            agent_status = "failed"

        # Merge extracted data
        aggregated_data: Dict[str, Any] = {}
        for r in tool_results:
            for k, v in r.data.items():
                if isinstance(v, list):
                    aggregated_data.setdefault(k, [])
                    for item in v:
                        if item not in aggregated_data[k]:
                            aggregated_data[k].append(item)
                elif isinstance(v, dict):
                    aggregated_data.setdefault(k, {}).update(v)
                else:
                    aggregated_data[k] = v

        return AgentResult(
            task_id=task_id,
            agent_id=self.agent_id,
            status=agent_status,
            observations=[{"tool": r.tool, "data": r.data, "warnings": r.warnings} for r in tool_results],
            knowledge_ids=knowledge_ids,
            evidence_ids=evidence_ids,
            findings=findings
        )

    def _get_tool_chain_for_capability(self, capability: CapabilityType, objective: str = "") -> List[str]:
        """Dynamically resolve prioritized list of tools for each capability via CapabilityResolver"""
        from core.capability_resolver import CapabilityResolver
        resolver = CapabilityResolver()
        resolved_profiles = resolver.resolve_tools(capability=capability.value, objective=objective)
        if resolved_profiles:
            return [p.name for p in resolved_profiles]
        return ["nmap"]

    async def _execute_tool_with_policy(
        self,
        tool_name: str,
        capability: CapabilityType,
        target: str,
        task_id: str,
        params: Dict[str, Any]
    ) -> ToolResult:
        """Execute a single tool with deterministic RetryPolicy and PartialResult handling"""
        from core.tool_knowledge_store import ToolKnowledgeStore
        store = ToolKnowledgeStore.get_instance()
        from urllib.parse import urlparse
        attempt = 1
        max_retries = 2
        current_tool = tool_name
        import time
        start_time = time.time()

        # Parse target URL to extract clean domain/IP (e.g. remove http://, fragments, query strings)
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            clean_target = parsed.hostname or parsed.netloc.split(":")[0]
        else:
            clean_target = target.split(":")[0].split("/")[0]

        while attempt <= max_retries:
            logger.info(f"TOOL_INVOCATION_REQUESTED: tool={current_tool} capability={capability.value} task_id={task_id}")

            try:
                # 1. Adapt invocation parameters deterministically (stack-aware)
                tool_params = dict(params)
                tool_params["target"] = clean_target
                inv = ToolInvocation(tool=current_tool, operation=capability.value, params=tool_params)
                
                # Fetch target profile if available for intelligent flag tuning
                target_profile = None
                if hasattr(self, "ctx") and self.ctx:
                    raw_prof = getattr(self.ctx, "target_profile", None) or (self.ctx.get("target_profile") if hasattr(self.ctx, "get") else None)
                    if raw_prof and not isinstance(raw_prof, dict):
                        target_profile = raw_prof
                    else:
                        from core.target_profiler import TargetProfiler
                        try:
                            target_profile = TargetProfiler.profile_target(target, self.ctx)
                        except Exception:
                            target_profile = None

                adapted = ToolAdapter.adapt(inv, profile=target_profile)

                # 2. Execute tool
                raw_res = await self.tools.execute(current_tool, adapted)
                
                # 3. Classify execution result and parse partial success
                tool_result = self._process_raw_tool_result(current_tool, capability.value, target, raw_res)

                # 4. Check status and log
                duration = round(time.time() - start_time, 2)
                logger.info(f"TOOL_EXECUTED: tool={current_tool} target={target} duration={duration}s")
                findings_count = len(tool_result.data.get("subdomains", [])) + len(tool_result.data.get("ports", [])) + len(tool_result.data.get("endpoints", []))
                store.record_execution(
                    tool_name=current_tool,
                    success=(tool_result.status in (ToolExecutionStatus.SUCCESS, ToolExecutionStatus.PARTIAL_SUCCESS)),
                    duration=duration,
                    findings_count=findings_count
                )

                if tool_result.status == ToolExecutionStatus.SUCCESS:
                    logger.info(f"TOOL_COMPLETED: tool={current_tool} task_id={task_id}")
                    return tool_result
                elif tool_result.status == ToolExecutionStatus.PARTIAL_SUCCESS:
                    logger.info(f"TOOL_PARTIAL_SUCCESS: tool={current_tool} task_id={task_id} warnings={tool_result.warnings}")
                    return tool_result

                # 5. Evaluate deterministic RetryPolicy on failure
                retry_dec = RetryPolicy.evaluate(current_tool, tool_result, attempt=attempt, max_retries=max_retries)
                if retry_dec.decision == RetryDecisionType.NO_RETRY:
                    return tool_result
                elif retry_dec.decision == RetryDecisionType.ALTERNATIVE_STRATEGY and retry_dec.alternative_tool:
                    current_tool = retry_dec.alternative_tool
                    attempt = 1
                    continue
                elif retry_dec.decision == RetryDecisionType.RETRY:
                    attempt += 1
                    continue

                return tool_result

            except ToolValidationError as tve:
                logger.error(f"TOOL_INVOCATION_REJECTED: tool={current_tool} reason='{tve}'")
                return ToolResult(
                    tool=current_tool,
                    capability=capability.value,
                    status=ToolExecutionStatus.FAILED,
                    stderr=str(tve),
                    warnings=[str(tve)]
                )
            except Exception as e:
                logger.error(f"TOOL_FAILED: tool={current_tool} exception={e}")
                return ToolResult(
                    tool=current_tool,
                    capability=capability.value,
                    status=ToolExecutionStatus.FAILED,
                    stderr=str(e),
                    warnings=[str(e)]
                )

        return ToolResult(
            tool=current_tool,
            capability=capability.value,
            status=ToolExecutionStatus.FAILED,
            stderr="Max retries reached without success"
        )

    def _process_raw_tool_result(
        self,
        tool_name: str,
        capability: str,
        target: str,
        raw_res: Dict[str, Any]
    ) -> ToolResult:
        """Process tool output into ToolResult, applying deduplication, significance filtering, token compression, and error translation."""
        from core.config import get_config
        from core.dedup_tracker import DeduplicationTracker
        from core.error_translator import ErrorTranslator
        from core.result_formatter import ToolResultFormatter
        from core.significance_filter import SignificanceFilter

        config = get_config()
        stdout = raw_res.get("output") or raw_res.get("stdout") or ""
        stderr = raw_res.get("stderr") or raw_res.get("error") or ""
        exit_code = raw_res.get("returncode", 0 if raw_res.get("success", False) else 1)
        raw_data = raw_res.get("data", {})

        from datetime import datetime
        duration_ms = int(raw_res.get("duration_ms", raw_res.get("duration", 0) * 1000 if isinstance(raw_res.get("duration"), (int, float)) else 0))
        stdout_lines = len(stdout.splitlines()) if stdout else 0
        stderr_lines = len(stderr.splitlines()) if stderr else 0
        iso_ts = datetime.now().isoformat()

        # Log 4 raw entries in exact required order before any parsing/filtering
        logger.info(f"TOOL_EXECUTED: tool={tool_name} capability={capability} target={target} timestamp={iso_ts}")
        logger.info(f"TOOL_RESULT_RAW: exit_code={exit_code} duration_ms={duration_ms} stdout_lines={stdout_lines} stderr_lines={stderr_lines}")
        logger.info(f"TOOL_OUTPUT_STDOUT:\n{stdout}")
        logger.info(f"TOOL_OUTPUT_STDERR:\n{stderr}")

        # Extract domain/entity data deterministically from stdout if not parsed yet
        extracted_data = dict(raw_data)
        extracted_data.update(self._extract_data_from_output(tool_name, capability, target, stdout))

        # Check for partial success: tool had non-zero exit code or stderr warning, BUT produced extracted data
        warnings = []
        if stderr:
            warnings.append(str(stderr)[:200])

        # Check status: exit code non-zero or empty data with stderr means failure
        has_error = (exit_code != 0) or (not raw_res.get("success", False))
        has_extracted = any(bool(v) for v in extracted_data.values() if isinstance(v, (list, dict, set)))

        if has_error and not has_extracted:
            status = ToolExecutionStatus.FAILED
            logger.warning(f"TOOL_FAILED: tool={tool_name} exit_code={exit_code} stderr='{stderr[:100]}'")
        elif has_error and has_extracted:
            status = ToolExecutionStatus.PARTIAL_SUCCESS
            logger.info(f"TOOL_PARTIAL_SUCCESS: tool={tool_name} exit_code={exit_code} extracted_data_found=True")
        elif has_extracted or raw_res.get("success", False):
            status = ToolExecutionStatus.SUCCESS
        else:
            status = ToolExecutionStatus.FAILED

        # Layer 1: Deduplication delta tracking
        delta_info = {}
        all_duplicate = False
        if config.dedup_enabled:
            dedup_tracker = DeduplicationTracker()
            for key, val in extracted_data.items():
                if isinstance(val, list) and val:
                    d_res = dedup_tracker.get_delta(tool_name, key, val, task_id=self.agent_id)
                    delta_info[key] = d_res
            all_duplicate = bool(delta_info) and all(d["new_count"] == 0 for d in delta_info.values())

        # Layer 2: Filter significance
        if config.significance_filter_enabled:
            filtered_data = SignificanceFilter.filter(tool_name, extracted_data)
        else:
            filtered_data = extracted_data

        # Token count calculation helper
        raw_payload = str(stdout) + str(extracted_data)
        orig_tokens = max(1, len(raw_payload) // 4)

        if status == ToolExecutionStatus.FAILED:
            if config.error_translation_enabled:
                error_report = ErrorTranslator.translate(tool_name, str(stderr) or str(stdout), exit_code, target)
                formatted_summary = error_report["formatted_report"]
                logger.info(f"TOOL_RESULT_TRANSLATED: tool={tool_name} category={error_report['category']}")
            else:
                formatted_summary = ToolResultFormatter.format_failure_result(tool_name, "Tool Error", str(stderr) or str(stdout))
            compressed_data = filtered_data
        elif config.dedup_enabled and all_duplicate:
            logger.info(f"TOOL_RESULT_DEDUPLICATED: tool={tool_name} status=SKIPPED_DUPLICATE")
            formatted_summary = ToolResultFormatter.format_duplicate_result(tool_name, self.agent_id)
            if status != ToolExecutionStatus.PARTIAL_SUCCESS:
                status = ToolExecutionStatus.SUCCESS
            compressed_data = filtered_data
        elif config.token_compression and (ToolResultFormatter.should_compress(tool_name, filtered_data) or orig_tokens > config.compression_threshold):
            compressed_data = ToolResultFormatter.compress_tool_data(tool_name, filtered_data)
            formatted_summary = ToolResultFormatter.format_success_result(tool_name, compressed_data)
            logger.info(f"TOOL_RESULT_COMPRESSED: tool={tool_name} size_reduction=85-95%")
        else:
            compressed_data = filtered_data
            formatted_summary = ToolResultFormatter.format_success_result(tool_name, filtered_data)

        # Compute compression metrics
        comp_payload = str(formatted_summary) + str(compressed_data)
        comp_tokens = max(1, len(comp_payload) // 4)
        pct_saved = max(0, round((1.0 - (comp_tokens / orig_tokens)) * 100))

        # Update logging
        logger.info(f"TOOL_EXECUTED: tool={tool_name}")
        raw_output_repr = f"exit_code={exit_code}, stdout={stdout[:500]!r}, stderr={stderr[:300]!r}, raw_data={extracted_data!r}"
        logger.info(f"TOOL_RESULT_RAW: tool={tool_name}, output={raw_output_repr}")
        logger.info(f"RESULT_COMPRESSION: {orig_tokens} tokens → {comp_tokens} tokens ({pct_saved}% saved)")
        sample_output = formatted_summary.splitlines()[0] if formatted_summary else ""
        logger.info(f"FORMATTED_OUTPUT: \"{sample_output}\"")

        # Layer 3: Send to shared context
        if self.ctx is not None:
            if hasattr(self.ctx, "append"):
                self.ctx.append(formatted_summary)
            elif hasattr(self.ctx, "add_tool_result"):
                self.ctx.add_tool_result(tool_name, formatted_summary)

        return ToolResult(
            tool=tool_name,
            capability=capability,
            status=status,
            stdout=formatted_summary,
            stderr=str(stderr),
            exit_code=exit_code,
            data=compressed_data,
            warnings=warnings,
            target=target
        )

    def _extract_data_from_output(
        self,
        tool_name: str,
        capability: str,
        target: str,
        output: str
    ) -> Dict[str, Any]:
        """Extract structured findings deterministically from text/JSON/XML output"""
        import json
        import xml.etree.ElementTree as ET

        data: Dict[str, Any] = {}
        if not output:
            return data

        # Clean target root
        root_domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip().lower()
        from core.subdomain_enum import extract_apex_domain
        apex_domain = extract_apex_domain(root_domain)

        # 1. Subfinder & Subdomain tools: parse JSON or line-by-line text
        if tool_name == "subfinder" or "dns" in capability or tool_name in ("amass", "dig"):
            subdomains = set()
            for line in output.splitlines():
                line_str = line.strip()
                if not line_str or line_str.startswith(("[", ";", "#", "Found", "Enumerating")):
                    continue
                if line_str.startswith("{") and line_str.endswith("}"):
                    try:
                        obj = json.loads(line_str)
                        host = obj.get("host") or obj.get("subdomain")
                        if host and isinstance(host, str) and (host.endswith(root_domain) or host.endswith(apex_domain) or "." in host):
                            subdomains.add(host.strip())
                    except Exception:
                        pass
                else:
                    parts = line_str.split()
                    for p in parts:
                        p_clean = p.strip().lower()
                        if (p_clean.endswith(root_domain) or p_clean.endswith(apex_domain)) and re.match(r'^[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}$', p_clean):
                            subdomains.add(p_clean)

            # Regex fallback
            domain_pattern = rf"\b([a-zA-Z0-9](?:[a-zA-Z0-9_\-]*[a-zA-Z0-9])?\.(?:[a-zA-Z0-9_\-]+\.)*{re.escape(apex_domain)})\b"
            for match in re.finditer(domain_pattern, output, re.IGNORECASE):
                subdomains.add(match.group(1).lower())

            valid_subdomains = [
                s for s in subdomains
                if s and "." in s and (s.endswith(root_domain) or s.endswith(apex_domain)) and not s.startswith("[") and not s.startswith("http")
            ]
            if valid_subdomains:
                data["subdomains"] = sorted(list(set(valid_subdomains)))

        # 2. Nmap & Port scanners: parse XML or text
        if tool_name in ("nmap", "masscan", "port_check") or "port" in capability:
            open_ports = []
            if "<nmaprun" in output or "<host" in output:
                try:
                    root = ET.fromstring(output)
                    for port_elem in root.findall(".//port"):
                        state_elem = port_elem.find("state")
                        if state_elem is not None and state_elem.get("state") == "open":
                            port_id = int(port_elem.get("portid", 0))
                            service_elem = port_elem.find("service")
                            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                            open_ports.append({"port": port_id, "service": service_name, "state": "open"})
                except Exception:
                    pass

            if not open_ports:
                port_pattern = r"(\d{1,5})/(?:tcp|udp)\s+open\s+([\w\-]+)?"
                for match in re.finditer(port_pattern, output, re.IGNORECASE):
                    port_num = int(match.group(1))
                    service = match.group(2) or "unknown"
                    open_ports.append({"port": port_num, "service": service, "state": "open"})

            if open_ports:
                data["ports"] = open_ports

        # 3. Dig / DNS records: parse text
        if tool_name == "dig":
            records = []
            for line in output.splitlines():
                if line.strip() and not line.startswith(";"):
                    parts = line.split()
                    if len(parts) >= 4:
                        records.append({"name": parts[0], "type": parts[3], "value": parts[-1]})
            if records:
                data["dns_records"] = records

        # 4. HTTPX / Web Crawling: parse JSON or text
        if tool_name in ("httpx", "katana", "gobuster", "feroxbuster", "paramspider") or "endpoint" in capability or "crawl" in capability:
            urls = set()
            headers_dict = {}
            for line in output.splitlines():
                line_str = line.strip()
                if line_str.startswith("{") and line_str.endswith("}"):
                    try:
                        obj = json.loads(line_str)
                        url_val = obj.get("url") or obj.get("input")
                        if url_val:
                            urls.add(url_val)
                        if "header" in obj or "headers" in obj:
                            headers_dict.update(obj.get("header") or obj.get("headers") or {})
                    except Exception:
                        pass
                elif line_str.startswith("http://") or line_str.startswith("https://") or line_str.startswith("/"):
                    urls.add(line_str.split()[0])

            url_pattern = r"(https?://[^\s\"\'<>]+|/[a-zA-Z0-9_\-\.\?&=/%]+)"
            urls.update(re.findall(url_pattern, output))
            if urls:
                data["endpoints"] = sorted(list(urls))[:100]
            if headers_dict:
                data["headers"] = headers_dict

        # 5. Technology Fingerprinting (WhatWeb / HTTPX)
        if "tech" in capability or tool_name in ("whatweb", "httpx"):
            tech_lines = [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("[")]
            if tech_lines:
                data["technologies"] = tech_lines

        # 6. Security Headers Analysis (HTTP Analysis / HTTPX / Curl)
        if "http" in capability or "header" in capability or tool_name in ("httpx", "curl", "python"):
            sec_headers = {}
            raw_headers_lower = output.lower()
            critical_headers = {
                "x-frame-options": "X-Frame-Options",
                "content-security-policy": "Content-Security-Policy",
                "strict-transport-security": "Strict-Transport-Security",
                "x-content-type-options": "X-Content-Type-Options",
                "x-xss-protection": "X-XSS-Protection",
                "referrer-policy": "Referrer-Policy"
            }

            for h_key, h_name in critical_headers.items():
                if h_key in raw_headers_lower:
                    sec_headers[h_name] = "found"
                else:
                    sec_headers[h_name] = "missing"

            data["security_headers"] = sec_headers
            csp_status = sec_headers.get("Content-Security-Policy", "missing")
            hsts_status = sec_headers.get("Strict-Transport-Security", "missing")
            xframe_status = sec_headers.get("X-Frame-Options", "missing")
            logger.info(f"SECURITY_HEADERS_ANALYZED: csp={csp_status}, hsts={hsts_status}, x_frame_options={xframe_status}")

        # 7. Extract database error signatures from HTTP error responses (BUG-009 fix)
        db_patterns = {
            "sqlite": [r"sqlite3", r"sqlite_error", r"sqlite exception", r"unrecognized token"],
            "mysql": [r"mysql_fetch", r"you have an error in your sql syntax", r"check the manual that corresponds to your mysql"],
            "postgresql": [r"pg_query", r"psycopg2", r"postgresql", r"syntax error at or near"],
            "oracle": [r"ora-\d{5}", r"oracle error"]
        }
        output_lower = output.lower()
        for db_type, patterns in db_patterns.items():
            if any(re.search(pat, output_lower) for pat in patterns):
                data["detected_database"] = db_type
                logger.info(f"DATABASE_FINGERPRINTED_FROM_ERROR: db_type={db_type} tool={tool_name}")
                break

        # Log extraction details
        extracted_summary = f"domains={len(data.get('subdomains', []))} ports={len(data.get('ports', []))} endpoints={len(data.get('endpoints', []))}"
        logger.info(f"TOOL_RESULT_EXTRACTED: tool={tool_name} {extracted_summary}")

        return data

    def _record_extracted_data(self, data: Dict[str, Any], tool_name: str, target: str) -> None:
        """Store extracted findings in SharedContext and per-tool dict"""
        if not self.ctx:
            return

        clean_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        # Store in shared_context[tool_name] dictionary if indexing supported
        try:
            if hasattr(self.ctx, "__setitem__"):
                self.ctx[tool_name] = data
                if "security_headers" in data:
                    self.ctx["security_headers"] = data["security_headers"]
            elif hasattr(self.ctx, "tool_results") and isinstance(self.ctx.tool_results, dict):
                self.ctx.tool_results[tool_name] = data
        except Exception:
            pass

        if "subdomains" in data and hasattr(self.ctx, "add_subdomains"):
            self.ctx.add_subdomains(data["subdomains"])
        if "ports" in data and hasattr(self.ctx, "add_ports"):
            self.ctx.add_ports(clean_host, data["ports"], source=tool_name)
        if "endpoints" in data and hasattr(self.ctx, "add_endpoints"):
            dict_eps = [{"url": ep if isinstance(ep, str) else ep.get("url", "")} for ep in data["endpoints"]]
            self.ctx.add_endpoints(dict_eps, source=tool_name)
        if "technologies" in data and hasattr(self.ctx, "add_technologies"):
            self.ctx.add_technologies(clean_host, data["technologies"])

        # Record missing critical security headers as low/medium vulnerabilities
        if "security_headers" in data and hasattr(self.ctx, "add_vulnerability"):
            for h_name, status in data["security_headers"].items():
                if status == "missing":
                    self.ctx.add_vulnerability({
                        "type": "missing_security_header",
                        "title": f"Missing Security Header: {h_name}",
                        "severity": "LOW" if h_name in ("Referrer-Policy", "X-XSS-Protection") else "MEDIUM",
                        "proof": f"Header '{h_name}' is missing in HTTP response for {target}",
                        "details": f"Missing security header '{h_name}' on {target}"
                    })
