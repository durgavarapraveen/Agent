import subprocess
import shutil
import json
import re
import uuid
import logging
from typing import Dict, Any, List
import time

from core.domain.endpoint import Endpoint
from core.domain.finding import SecurityFinding, FindingState
from core.fuzzing.models import ToolResult, ToolStatus

# Endpoints reach probes in many shapes; a tool binary needs a clean absolute URL.
# Strip a "METHOD:" prefix and "get://"-style artifacts, drop the SPA fragment,
# and reject un-rendered JS template literals (e.g. "https://${this.hostServer}/…"
# extracted from a bundle). Returns "" when the input isn't a usable http(s) URL.
_METHOD_PREFIX = re.compile(r'^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*:(?!//)', re.I)
_METHOD_SCHEME = re.compile(r'^(?:get|post|put|patch|delete|head|options)://', re.I)


def _clean_target_url(raw: str) -> str:
    if not raw:
        return ""
    u = raw.strip().split("#", 1)[0].strip()
    prev = None
    while prev != u:
        prev = u
        u = _METHOD_PREFIX.sub("", u).strip()
        u = _METHOD_SCHEME.sub("", u).strip()
    if "${" in u or "{{" in u or "`" in u:   # un-rendered JS template — not a real URL
        return ""
    return u if u.startswith(("http://", "https://")) else ""

logger = logging.getLogger(__name__)


def _kali_available() -> bool:
    """True if the Kali tool container is (or can be) up — binaries live there,
    not on the host PATH (critical on Windows where nuclei/sqlmap/dalfox aren't
    local).

    P0-D1: auto_create=True. With auto_create=False, a container that simply
    wasn't running yet made this return False, so the probe short-circuited to
    `binary_not_found` and NEVER built/ran the command (dalfox never dispatched,
    sqlmap reported exit_code=-1). `_run_cmd` already dispatches via
    KaliDockerExecutor.run (which auto-creates), so gating on a *running*
    container here was the self-inflicted failure. Creating it on demand makes
    availability consistent with actual dispatch."""
    try:
        from agents.kali_executor import KaliDockerExecutor
        return bool(KaliDockerExecutor.get_container(auto_create=True))
    except Exception:
        return False


def _tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None or _kali_available()


class _Completed:
    """subprocess.CompletedProcess-shaped result for the Kali-docker path."""
    def __init__(self, returncode: int, stdout: str, stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _run_cmd(cmd: List[str], timeout: float):
    """Run a tool command locally if the binary (cmd[0]) is on PATH, otherwise
    via the Kali docker container (which also applies target-scope validation)."""
    binary = cmd[0] if cmd else ""
    if shutil.which(binary):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    import shlex
    from agents.kali_executor import KaliDockerExecutor
    cmd_str = " ".join(shlex.quote(c) for c in cmd)
    r = KaliDockerExecutor.run(cmd_str, timeout=int(timeout), auto_install=True)
    rc = r.get("returncode")
    return _Completed(rc if rc is not None else 1,
                      r.get("stdout", "") or "", r.get("stderr", "") or "")


def _missing_binary_result(tool: str, binary: str, start: float) -> ToolResult:
    duration = (time.time() - start) * 1000
    logger.warning("Tool binary not found: %s (%s)", tool, binary)
    return ToolResult(
        tool_name=tool,
        status=ToolStatus.ERROR,
        findings=[],
        evidence=f"binary_not_found:{binary}",
        execution_time_ms=duration,
    )


def _dalfox_query_params(endpoint: Endpoint, cap: int = 6) -> List[str]:
    """F-X3: query-param names to give dalfox a reflected-XSS surface. Prefer the
    endpoint's OWN declared query parameters; fall back to a generic, app-agnostic
    reflected-param vocab (search/redirect/file names) — never target-specific."""
    names: List[str] = []
    for p in (getattr(endpoint, "parameters", None) or []):
        try:
            if str(getattr(p, "parameter_type", "")).lower().endswith("query") and p.name:
                names.append(p.name)
        except Exception:
            continue
    if not names:
        try:
            from core.common import target_shape as ts
            names = ["q", "id"] + sorted(ts._SEARCH_NAMES)[:2] + sorted(ts._REDIRECT_NAMES)[:1]
        except Exception:
            names = ["q", "id", "search", "redirect"]
    seen: List[str] = []
    for n in names:
        if n and n not in seen:
            seen.append(n)
    return seen[:cap]


class BaseAdapter:
    def __init__(self, endpoint: Endpoint, target: str):
        self.endpoint = endpoint
        self.target = target
        self.tool_name = "base"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        raise NotImplementedError()

class SQLMapAdapter(BaseAdapter):
    def __init__(self, endpoint: Endpoint, target: str):
        super().__init__(endpoint, target)
        self.tool_name = "sqlmap"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        start = time.time()
        if not _tool_available("sqlmap"):
            return _missing_binary_result(self.tool_name, "sqlmap", start)

        from core.domain.parameter import ParameterType

        # Clean the target: drop the SPA fragment (everything after '#' is client-
        # side → no server param to test, root cause of prior no_result), plus any
        # METHOD:/get:// prefix and un-rendered ${...} template URLs.
        url = _clean_target_url(self.endpoint.url)
        if not url:
            return ToolResult(tool_name=self.tool_name, status=ToolStatus.ERROR,
                              evidence="skipped: invalid/template URL",
                              execution_time_ms=(time.time() - start) * 1000)
        # An Angular/SPA catch-all route returns index.html for any path — sqlmap
        # against it only wastes the budget. Skip it explicitly.
        if getattr(self.endpoint, "is_spa_catch_all", False):
            return ToolResult(tool_name=self.tool_name, status=ToolStatus.ERROR,
                              evidence="skipped: SPA catch-all route (no server-side params)",
                              execution_time_ms=(time.time() - start) * 1000)

        plist = getattr(self.endpoint, "parameters", []) or []
        methods = [m.upper() for m in (getattr(self.endpoint, "method_set", ["GET"]) or ["GET"])]
        query_params = [p.name for p in plist
                        if getattr(p, "name", None) and getattr(p, "parameter_type", None)
                        in (ParameterType.QUERY, ParameterType.PATH,
                            ParameterType.INFERRED, ParameterType.UNKNOWN)]
        body_params = [p.name for p in plist
                       if getattr(p, "name", None) and getattr(p, "parameter_type", None)
                       in (ParameterType.BODY, ParameterType.JSON, ParameterType.FORM)]

        # Point sqlmap at an actually-injectable surface instead of a bare URL.
        data_arg = None
        if "?" in url:
            target_url = url                                   # already parameterized
        elif query_params:
            target_url = url + "?" + "&".join(f"{n}=1" for n in query_params[:6])
        elif body_params and ({"POST", "PUT", "PATCH"} & set(methods)):
            target_url = url
            ct = (getattr(self.endpoint, "content_type", "") or "").lower()
            if "json" in ct:
                data_arg = "{" + ",".join(f'"{n}":"1"' for n in body_params[:6]) + "}"
            else:
                data_arg = "&".join(f"{n}=1" for n in body_params[:6])
        else:
            target_url = url                                   # no known params → crawl/forms below

        # -o turns on all safe optimization switches (keep-alive, null-connection,
        # output prediction, threads) so blind-injection confirmation fits inside
        # the per-tool timeout ceiling (600s) instead of being killed with no
        # result. Optimization only — it does not drop techniques/level/risk.
        cmd = ["sqlmap", "-u", target_url, "--batch", "-o",
               "--level=2", "--risk=2", "--random-agent"]
        if data_arg:
            cmd += ["--data", data_arg]
        elif "?" not in target_url:
            cmd += ["--forms", "--crawl=2"]

        # Additional params from config
        if params.get("tamper"):
            cmd.extend(["--tamper", params["tamper"]])
        if params.get("threads"):
            cmd.extend(["--threads", str(params["threads"])])

        # sqlmap with --level/--risk (+ --forms/--crawl for param-less URLs) needs
        # minutes to confirm boolean/time-based blind injection. A 30s cap killed it
        # before confirmation → reason=no_result. Give it a real budget.
        _SQLMAP_TIMEOUT = 900.0
        try:
            result = _run_cmd(cmd, _SQLMAP_TIMEOUT)
            duration = (time.time() - start) * 1000

            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.ERROR
            findings = self._parse_output(result.stdout)

            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                findings=findings,
                evidence=result.stdout,
                execution_time_ms=duration
            )

        except subprocess.TimeoutExpired as e:
            logger.warning(f"SQLMap timed out on {self.endpoint.url}")
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.TIMEOUT,
                evidence=e.stdout.decode() if e.stdout else "",
                execution_time_ms=_SQLMAP_TIMEOUT * 1000
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                evidence=str(e),
                execution_time_ms=(time.time() - start) * 1000
            )

    # sqlmap prints per-parameter blocks like:
    #       Type: boolean-based blind
    #       Title: AND boolean-based blind - WHERE or HAVING clause
    #       Payload: id=1 AND 1=1
    # A block is only a real finding if it contains BOTH `Parameter:` and
    # at least one of the confirmation markers. The previous substring
    # check accepted any stdout that happened to include those keywords
    # anywhere, including sqlmap's own banner text.
    _SQLMAP_CONFIRMATION_MARKERS = (
        "the following injection point",
        "sqlmap identified the following injection point",
        "type:",
        "payload:",
        "target url appears to be UNION injectable",
    )

    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        import re as _re_sql
        # Find each `Parameter: <name> (<method>)` block and verify at least
        # one confirmation marker appears within its slice.
        param_iter = list(_re_sql.finditer(
            r"Parameter:\s+([\w\[\]#-]+)\s+\((GET|POST|COOKIE|HEADER|URI)\)",
            stdout,
        ))
        for i, m in enumerate(param_iter):
            start = m.end()
            end = param_iter[i + 1].start() if i + 1 < len(param_iter) else len(stdout)
            block = stdout[start:end]
            low_block = block.lower()
            if not any(marker in low_block for marker in self._SQLMAP_CONFIRMATION_MARKERS):
                continue
            param_name = m.group(1)
            method = m.group(2)
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title=f"SQL Injection in {method} parameter '{param_name}'",
                description=("SQLMap detected an injectable parameter with at least "
                              "one confirmation marker in its output block."),
                severity="CRITICAL",
                endpoint_id=self.endpoint.endpoint_id,
                state=FindingState.CANDIDATE,
                evidence={"parameter": param_name, "method": method, "output": block[:2000]},
            ))
        return findings


class NucleiAdapter(BaseAdapter):
    def __init__(self, endpoint: Endpoint, target: str):
        super().__init__(endpoint, target)
        self.tool_name = "nuclei"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        start = time.time()
        if not _tool_available("nuclei"):
            return _missing_binary_result(self.tool_name, "nuclei", start)

        cmd = [
            "nuclei",
            "-u", self.endpoint.url,
            "-json-export", "-" # output json to stdout
        ]

        if params.get("template"):
            cmd.extend(["-t", params["template"]])
        else:
            # Fall back to the PATT-synced templates dir when present so nuclei
            # never FTLs with "no templates provided for scan".
            try:
                from core.payloads.updater import nuclei_templates_dir
                _tdir = nuclei_templates_dir()
                if _tdir:
                    cmd.extend(["-t", _tdir])
            except Exception:
                pass
        if params.get("rate_limit"):
            cmd.extend(["-rl", str(params["rate_limit"])])

        try:
            result = _run_cmd(cmd, 30.0)
            duration = (time.time() - start) * 1000
            
            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.ERROR
            findings = self._parse_output(result.stdout)
            
            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                findings=findings,
                evidence=result.stdout,
                execution_time_ms=duration
            )
        except subprocess.TimeoutExpired as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.TIMEOUT,
                evidence=e.stdout.decode() if e.stdout else "",
                execution_time_ms=30000.0
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                evidence=str(e)
            )
            
    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings = []
        lines = stdout.strip().split("\n")
        for line in lines:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                if "info" in data:
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        title=data["info"].get("name", "Nuclei Finding"),
                        description=data["info"].get("description", ""),
                        severity=str(data["info"].get("severity", "MEDIUM")).upper(),
                        endpoint_id=self.endpoint.endpoint_id,
                        state=FindingState.CANDIDATE,
                        evidence=data
                    ))
            except json.JSONDecodeError:
                pass
        return findings

class DalfoxAdapter(BaseAdapter):
    def __init__(self, endpoint: Endpoint, target: str):
        super().__init__(endpoint, target)
        self.tool_name = "dalfox"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        start = time.time()
        if not _tool_available("dalfox"):
            return _missing_binary_result(self.tool_name, "dalfox", start)

        # dalfox 3.x requires the URL as a flag: `dalfox url --url <URL>` (the bare
        # positional `dalfox url <URL>` errors "required arguments were not
        # provided: --url"). Also sanitize the target (drop METHOD:/get:// prefixes,
        # the SPA #fragment, and un-rendered ${...} template URLs from JS bundles).
        url = _clean_target_url(self.endpoint.url)
        if not url:
            return ToolResult(tool_name=self.tool_name, status=ToolStatus.ERROR,
                              evidence="skipped: invalid/template URL",
                              execution_time_ms=(time.time() - start) * 1000)
        if getattr(self.endpoint, "is_spa_catch_all", False):
            return ToolResult(tool_name=self.tool_name, status=ToolStatus.ERROR,
                              evidence="skipped: SPA catch-all route",
                              execution_time_ms=(time.time() - start) * 1000)

        # F-X3: dalfox `url` mode issues GET requests. A POST-only endpoint (e.g. a
        # JSON write API) can't be tested this way — pointing dalfox at it just
        # times out / returns no_result. Skip it (DOM-XSS on those is covered by the
        # browser-driven dom_sink_monitor).
        methods = {str(m).upper() for m in (getattr(self.endpoint, "method_set", None) or [])}
        if methods and "GET" not in methods:
            return ToolResult(tool_name=self.tool_name, status=ToolStatus.ERROR,
                              evidence=f"skipped: no GET method (methods={sorted(methods)})",
                              execution_time_ms=(time.time() - start) * 1000)

        # F-X3: reflected XSS needs a query surface. If the URL carries no query
        # string, synthesize one from the endpoint's declared query parameters, or
        # (none declared) a generic, app-agnostic reflected-param vocab — so dalfox
        # has values to mutate instead of scanning a bare, param-less URL.
        if "?" not in url:
            names = _dalfox_query_params(self.endpoint)
            if names:
                url = url + "?" + "&".join(f"{n}=1" for n in names)

        # Param + DOM mining and DOM-XSS AST analysis are DEFAULT-ON in current
        # dalfox (the old `--mining-dom`/`--mining-dict`/`--deep-domxss` flags were
        # removed — they now only exist as `--skip-*` opt-outs, and `--worker` is
        # now `--workers`). So we just follow redirects + throttle; mining happens
        # automatically. (Older flags caused rc=2 "unexpected argument".)
        cmd = ["dalfox", "url", "--url", url,
               "--follow-redirects", "--workers", "10", "--delay", "50"]

        try:
            result = _run_cmd(cmd, 120.0)
            duration = (time.time() - start) * 1000
            
            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.ERROR
            findings = self._parse_output(result.stdout)
            
            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                findings=findings,
                evidence=result.stdout,
                execution_time_ms=duration
            )
        except subprocess.TimeoutExpired as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.TIMEOUT,
                evidence=e.stdout.decode() if e.stdout else "",
                execution_time_ms=120000.0
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                evidence=str(e)
            )

    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        import re as _re_dx
        for m in _re_dx.finditer(r"^\s*\[(V|G|R)\]\s+(\S+)(.*)$", stdout, _re_dx.MULTILINE):
            tag, url, tail = m.group(1), m.group(2), (m.group(3) or "").strip()
            if tag == "V":
                severity = "HIGH"
                title = f"XSS confirmed by Dalfox on {url}"
            elif tag == "G":
                severity = "MEDIUM"  # grep-based, weaker signal
                title = f"XSS candidate (grep-match) by Dalfox on {url}"
            else:  # 'R' = reflected but not proven
                severity = "LOW"
                title = f"Dalfox reflected marker on {url}"
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title=title,
                description="Dalfox reported a signal against the parameter.",
                severity=severity,
                endpoint_id=self.endpoint.endpoint_id,
                state=FindingState.CANDIDATE,
                evidence={"tag": tag, "url": url, "detail": tail[:400]},
            ))
        return findings
