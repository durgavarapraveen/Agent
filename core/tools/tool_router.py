import logging
from typing import List, Any
from core.common.schemas import ToolInvocation, ToolResult

logger = logging.getLogger(__name__)

class ToolRouter:
    
    def __init__(self, tool_registry):
        self.registry = tool_registry
        self.effectiveness_db = EffectivenessDB()
    
    async def route_and_execute(self, invocation: ToolInvocation, 
                               auth_context) -> ToolResult:
        
        # Get all tools that implement this operation
        capable_tools = self._get_tools_for_operation(invocation.operation)
        
        if not capable_tools:
            from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
            return SchemaToolResult(
                tool=invocation.tool_id or invocation.operation or "unknown",
                capability=invocation.operation or "unknown",
                status=ToolExecutionStatus.FAILED,
                target=invocation.target,
                error=ErrorInfo(
                    error_type=ErrorType.TOOL_UNAVAILABLE,
                    message=f"No tools available for {invocation.operation}",
                    tool=invocation.tool_id
                )
            )
        
        # Score each tool
        scored = []
        req_tool = invocation.tool_id or invocation.params.get("tool") or invocation.params.get("preferred_tool")
        req_obj = str(invocation.params.get("objective", ""))
        for tool in capable_tools:
            score = await self._score_tool(
                tool,
                target=invocation.target,
                target_profile=auth_context.target_profile if auth_context else None,
                requested_tool=req_tool,
                objective=req_obj
            )
            scored.append((tool, score))
        
        # Sort by score
        scored.sort(key=lambda x: x[1], reverse=True)
        
        logger.info(f"Routing {invocation.operation}:")
        for tool, score in scored[:3]:
            logger.info(f"  {tool.name}: {score:.2f}")
        
        # Execute best tool
        best_tool = scored[0][0]
        invocation.tool_id = best_tool.name
        
        # Actually execute the tool
        import time
        start_time = time.time()
        try:
            import inspect
            
            # If it's a KaliTool and no command is provided, build one from target
            if best_tool.__class__.__name__ == "KaliTool" and "command" not in invocation.params:
                target = invocation.params.get("target", invocation.target)
                tname = best_tool.name
                if target:
                    # Validate + escape target/domain before interpolating into
                    # shell commands executed inside the Kali container. Previously
                    # `target` was interpolated raw via f-strings; a target string
                    # containing shell metacharacters (`;`, `` ` ``, `$()`, `|`)
                    # would achieve command injection.
                    import shlex, re as _re_router

                    def _valid_url(s: str) -> bool:
                        return bool(_re_router.match(
                            r'^https?://[A-Za-z0-9\.\-_:]+(?::\d+)?(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]*)?$',
                            s))

                    def _valid_host(s: str) -> bool:
                        return bool(_re_router.match(
                            r'^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$', s))

                    # Strip http(s):// for tools that expect domain names
                    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                    # Also derive a base domain for tools that fail on subdomains or just need the root
                    base_domain = domain[4:] if domain.startswith("www.") else domain

                    # Refuse to build the command if either form fails validation.
                    if not (_valid_url(target) or _valid_host(target)) or not _valid_host(domain):
                        from core.common.schemas import (
                            ToolResult as _STR, ToolExecutionStatus as _TES,
                            ErrorInfo as _EI, ErrorType as _ET,
                        )
                        return _STR(
                            tool=tname,
                            capability=invocation.operation or "unknown",
                            status=_TES.FAILED,
                            target=target,
                            error=_EI(
                                error_type=_ET.TOOL_UNAVAILABLE,
                                message=f"Target failed validation (potential injection): {target!r}",
                                tool=tname,
                            ),
                        )

                    # shlex-quote every substituted value.
                    t = shlex.quote(target)
                    d = shlex.quote(domain)
                    bd = shlex.quote(base_domain)
                    if tname == "subfinder":
                        invocation.params["command"] = f"subfinder -d {bd} -silent"
                    elif tname == "assetfinder":
                        invocation.params["command"] = f"assetfinder --subs-only {bd}"
                    elif tname == "dnsenum":
                        invocation.params["command"] = f"dnsenum {bd}"
                    elif tname == "fierce":
                        invocation.params["command"] = f"fierce --domain {bd}"
                    elif tname == "httpx":
                        invocation.params["command"] = f"httpx-toolkit -u {t} -silent -title -tech-detect -status-code"
                    elif tname == "nuclei":
                        invocation.params["command"] = (
                            f"nuclei -u {t} "
                            f"-tags cve,misconfig,exposure,tech,default-login,takeover "
                            f"-severity info,low,medium,high,critical -jsonl -silent"
                        )
                    elif tname == "nmap":
                        ea = invocation.params.get("extra_args", "") or ""
                        use_fast = "-F" if "-p" not in ea and "--top-ports" not in ea else ""
                        invocation.params["command"] = f"nmap -sT -sV {use_fast} --unprivileged {d}".replace("  ", " ")
                    elif tname == "masscan":
                        invocation.params["command"] = f"masscan {d} -p1-1000 --rate=1000"
                    elif tname == "whatweb":
                        invocation.params["command"] = f"whatweb {t}"
                    elif tname == "nikto":
                        invocation.params["command"] = f"nikto -h {t}"
                    elif tname == "wafw00f":
                        invocation.params["command"] = f"wafw00f {t}"
                    elif tname == "sqlmap":
                        invocation.params["command"] = f"sqlmap -u {t} --batch"
                    elif tname == "katana":
                        invocation.params["command"] = f"katana -u {t} -d 2 -silent"
                    elif tname == "ffuf":
                        # FUZZ marker appended after the escaped target
                        invocation.params["command"] = f"ffuf -u {t}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403"
                    elif tname in ("dirb", "dirsearch", "feroxbuster", "gobuster"):
                        if tname == "gobuster":
                            invocation.params["command"] = f"gobuster dir -u {t} -w /usr/share/wordlists/dirb/common.txt -q"
                        elif tname == "feroxbuster":
                            invocation.params["command"] = f"feroxbuster -u {t} -w /usr/share/wordlists/dirb/common.txt -q"
                        else:
                            invocation.params["command"] = f"{tname} -u {t}"
                    elif tname == "dig":
                        invocation.params["command"] = f"dig {bd}"
                    elif tname == "whois":
                        invocation.params["command"] = f"whois {d}"
                    elif tname == "sslscan":
                        invocation.params["command"] = f"sslscan --no-colour {d}"
                    elif tname == "sslyze":
                        invocation.params["command"] = f"sslyze {d}"
                    elif tname == "theharvester":
                        invocation.params["command"] = f"theHarvester -d {bd} -b all -l 100"
                    elif tname == "wpscan":
                        invocation.params["command"] = f"wpscan --url {t} --enumerate vp,vt --no-banner"
                    elif tname == "dalfox":
                        # --skip-bav removed: rejected by current dalfox (rc=2,
                        # "unexpected argument '--skip-bav'"), which the pipeline
                        # then mislabels as a WAF block. The BAV scan is optional;
                        # dropping the flag lets the XSS scan run.
                        invocation.params["command"] = f"dalfox url {t} --silence --no-color"
                    elif tname == "arjun":
                        invocation.params["command"] = f"arjun -u {t} --stable"
                    else:
                        invocation.params["command"] = f"{tname} {t}"
                    logger.info(f"Auto-constructed command for {tname}: {invocation.params['command']}")

            # If it's a PythonHTTPTool and no url is provided, set url from target
            elif best_tool.__class__.__name__ == "PythonHTTPTool" and "url" not in invocation.params:
                target = invocation.params.get("target", invocation.target)
                if target:
                    invocation.params["url"] = target
                    # Remove 'target' key since PythonHTTPTool.run() doesn't accept it
                    invocation.params.pop("target", None)
                    logger.info(f"Auto-set url={target} for http_request tool")

            # If it's a PythonDNSTool or PythonSSLTool, map target → domain
            elif best_tool.__class__.__name__ in ("PythonDNSTool", "PythonSSLTool") and "domain" not in invocation.params:
                target = invocation.params.get("target", invocation.target)
                if target:
                    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                    invocation.params["domain"] = domain
                    invocation.params.pop("target", None)
                    logger.info(f"Auto-set domain={domain} for {best_tool.name}")

            # If it's a PythonPortScanTool, map target → host
            elif best_tool.__class__.__name__ == "PythonPortScanTool" and "host" not in invocation.params:
                target = invocation.params.get("target", invocation.target)
                if target:
                    host = target.replace("https://", "").replace("http://", "").split("/")[0]
                    invocation.params["host"] = host
                    invocation.params["port"] = invocation.params.get("port", 443)
                    invocation.params.pop("target", None)
                    logger.info(f"Auto-set host={host} for port_check")

            # Remove 'target' from params for tools that don't expect it as a kwarg
            if "target" in invocation.params and best_tool.__class__.__name__ in ("KaliTool", "PythonDNSTool", "PythonSSLTool", "PythonPortScanTool"):
                invocation.params.pop("target", None)

            # Strip routing-only params that tools don't accept as kwargs
            invocation.params.pop("objective", None)
            invocation.params.pop("preferred_tool", None)
            extra_args = invocation.params.pop("extra_args", None)

            # Append extra_args to command for KaliTool — only safe flags and their values
            if extra_args and "command" in invocation.params and best_tool.__class__.__name__ == "KaliTool":
                import re as _re
                # REJECT — don't silently accept the prefix — when extra_args
                # contains shell metacharacters. The previous "keep the first
                # segment before the first `|;&\`$()`" behavior silently
                # discarded the tail, which could still be attacker-influenced
                # by an LLM that split its exploit across shell operators.
                _operator_passthrough = False
                if _re.search(r'[|;&`$()]', extra_args):
                    from core.utils.scan_flags import allow_shell_operators
                    if allow_shell_operators():
                        # Operator chars present, and operator-passthrough was
                        # authorised at scan start. Do NOT run them as shell
                        # control: shlex-tokenise (respecting the LLM's quoting)
                        # then shlex.quote each token so the characters survive as
                        # LITERAL DATA (e.g. sqlmap --data="a=1&b=2"). Safe and
                        # compliant, as the Kali layer now runs shell=False.
                        try:
                            import shlex as _shlex
                            toks = _shlex.split(extra_args)
                            extra_args = " ".join(_shlex.quote(tk) for tk in toks)
                            _operator_passthrough = True
                        except ValueError:
                            logger.warning(
                                "Unbalanced quotes in extra_args; rejecting: %r",
                                extra_args[:80],
                            )
                            extra_args = ""
                    else:
                        logger.warning(
                            "Rejecting extra_args containing shell operators "
                            "(shell passthrough disabled for this scan): %r",
                            extra_args[:80],
                        )
                        extra_args = ""
                clean_args = extra_args.strip()
                if not _operator_passthrough:
                    # Strip ALL quotes from extra_args — quoted values from LLM
                    # break when split on spaces; the underlying tools don't need
                    # them. Skipped when we deliberately shlex-quoted above.
                    clean_args = clean_args.replace('"', '').replace("'", '')

                # Strip known-bad flags that LLMs generate but tools reject
                # sslscan doesn't accept --target=; nmap --top-ports needs int validation
                _BAD_FLAG_PATTERNS = [
                    r'--target=[^\s]*',        # sslscan doesn't use --target=
                    r'--host=[^\s]*',           # not a valid flag for most tools
                ]
                for pat in _BAD_FLAG_PATTERNS:
                    clean_args = _re.sub(pat, '', clean_args).strip()

                # Per-tool bad-flag stripping — LLMs mix up ffuf/feroxbuster/etc
                # syntax. Strip flags the tool does NOT support so it still runs
                # instead of failing rc=2.
                base_cmd_l = invocation.params.get("command", "").split()
                base_bin = (base_cmd_l[0] if base_cmd_l else "").lower()
                _PER_TOOL_STRIP = {
                    # feroxbuster uses -s "200 301" (space-sep), NOT ffuf's -mc "200,301"
                    "feroxbuster": [
                        r'-mc\s+[^\s]+',           # ffuf flag
                        r'-fs\s+[^\s]+',           # ffuf flag
                        r'-fw\s+[^\s]+',           # ffuf flag
                        r'-o\s+/dev/stdout',       # duplicate output redirection
                        r'-x\s+php,json,bak,txt,html',  # comma-list rejected; use -x per ext
                    ],
                    # wafw00f only accepts -v (verbose); -silent/-s/-o etc all invalid
                    "wafw00f": [
                        r'-silent\b',
                        r'-s\b(?!\S)',             # bare -s (short for something else)
                        r'-o\s+[^\s]+',
                        r'--silent\b',
                    ],
                    # gobuster dir: -q and --no-error are valid but LLM sometimes adds -mc
                    "gobuster": [
                        r'-mc\s+[^\s]+',
                        r'-fs\s+[^\s]+',
                    ],
                    # dirsearch: -silent invalid; only -q
                    "dirsearch": [
                        r'-silent\b',
                        r'--silent\b',
                    ],
                    # whatweb: -mc/-fs are ffuf-only
                    "whatweb": [
                        r'-mc\s+[^\s]+',
                        r'-fs\s+[^\s]+',
                    ],
                }
                for bin_name, patterns in _PER_TOOL_STRIP.items():
                    if base_bin.endswith(bin_name) or base_bin == bin_name:
                        for pat in patterns:
                            new_args = _re.sub(pat, '', clean_args).strip()
                            if new_args != clean_args:
                                logger.info(f"Stripped invalid {bin_name} flag matching {pat!r}")
                                clean_args = new_args
                        # collapse double spaces
                        clean_args = _re.sub(r'\s+', ' ', clean_args).strip()
                        break

                # Validate --top-ports value is a positive integer
                top_ports_match = _re.search(r'--top-ports\s+(\S+)', clean_args)
                if top_ports_match:
                    try:
                        int(top_ports_match.group(1))
                    except ValueError:
                        clean_args = _re.sub(r'--top-ports\s+\S+', '', clean_args).strip()
                        logger.info(f"Stripped invalid --top-ports value: {top_ports_match.group(1)}")

                base_cmd = invocation.params["command"]
                base_tokens = set(base_cmd.split())
                # Extract the target domain/URL from base command for dedup
                base_target = invocation.params.get("target", "")
                tokens = clean_args.split()
                deduped_parts = []
                i = 0
                while i < len(tokens):
                    token = tokens[i]
                    if token.startswith("-"):
                        if token in base_tokens:
                            i += 1
                            if i < len(tokens) and not tokens[i].startswith("-"):
                                i += 1
                            continue
                        # Check if this flag's value is just the target again
                        if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                            flag_val = tokens[i + 1]
                            norm_val = flag_val.replace("https://", "").replace("http://", "").split(":")[0].rstrip("/")
                            norm_tgt = base_target.replace("https://", "").replace("http://", "").split(":")[0].rstrip("/") if base_target else ""
                            if norm_tgt and (norm_val == norm_tgt or norm_tgt in norm_val or norm_val in norm_tgt):
                                logger.debug(f"Rejecting flag {token} {flag_val} (duplicate target)")
                                i += 2
                                continue
                        deduped_parts.append(token)
                        if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                            i += 1
                            deduped_parts.append(tokens[i])
                    else:
                        # Reject bare words that duplicate the target or are already in base cmd
                        DNS_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "SRV", "CAA", "ANY"}
                        if token in base_tokens:
                            pass
                        elif base_target and (base_target in token or token in base_target):
                            logger.debug(f"Rejecting duplicate target in extra_args: {token}")
                        elif any(c in token for c in ".:/"):
                            deduped_parts.append(token)
                        elif token.upper() in DNS_RECORD_TYPES:
                            deduped_parts.append(token)
                        else:
                            logger.debug(f"Rejecting bare-word extra_arg: {token}")
                    i += 1
                if deduped_parts:
                    invocation.params["command"] = f"{base_cmd} {' '.join(deduped_parts)}"
                    logger.info(f"Appended extra_args to command: {invocation.params['command']}")
                else:
                    logger.info(f"Skipped duplicate extra_args for: {base_cmd}")

            if inspect.iscoroutinefunction(best_tool.run):
                raw_result = await best_tool.run(**invocation.params)
            else:
                raw_result = best_tool.run(**invocation.params)
                
            from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus
            
            result = SchemaToolResult(
                tool=best_tool.name,
                capability=invocation.operation,
                status=ToolExecutionStatus.SUCCESS if raw_result.success else ToolExecutionStatus.FAILED,
                stdout=raw_result.output,
                stderr=raw_result.error,
                data=raw_result.data,
                target=invocation.target,
                duration_seconds=time.time() - start_time
            )
        except Exception as e:
            from core.common.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
            result = SchemaToolResult(
                tool=best_tool.name,
                capability=invocation.operation,
                status=ToolExecutionStatus.FAILED,
                target=invocation.target,
                duration_seconds=time.time() - start_time,
                error=ErrorInfo(
                    error_type=ErrorType.EXECUTION_ERROR,
                    message=str(e),
                    tool=best_tool.name
                )
            )
        
        # Measure effectiveness
        await self.effectiveness_db.update(
            tool_id=best_tool.name,
            success=result.success,
            time_taken=result.duration_seconds,
            target_type=getattr(auth_context.target_profile, 'target_type', 'generic').value if auth_context and hasattr(auth_context, 'target_profile') and auth_context.target_profile and hasattr(getattr(auth_context.target_profile, 'target_type', None), 'value') else "generic"
        )
        
        return result
    
    async def _score_tool(self, tool: Any, target: str, 
                         target_profile=None, requested_tool: str = None, objective: str = "") -> float:
        
        score = 0.0

        # Prioritize explicitly requested tool or tool named in objective
        if requested_tool and requested_tool.lower() == tool.name.lower():
            score += 0.5
        elif objective and tool.name.lower() in objective.lower():
            score += 0.35
        
        # Historical effectiveness
        historical = await self.effectiveness_db.get_score(
            tool.name, 
            getattr(target_profile, 'target_type', 'generic').value if target_profile and hasattr(getattr(target_profile, 'target_type', None), 'value') else "generic"
        )
        score += historical * 0.4
        
        # Target type match
        if target_profile:
            match_score = self._target_match_score(tool, target_profile)
            score += match_score * 0.3
        
        # Speed (faster = higher score)
        speed_score = 0.5  # default
        score += speed_score * 0.2
        
        # False positive rate (lower FP = higher score)
        fp_score = 0.5  # default
        score += fp_score * 0.1
        
        return min(1.0, score)
    
    def _target_match_score(self, tool: Any, target_profile) -> float:
        
        score = 0.0
        
        # Is this tool designed for this type of target?
        if hasattr(tool, 'category'):
            target_type_val = getattr(target_profile, 'target_type', None)
            target_type_str = target_type_val.value if hasattr(target_type_val, 'value') else str(target_type_val)
            if target_type_str in ("web_application", "web") and "recon" in tool.category:
                score += 0.5
        
        # If target has WAF, slow down the tool
        if getattr(target_profile, 'waf_detected', False):
            # Tool should use slower timing
            score *= 0.8
        
        # If target is API-only, prefer API tools
        if getattr(target_profile, 'is_api_only', False) and hasattr(tool, 'category') and "api" in tool.category:
            score += 0.2
        
        return min(1.0, score)
    
    def _get_tools_for_operation(self, operation: str) -> List[Any]:
        
        # Map operation → tool_ids (aligned with HexStrike AI capability architecture)
        op_map = {
            "port_scanning": ["nmap", "masscan", "port_check"],
            "dns_enumeration": ["subfinder", "assetfinder", "dnsenum", "fierce"],
            "subdomain_enumeration": ["subfinder", "assetfinder"],
            "technology_fingerprinting": ["httpx", "whatweb", "wafw00f"],
            "endpoint_discovery": ["katana", "ffuf", "feroxbuster", "gobuster", "dirsearch", "dirb", "http_request"],
            "vulnerability_scanning": ["nuclei", "nikto", "wpscan", "sqlmap"],
            "authentication_testing": ["hydra", "ffuf", "gobuster", "http_request"],
            "sql_injection": ["sqlmap"],
            "tls_analysis": ["sslscan", "sslyze", "ssl_inspect", "openssl"],
            "web_crawling": ["katana", "http_request"],
            "http_analysis": ["httpx", "curl", "http_request"],
            "javascript_analysis": ["katana", "http_request"],
            "parameter_discovery": ["arjun", "paramspider", "katana", "ffuf"],
            "xss_scanning": ["dalfox", "nuclei"],
            "waf_detection": ["wafw00f", "httpx", "whatweb"],
            "employee_enumeration": ["theharvester"],
            "github_scanning": ["http_request"],
            "dns_intelligence": ["dig", "whois", "dnsenum", "dns_lookup"],
            "threat_intelligence": ["http_request"],
            # P2-8: structured HTTP operations. The LLM asks for a capability
            # (e.g. `api_route_extraction`) and the router picks the
            # matching adapter from core/tools/http_ops_tools.py.
            "http_fetch":           ["http_fetch", "http_request", "httpx", "curl"],
            "http_get":             ["http_fetch"],
            "http_post":            ["http_fetch"],
            "link_extraction":      ["extract_links"],
            "api_route_extraction": ["extract_api_routes"],
            "file_link_extraction": ["extract_file_links"],
            "regex_extraction":     ["extract_regex"],
            "html_parsing":         ["parse_html"],
            "json_parsing":         ["parse_json"],
            "response_diff":        ["compare_responses"],
            "header_extraction":    ["extract_headers"],
        }
        
        tool_ids = op_map.get(operation, [])
        tools = []

        for tool_id in tool_ids:
            tool = self.registry.get(tool_id)
            if tool:
                tools.append(tool)

        # Fallback: if operation didn't match any op_map key, try it as a direct tool name
        if not tools:
            direct = self.registry.get(operation)
            if direct:
                tools.append(direct)
            else:
                # Try reverse lookup: scan op_map values for the operation string
                for _op, _ids in op_map.items():
                    if operation in _ids:
                        for tid in _ids:
                            t = self.registry.get(tid)
                            if t and t not in tools:
                                tools.append(t)
                        break

        return tools


class EffectivenessDB:
    
    def __init__(self):
        from core.memory.database import DatabaseManager
        self.db = DatabaseManager
        with self.db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS tool_effectiveness (
                        tool_id TEXT,
                        target_type TEXT,
                        success_count INTEGER DEFAULT 0,
                        total_count INTEGER DEFAULT 0,
                        avg_time DOUBLE PRECISION DEFAULT 0.0,
                        PRIMARY KEY (tool_id, target_type)
                    )
                """)
                conn.commit()
    
    async def get_score(self, tool_id: str, target_type: str) -> float:
        with self.db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT success_count, total_count, avg_time FROM tool_effectiveness WHERE tool_id = %s AND target_type = %s",
                    (tool_id, target_type)
                )
                row = cur.fetchone()
        
        if not row or row[1] == 0:
            return 0.5  # default score
            
        success_count, total_count, avg_time = row
        success_rate = success_count / total_count
        
        # speed score: faster than 10 seconds is 1.0, slower than 600 is 0.0
        speed_score = max(0.0, min(1.0, 1.0 - (avg_time / 600.0)))
        
        score = (success_rate * 0.7) + (speed_score * 0.3)
        return score
    
    async def update(self, tool_id: str, success: bool, 
                    time_taken: float, target_type: str):
        success_val = 1 if success else 0
        with self.db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tool_effectiveness (tool_id, target_type, success_count, total_count, avg_time)
                    VALUES (%s, %s, %s, 1, %s)
                    ON CONFLICT (tool_id, target_type) DO UPDATE SET
                        success_count = tool_effectiveness.success_count + EXCLUDED.success_count,
                        total_count = tool_effectiveness.total_count + 1,
                        avg_time = ((tool_effectiveness.avg_time * tool_effectiveness.total_count) + EXCLUDED.avg_time) / (tool_effectiveness.total_count + 1)
                    """,
                    (tool_id, target_type, success_val, time_taken)
                )
                conn.commit()
