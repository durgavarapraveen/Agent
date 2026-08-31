import logging
from typing import List, Any
from core.schemas import ToolInvocation, ToolResult, ToolDefinition

logger = logging.getLogger(__name__)

class ToolRouter:
    """
    Intelligent tool selection (the DETERMINISTIC part of Approach A).
    
    Given a capability request:
    - "port_scan"
    
    Decides:
    - Which tool? (nmap vs masscan vs zmap)
    - With what params? (timing, ports, detection)
    - In what order? (primary, fallback)
    - In parallel? (yes if non-exclusive)
    """
    
    def __init__(self, tool_registry):
        self.registry = tool_registry
        self.effectiveness_db = EffectivenessDB()
    
    async def route_and_execute(self, invocation: ToolInvocation, 
                               auth_context) -> ToolResult:
        """
        1. Score available tools for this capability
        2. Select best + plan fallbacks
        3. Execute + measure effectiveness
        4. Return result
        """
        
        # Get all tools that implement this operation
        capable_tools = self._get_tools_for_operation(invocation.operation)
        
        if not capable_tools:
            from core.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
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
                    # Strip http(s):// for tools that expect domain names
                    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                    if tname == "subfinder":
                        invocation.params["command"] = f"subfinder -d {domain} -silent"
                    elif tname == "assetfinder":
                        invocation.params["command"] = f"assetfinder --subs-only {domain}"
                    elif tname == "amass":
                        invocation.params["command"] = f"amass enum -d {domain} -passive"
                    elif tname == "dnsenum":
                        invocation.params["command"] = f"dnsenum {domain}"
                    elif tname == "fierce":
                        invocation.params["command"] = f"fierce --domain {domain}"
                    elif tname == "httpx":
                        invocation.params["command"] = f"echo {domain} | httpx -silent -title -tech-detect -status-code"
                    elif tname == "nuclei":
                        invocation.params["command"] = f"nuclei -u {target} -silent"
                    elif tname == "nmap":
                        invocation.params["command"] = f"nmap -sV -F {domain}"
                    elif tname == "masscan":
                        invocation.params["command"] = f"masscan {domain} -p1-1000 --rate=1000"
                    elif tname == "whatweb":
                        invocation.params["command"] = f"whatweb {target}"
                    elif tname == "nikto":
                        invocation.params["command"] = f"nikto -h {target}"
                    elif tname == "wafw00f":
                        invocation.params["command"] = f"wafw00f {target}"
                    elif tname == "sqlmap":
                        invocation.params["command"] = f"sqlmap -u {target} --batch"
                    elif tname == "katana":
                        invocation.params["command"] = f"katana -u {target} -d 2 -silent"
                    elif tname == "ffuf":
                        invocation.params["command"] = f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403"
                    elif tname in ("dirb", "dirsearch", "feroxbuster", "gobuster"):
                        if tname == "gobuster":
                            invocation.params["command"] = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q"
                        elif tname == "feroxbuster":
                            invocation.params["command"] = f"feroxbuster -u {target} -w /usr/share/wordlists/dirb/common.txt -q"
                        else:
                            invocation.params["command"] = f"{tname} -u {target}"
                    elif tname in ("dig", "whois"):
                        invocation.params["command"] = f"{tname} {domain}"
                    elif tname == "sslscan":
                        invocation.params["command"] = f"sslscan --no-colour {domain}"
                    elif tname == "sslyze":
                        invocation.params["command"] = f"sslyze {domain}"
                    elif tname == "theharvester":
                        invocation.params["command"] = f"theHarvester -d {domain} -b all -l 100"
                    elif tname == "wpscan":
                        invocation.params["command"] = f"wpscan --url {target} --enumerate vp,vt --no-banner"
                    else:
                        invocation.params["command"] = f"{tname} {target}"
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

            if inspect.iscoroutinefunction(best_tool.run):
                raw_result = await best_tool.run(**invocation.params)
            else:
                # If run is synchronous but it's an I/O operation, ideally we should run in executor.
                # However, many run methods in tool_registry wrap asyncio.run, so we just call them directly.
                raw_result = best_tool.run(**invocation.params)
                
            from core.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus
            
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
            from core.schemas import ToolResult as SchemaToolResult, ToolExecutionStatus, ErrorInfo, ErrorType
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
        """
        Score 0.0-1.0 based on:
        - Explicit request / objective match
        - Historical effectiveness (40%)
        - Target type match (30%)
        - Speed (20%)
        - False positive rate (10%)
        """
        
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
        """Score how well tool matches target"""
        
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
        """Get all tools implementing this operation"""
        
        # Map operation → tool_ids (aligned with HexStrike AI capability architecture)
        op_map = {
            "port_scanning": ["nmap", "masscan", "port_check"],
            "dns_enumeration": ["subfinder", "amass", "assetfinder", "dnsenum", "fierce"],
            "subdomain_enumeration": ["subfinder", "amass", "assetfinder"],
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
            "dns_intelligence": ["dig", "whois", "dnsenum"],
            "threat_intelligence": ["http_request"],
        }
        
        tool_ids = op_map.get(operation, [])
        tools = []
        
        for tool_id in tool_ids:
            tool = self.registry.get(tool_id)
            if tool:
                tools.append(tool)
        
        return tools


class EffectivenessDB:
    """Track which tools work best on what targets"""
    
    def __init__(self):
        from core.database import DatabaseManager
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
        """Get historical effectiveness (0.0-1.0)"""
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
        """After tool runs, update its score"""
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