"""Metasploit auxiliary-scanner adapter (Level-A: read-only verification only).

HARD SAFETY CONTRACT:
- Only `auxiliary/scanner/*` modules may run. The `exploit/`, `post/`,
  `payload/`, `auxiliary/{dos,fuzzers}/` and `*/login|brute|enum_users`
  namespaces are refused — this is a non-negotiable control, not a default.
- RHOSTS is scope-validated through TargetScopeValidator (fail-closed on
  empty scope), exactly like every other tool.
- Off unless NEO_ENABLE_MSF is set — see core.utils.scan_flags.enable_metasploit.
- msfconsole is never auto-installed (heavy image); a missing binary just
  yields a normal tool failure.
No session handlers, no LHOST, no meterpreter. See prior discussion for why
B/C (armed exploit / post) are intentionally out of scope.
"""
from __future__ import annotations

import re
import shlex

from core.tools.tool_registry import KaliTool

# Only aux SCANNER modules; every intrusive family is denied even under the
# scanner prefix.
_ALLOWED = re.compile(r"^auxiliary/scanner/[a-z0-9_]+/[a-z0-9_]+$")
_DENIED_SUBSTR = ("login", "brute", "enum_users", "fuzzer", "/dos/", "dos_")

# Curated non-destructive defaults picked by service port.
_PORT_DEFAULT = {
    445: "auxiliary/scanner/smb/smb_ms17_010",
    139: "auxiliary/scanner/smb/smb_version",
    22: "auxiliary/scanner/ssh/ssh_version",
    21: "auxiliary/scanner/ftp/ftp_version",
    25: "auxiliary/scanner/smtp/smtp_version",
    3389: "auxiliary/scanner/rdp/rdp_scanner",
    443: "auxiliary/scanner/ssl/openssl_heartbleed",
    80: "auxiliary/scanner/http/http_version",
    8080: "auxiliary/scanner/http/http_version",
}


def module_is_allowed(module: str) -> bool:
    m = (module or "").strip().lower()
    if not _ALLOWED.match(m):
        return False
    return not any(s in m for s in _DENIED_SUBSTR)


def _host(target: str) -> str:
    t = (target or "").strip()
    t = t.replace("https://", "").replace("http://", "")
    return t.split("/")[0].split(":")[0]


class MetasploitAuxTool(KaliTool):
    """Runs one allow-listed msf auxiliary scanner against an in-scope host."""

    # non-zero rc from msfconsole is normal; treat like other lenient tools
    def run(self, target: str = None, module: str = None, rhosts: str = None,
            rport: int = None, timeout: int = 600, **_ignored):
        from core.tools.tool_registry import ToolResult as _TR
        from core.utils.scan_flags import enable_metasploit

        if not enable_metasploit():
            return _TR(success=False, output="",
                       error="metasploit disabled (set NEO_ENABLE_MSF=1 to enable, "
                             "authorized targets only)",
                       data={"skipped": "disabled"})

        host = _host(rhosts or target or "")
        if not host:
            return _TR(success=False, output="", error="no RHOSTS/target given")

        # Scope gate — fail-closed. Raises AuthorizationError on out-of-scope.
        try:
            from core.security.authorization import TargetScopeValidator
            TargetScopeValidator.get().validate(host)
        except Exception as e:
            return _TR(success=False, output="", error=f"scope denied: {e}",
                       data={"scope_denied": True})

        try:
            rport_i = int(rport) if rport is not None else None
        except (TypeError, ValueError):
            rport_i = None

        mod = (module or _PORT_DEFAULT.get(rport_i or -1)
               or "auxiliary/scanner/http/http_version").strip()

        if not module_is_allowed(mod):
            return _TR(success=False, output="",
                       error=f"module refused (not an allowed auxiliary/scanner/*): {mod!r}",
                       data={"module_denied": mod})

        rc_parts = [f"use {shlex.quote(mod)}",
                    f"set RHOSTS {shlex.quote(host)}"]
        if rport_i:
            rc_parts.append(f"set RPORT {rport_i}")
        rc_parts += ["run", "exit"]
        resource = "; ".join(rc_parts)
        command = f"msfconsole -q -x {shlex.quote(resource)}"

        r = super().run(command=command, timeout=timeout)
        # annotate for downstream visibility
        try:
            r.data = dict(r.data or {})
            r.data["msf_module"] = mod
        except Exception:
            pass
        return r
