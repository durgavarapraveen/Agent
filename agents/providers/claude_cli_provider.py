"""Claude CLI LLM provider — uses the local `claude` CLI (Max/Pro subscription)
instead of a paid API. Temporary stand-in while Bedrock model access is pending.

Implements the harness ``LLMProvider`` interface by shelling out to `claude -p`
in headless JSON mode. The SAME model family is used as Bedrock (haiku = small,
sonnet = large); only the transport differs. Cost is still computed from token
usage at Haiku/Sonnet rates so budgets/reports stay consistent (on a Max plan the
real marginal cost is $0 — the number is a nominal API-equivalent for accounting).

.env:
    LLM_PROVIDER=claude_cli
    CLAUDE_CLI_SMALL_MODEL=haiku       # optional; default haiku
    CLAUDE_CLI_LARGE_MODEL=sonnet      # optional; default sonnet
    CLAUDE_CLI_BIN=claude              # optional; default resolves on PATH
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from typing import Any, Optional

from agents.universal_llm_harness import (
    LLMProvider,
    LLMResponse,
    ProviderType,
    TaskTier,
    TokenBudget,
)

logger = logging.getLogger(__name__)

# Nominal per-1M-token pricing (USD) — Haiku 4.5 / Sonnet 4 published rates.
# Used for accounting only; a Max-plan CLI call has no marginal API cost.
def _price_for(model: str) -> tuple:
    # Authoritative per-model rates (env-overridable); unknown → (0, 0) + warn,
    # never a fabricated default (spec Phase 29).
    from core.economics.pricing import price_for as _pf
    return _pf(model)


class ClaudeCLIProvider(LLMProvider):

    def __init__(self, small_model: str = "", large_model: str = "",
                 bin_path: str = "", budget: Optional[TokenBudget] = None):
        super().__init__(ProviderType.CLAUDE_CLI, budget or TokenBudget())
        self.small_model = small_model or os.getenv("CLAUDE_CLI_SMALL_MODEL", "haiku")
        self.large_model = large_model or os.getenv("CLAUDE_CLI_LARGE_MODEL", "sonnet")
        self._bin = bin_path or os.getenv("CLAUDE_CLI_BIN", "")

    def _resolve_bin(self) -> Optional[str]:
        if self._bin and (os.path.isfile(self._bin) or shutil.which(self._bin)):
            return shutil.which(self._bin) or self._bin
        found = shutil.which("claude")
        if found:
            self._bin = found
        return found

    async def is_available(self) -> bool:
        if self._resolve_bin() is None:
            logger.warning("ClaudeCLIProvider unavailable: `claude` not found on PATH "
                           "(set CLAUDE_CLI_BIN)")
            return False
        return True

    def get_small_model(self) -> str:
        return self.small_model

    def get_large_model(self) -> str:
        return self.large_model

    def supports_native_tools(self) -> bool:
        # The CLI has no native tool-calling API (generate_with_tools returns a
        # plain completion), so callers must use the JSON-planner path.
        return False

    def count_tokens(self, text: str) -> int:
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except Exception:
            return max(1, len(text) // 4)

    async def generate_response(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL,
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        binp = self._resolve_bin()
        start = time.monotonic()
        if binp is None:
            return LLMResponse(content="", provider="claude_cli", model=model,
                               error="claude CLI not found", latency_ms=0.0)

        # temperature is not exposed by the CLI; response_format is honoured by
        # asking for raw JSON in the system prompt when json is requested.
        sys_prompt = system or ""
        if response_format == "json":
            sys_prompt = (sys_prompt + "\n\nRespond with a single valid JSON object "
                          "only. No prose, no markdown fences.").strip()

        # `claude` on Windows is a .CMD shim invoked through cmd.exe, whose command
        # line is capped (~8 KB). A large system prompt — e.g. RAG-injected context —
        # passed via --append-system-prompt overflows it (WinError 206) and the spawn
        # fails. stdin has no such limit, so fold an oversized system prompt into the
        # stdin payload instead of argv. Small system prompts keep the native flag.
        _SYS_ARG_MAX = 3500
        # Total argv budget for the Windows .CMD shim (cmd.exe line cap ~8 KB,
        # WinError 206 above it). Keep whole command line comfortably under it.
        _ARG_MAX = 7000
        args = [binp, "-p", "--output-format", "json", "--model", model]

        # Small system prompt → native flag; large → fold into the prompt body
        # (argv or stdin below), never --append-system-prompt (overflows argv).
        sys_in_flag = bool(sys_prompt) and len(sys_prompt) <= _SYS_ARG_MAX
        if sys_in_flag:
            args += ["--append-system-prompt", sys_prompt]
            effective_prompt = prompt or ""
        elif sys_prompt:
            effective_prompt = f"{sys_prompt}\n\n---\n\n{prompt}"
        else:
            effective_prompt = prompt or ""

        # The CLI needs the prompt via a positional arg OR stdin. Prefer the arg
        # (avoids the .cmd-shim stdin race that yields "no stdin data received in
        # 3s"); fall back to stdin only when the arg would overflow the cmdline.
        # Guard empty: an all-in-system-prompt call left stdin empty and the CLI
        # exited with "Input must be provided".
        if not effective_prompt.strip():
            effective_prompt = prompt or sys_prompt or "Proceed."
        used_len = len(effective_prompt) + (len(sys_prompt) if sys_in_flag else 0)
        if used_len <= _ARG_MAX:
            args.append(effective_prompt)
            stdin_payload = ""
        else:
            stdin_payload = effective_prompt

        # stdin handling. The `claude` .cmd shim on Windows loses a PIPE-written
        # stdin (its 3s stdin-detection races the pipe write → "no stdin data
        # received in 3s" then "Input must be provided"). So:
        #   - argv route (prompt is a positional arg): give the CLI DEVNULL so it
        #     never waits on stdin at all.
        #   - stdin route (oversized prompt): hand it a REAL file descriptor, read
        #     immediately with no pipe race, instead of communicate(input=...).
        import tempfile
        _stdin_path = None
        _stdin_fh = None
        try:
            if stdin_payload:
                fd, _stdin_path = tempfile.mkstemp(suffix=".claude_prompt.txt")
                with os.fdopen(fd, "w", encoding="utf-8") as _w:
                    _w.write(stdin_payload)
                _stdin_fh = open(_stdin_path, "rb")
                _stdin_arg = _stdin_fh
            else:
                _stdin_arg = asyncio.subprocess.DEVNULL

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=_stdin_arg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            return LLMResponse(content="", provider="claude_cli", model=model,
                               error=f"claude CLI timeout after {self.timeout}s",
                               latency_ms=(time.monotonic() - start) * 1000)
        except Exception as e:
            return LLMResponse(content="", provider="claude_cli", model=model,
                               error=str(e), latency_ms=(time.monotonic() - start) * 1000)
        finally:
            if _stdin_fh is not None:
                try:
                    _stdin_fh.close()
                except Exception:
                    pass
            if _stdin_path:
                try:
                    os.unlink(_stdin_path)
                except Exception:
                    pass

        latency = (time.monotonic() - start) * 1000
        raw = (out or b"").decode("utf-8", errors="replace").strip()
        if proc.returncode != 0 and not raw:
            estderr = (err or b"").decode("utf-8", errors="replace")[:500]
            return LLMResponse(content="", provider="claude_cli", model=model,
                               error=f"claude CLI exit {proc.returncode}: {estderr}",
                               latency_ms=latency)

        content, in_tok, out_tok, cache_read, cache_create, cli_err = self._parse_cli_json(raw)
        if cli_err:
            return LLMResponse(content=content, provider="claude_cli", model=model,
                               error=cli_err, latency_ms=latency)

        pin, pout = _price_for(model)
        cost = (in_tok * pin + out_tok * pout) / 1_000_000

        structured = self._try_json(content) if response_format == "json" else None

        return LLMResponse(
            content=content, structured_output=structured, provider="claude_cli",
            model=model,
            usage={"input_tokens": in_tok, "output_tokens": out_tok,
                   "total_tokens": in_tok + out_tok},
            cost_usd=round(cost, 6), latency_ms=latency,
            cache_hit_tokens=cache_read, cache_miss_tokens=cache_create)

    async def generate_with_tools(
        self,
        messages: list,
        tools: list,
        max_tokens: int = 4096,
        tier: TaskTier = TaskTier.LARGE,
        tool_executor=None,
        max_rounds: int = 10,
    ) -> LLMResponse:
        # The CLI runs its own agent/tool loop; external tool schemas + executors
        # can't be injected. P1-I3: when the caller actually wired a tool_executor
        # (i.e. it expects real native tool-calling), do NOT silently degrade to a
        # toolless completion — surface a typed error so the caller deterministically
        # falls back to the JSON-planner path instead of losing tool calls unnoticed.
        if tools and tool_executor is not None:
            logger.warning("[claude_cli] native tool-calling unsupported; signaling caller to use JSON-planner")
            return LLMResponse(content="", provider="claude_cli", model="",
                               error="native_tools_unsupported")
        # No executor wired → a plain completion is the intended best-effort.
        logger.warning("[claude_cli] generate_with_tools: external tools ignored "
                       "(CLI provider); returning plain completion")
        sys_parts = [m.get("content", "") for m in messages if m.get("role") == "system"]
        convo = []
        for m in messages:
            if m.get("role") == "system":
                continue
            c = m.get("content", "")
            if isinstance(c, list):
                c = "".join(b.get("text", "") for b in c if isinstance(b, dict))
            convo.append(f"{m.get('role', 'user')}: {c}")
        return await self.generate_response(
            "\n\n".join(convo), system="\n\n".join(p for p in sys_parts if p),
            max_tokens=max_tokens, tier=tier)

    @staticmethod
    def _parse_cli_json(raw: str):
        """Return (content, in_tok, out_tok, cache_read, cache_create, error)."""
        import re
        data: Any
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            # stdout may carry a leading init/log line — grab the last JSON object.
            m = re.findall(r"\{[\s\S]*\}", raw)
            try:
                data = json.loads(m[-1]) if m else None
            except (ValueError, TypeError):
                data = None
            if data is None:
                return raw, 0, 0, 0, 0, None  # plain text
        if isinstance(data, list):  # stream-json fallback: take last result event
            data = next((e for e in reversed(data)
                         if isinstance(e, dict) and e.get("type") == "result"),
                        data[-1] if data else {})
        if not isinstance(data, dict):
            return str(data), 0, 0, 0, 0, None
        usage = data.get("usage", {}) or {}
        in_tok = int(usage.get("input_tokens", 0) or 0)
        out_tok = int(usage.get("output_tokens", 0) or 0)
        cache_read = int(usage.get("cache_read_input_tokens", 0) or 0)
        cache_create = int(usage.get("cache_creation_input_tokens", 0) or 0)
        # Error detection: is_error, api_error_status (e.g. 429 rate/usage limit),
        # error subtype, or an api_error terminal reason.
        is_err = bool(data.get("is_error")) or data.get("subtype") == "error" \
            or data.get("terminal_reason") == "api_error" or data.get("api_error_status")
        result = data.get("result") or data.get("content") or ""
        if isinstance(result, list):
            result = "".join(b.get("text", "") for b in result if isinstance(b, dict))
        if is_err:
            code = data.get("api_error_status")
            msg = str(result or data.get("error") or "claude CLI error")
            err = f"HTTP {code}: {msg}" if code else msg
            return "", in_tok, out_tok, cache_read, cache_create, err
        return result, in_tok, out_tok, cache_read, cache_create, None

    @staticmethod
    def _try_json(text: str):
        import re
        try:
            return json.loads(re.sub(r"```json\n?|\n?```", "", text or "").strip())
        except (ValueError, TypeError):
            m = re.search(r"\{[\s\S]*\}", text or "")
            if m:
                try:
                    return json.loads(m.group(0))
                except (ValueError, TypeError):
                    return None
            return None
