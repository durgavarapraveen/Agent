"""
Reachability analysis.

Given a finding (file, line, vulnerable symbol), decide whether the vulnerable
symbol is actually reachable from an entry point (main, __main__ block, route
handler, or exported/public function). This separates "the vulnerable code
exists" from "the vulnerable code can actually run".

  - Python targets: a lightweight call graph via the stdlib `ast` module.
  - JS/TS targets:  via tree-sitter when available; otherwise 'indeterminate'.

Output: 'reachable' | 'unreachable' | 'indeterminate'.
"""

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
INDETERMINATE = "indeterminate"

# Decorator name fragments that mark a function as an entry point (route handler).
_ROUTE_DECORATORS = ("route", "get", "post", "put", "delete", "patch",
                     "middleware", "task", "command", "handler")


@dataclass
class ReachabilityResult:
    status: str                  # reachable | unreachable | indeterminate
    symbol: str
    reason: str = ""
    entry_points: List[str] = field(default_factory=list)
    call_path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"status": self.status, "symbol": self.symbol,
                "reason": self.reason, "entry_points": self.entry_points,
                "call_path": self.call_path}


class _PyCallGraph(ast.NodeVisitor):
    """Builds function -> {called names} and detects entry points."""

    def __init__(self):
        self.graph: Dict[str, Set[str]] = {}
        self.entry_points: Set[str] = set()
        self.defined: Set[str] = set()
        self._stack: List[str] = []

    def _visit_func(self, node):
        name = node.name
        self.defined.add(name)
        self.graph.setdefault(name, set())
        # Entry point if it's a route/task handler or conventionally an entry.
        for dec in node.decorator_list:
            dname = self._dotted(dec).lower()
            if any(frag in dname for frag in _ROUTE_DECORATORS):
                self.entry_points.add(name)
        if name in ("main", "handler", "lambda_handler", "app"):
            self.entry_points.add(name)
        self._stack.append(name)
        self.generic_visit(node)
        self._stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Call(self, node):
        called = self._dotted(node.func)
        callee = called.split(".")[-1] if called else ""
        if self._stack:
            self.graph.setdefault(self._stack[-1], set()).add(callee)
        else:
            # Module-level call: its callee is an entry point (runs on import/run).
            if callee:
                self.entry_points.add(callee)
        self.generic_visit(node)

    def visit_If(self, node):
        # Detect `if __name__ == "__main__":` and treat its calls as entries.
        if self._is_main_guard(node):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    callee = self._dotted(sub.func).split(".")[-1]
                    if callee:
                        self.entry_points.add(callee)
        self.generic_visit(node)

    @staticmethod
    def _is_main_guard(node: ast.If) -> bool:
        try:
            t = node.test
            return (isinstance(t, ast.Compare)
                    and isinstance(t.left, ast.Name) and t.left.id == "__name__")
        except Exception:       # noqa: BLE001
            return False

    @staticmethod
    def _dotted(node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{_PyCallGraph._dotted(node.value)}.{node.attr}"
        return ""


class ReachabilityAnalyzer:
    """Determines whether a vulnerable symbol is reachable from an entry point."""

    def analyze(self, file_path: str, symbol: str,
                extra_files: Optional[List[str]] = None) -> ReachabilityResult:
        if not symbol:
            return ReachabilityResult(INDETERMINATE, symbol, "no symbol provided")

        lang = self._lang(file_path)
        if lang == "python":
            return self._analyze_python(file_path, symbol, extra_files or [])
        if lang in ("javascript", "typescript"):
            return self._analyze_js(file_path, symbol)
        return ReachabilityResult(INDETERMINATE, symbol,
                                  f"unsupported language for {file_path}")

    # ── Python ──

    def _analyze_python(self, file_path: str, symbol: str,
                        extra_files: List[str]) -> ReachabilityResult:
        cg = _PyCallGraph()
        parsed_any = False
        for path in [file_path, *extra_files]:
            src = self._read(path)
            if src is None:
                continue
            try:
                tree = ast.parse(src)
                cg.visit(tree)
                parsed_any = True
            except SyntaxError as e:
                logger.debug(f"[reach] parse error in {path}: {e}")

        if not parsed_any:
            return ReachabilityResult(INDETERMINATE, symbol,
                                      "could not parse source")
        if symbol not in cg.defined:
            # Symbol not defined here — can't prove (un)reachability.
            return ReachabilityResult(INDETERMINATE, symbol,
                                      f"symbol '{symbol}' not found in analyzed files",
                                      entry_points=sorted(cg.entry_points))
        if not cg.entry_points:
            return ReachabilityResult(INDETERMINATE, symbol,
                                      "no entry points detected")

        # BFS from every entry point over the call graph.
        path = self._bfs(cg.graph, cg.entry_points, symbol)
        if path is not None:
            return ReachabilityResult(REACHABLE, symbol,
                                      "reachable from entry point",
                                      entry_points=sorted(cg.entry_points),
                                      call_path=path)
        return ReachabilityResult(UNREACHABLE, symbol,
                                  "defined but not reachable from any entry point",
                                  entry_points=sorted(cg.entry_points))

    @staticmethod
    def _bfs(graph: Dict[str, Set[str]], starts: Set[str],
             target: str) -> Optional[List[str]]:
        from collections import deque
        for start in starts:
            seen = {start}
            q = deque([(start, [start])])
            while q:
                node, trail = q.popleft()
                if node == target:
                    return trail
                for nxt in graph.get(node, ()):  # callees
                    if nxt not in seen:
                        seen.add(nxt)
                        q.append((nxt, trail + [nxt]))
        return None

    # ── JS/TS (optional tree-sitter) ──

    def _analyze_js(self, file_path: str, symbol: str) -> ReachabilityResult:
        try:
            import tree_sitter  # noqa: F401
        except Exception:       # noqa: BLE001
            return ReachabilityResult(
                INDETERMINATE, symbol,
                "tree-sitter not installed; JS/TS reachability unavailable")
        # Minimal heuristic: if the symbol is exported it is externally reachable.
        src = self._read(file_path) or ""
        if (f"export function {symbol}" in src
                or f"export const {symbol}" in src
                or f"exports.{symbol}" in src
                or f"module.exports" in src and symbol in src):
            return ReachabilityResult(REACHABLE, symbol, "exported symbol")
        return ReachabilityResult(INDETERMINATE, symbol,
                                  "tree-sitter present but no export match")

    # ── helpers ──

    @staticmethod
    def _lang(path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        return {".py": "python", ".js": "javascript", ".jsx": "javascript",
                ".ts": "typescript", ".tsx": "typescript"}.get(ext, "")

    @staticmethod
    def _read(path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:       # noqa: BLE001
            return None
