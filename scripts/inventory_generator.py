#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ["core", "agents", "ui", "scripts"]
SOURCE_FILES = ["main.py"]

# ── High-risk primitive detection ─────────────────────────────────────────

NETWORK_IO_PATTERNS = {
    "httpx": ["get", "post", "put", "patch", "delete", "request", "head", "options", "AsyncClient", "Client"],
    "aiohttp": ["ClientSession", "request", "get", "post"],
    "requests": ["get", "post", "put", "patch", "delete", "request", "Session"],
    "urllib": ["urlopen", "Request"],
    "socket": ["socket", "connect", "send", "recv", "getaddrinfo", "create_connection"],
    "asyncio": ["open_connection"],
}

PROCESS_EXEC_PATTERNS = {
    "subprocess": ["run", "Popen", "call", "check_output", "check_call"],
    "os": ["system", "popen", "exec", "execl", "execle", "execlp", "execvp", "execvpe", "spawn"],
    "shutil": ["which"],
}

BROWSER_PATTERNS = {
    "playwright": ["chromium", "firefox", "webkit", "launch", "new_page", "goto", "click", "fill"],
    "selenium": ["webdriver", "Chrome", "Firefox"],
}

FILESYSTEM_WRITE_PATTERNS = {
    "builtins": ["open"],
    "pathlib": ["write_text", "write_bytes", "touch", "mkdir", "unlink", "rmdir"],
    "os": ["makedirs", "remove", "unlink", "rmdir", "rename", "replace"],
    "shutil": ["rmtree", "copy", "copy2", "copytree", "move"],
}

DYNAMIC_EXEC_PATTERNS = {
    "builtins": ["eval", "exec", "compile", "__import__"],
    "importlib": ["import_module"],
}

CREDENTIAL_ACCESS_PATTERNS = {
    "os": ["getenv", "environ"],
    "dotenv": ["load_dotenv", "dotenv_values"],
}

STATE_MUTATION_KEYWORDS = [
    "INSERT", "UPDATE", "DELETE", "CREATE TABLE", "DROP TABLE", "ALTER TABLE",
    "TRUNCATE", "execute", "executemany", "commit",
]

RISK_CATEGORIES = {
    "network_io": "Network I/O",
    "process_exec": "Process Execution",
    "browser_action": "Browser Automation",
    "filesystem_write": "Filesystem Write",
    "dynamic_exec": "Dynamic Code Execution",
    "credential_access": "Credential Access",
    "state_mutation": "State Mutation (DB)",
}


# ── Data models ───────────────────────────────────────────────────────────

@dataclass
class RiskPrimitive:
    file: str
    line: int
    function: str
    category: str
    detail: str
    owner_module: str


@dataclass
class ClassInfo:
    name: str
    file: str
    line: int
    bases: List[str]
    methods: List[str]
    docstring: Optional[str] = None


@dataclass
class ComponentInfo:
    module_path: str
    component_type: str
    description: str
    classes: List[ClassInfo] = field(default_factory=list)
    risk_primitives: List[RiskPrimitive] = field(default_factory=list)
    imports_from: List[str] = field(default_factory=list)
    test_file: Optional[str] = None


@dataclass
class Inventory:
    version: str = "1.0.0"
    generated_at: str = ""
    checksum: str = ""
    components: List[ComponentInfo] = field(default_factory=list)
    call_graph_edges: List[Dict[str, str]] = field(default_factory=list)
    duplicates: List[Dict[str, Any]] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    unowned_paths: List[str] = field(default_factory=list)


# ── Component type classifier ─────────────────────────────────────────────

COMPONENT_TYPE_MAP = {
    "agents/": "agent",
    "core/orchestration/": "orchestration",
    "core/security/": "security",
    "core/tools/": "tool",
    "core/execution/": "executor",
    "core/decisions/": "policy_engine",
    "core/database/": "database",
    "core/memory/": "state_store",
    "core/knowledge/": "state_store",
    "core/network/": "network",
    "core/actuation/": "browser_driver",
    "core/workflows/": "browser_driver",
    "core/analysis/": "analysis_engine",
    "core/intelligence/": "analysis_engine",
    "core/coverage/": "coverage",
    "core/reporting/": "reporting",
    "core/evidence/": "evidence",
    "core/findings/": "findings",
    "core/exploitation/": "exploitation",
    "core/verification/": "verification",
    "core/discovery/": "discovery",
    "core/identity/": "identity",
    "core/domain/": "domain_model",
    "core/common/": "common",
    "core/observability/": "observability",
    "core/rag/": "rag",
    "core/llm/": "llm",
    "core/hypothesis/": "reasoning",
    "core/reasoning/": "reasoning",
    "core/fuzzing/": "fuzzing",
    "core/injection/": "injection",
    "core/replay/": "replay",
    "core/compliance/": "compliance",
    "core/convergence/": "convergence",
    "core/validation/": "validation",
    "core/scope/": "scope",
    "core/scoring/": "scoring",
    "core/learning/": "learning",
    "core/economics/": "economics",
    "core/scheduling/": "scheduling",
    "core/recovery/": "recovery",
    "core/error/": "error",
    "core/failure/": "failure",
    "core/defensive/": "defensive",
    "core/escalation/": "escalation",
    "core/cloud/": "cloud",
    "core/intel/": "intel",
    "core/skills/": "skills",
    "core/notifications/": "notifications",
    "core/monitoring/": "monitoring",
    "core/checkpointing/": "checkpointing",
    "core/prompts/": "prompts",
    "core/extraction/": "extraction",
    "core/authentication/": "authentication",
    "core/access_control/": "access_control",
    "core/attack_surface/": "attack_surface",
    "core/adaptation/": "adaptation",
    "core/utils/": "utility",
    "ui/": "ui",
    "scripts/": "script",
}


def classify_component(filepath: str) -> str:
    fp = filepath.replace("\\", "/")
    for prefix, ctype in COMPONENT_TYPE_MAP.items():
        if fp.startswith(prefix):
            return ctype
    return "other"


# ── AST analysis ──────────────────────────────────────────────────────────

def _get_enclosing_function(tree: ast.Module, target_line: int) -> str:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if hasattr(node, "end_lineno"):
                if node.lineno <= target_line <= (node.end_lineno or node.lineno + 100):
                    return node.name
            elif node.lineno <= target_line:
                return node.name
    return "<module>"


def _extract_classes(tree: ast.Module, filepath: str) -> List[ClassInfo]:
    classes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = []
            for b in node.bases:
                if isinstance(b, ast.Name):
                    bases.append(b.id)
                elif isinstance(b, ast.Attribute):
                    bases.append(ast.dump(b))
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            doc = ast.get_docstring(node)
            if doc:
                doc = doc.split("\n")[0][:120]
            classes.append(ClassInfo(
                name=node.name, file=filepath, line=node.lineno,
                bases=bases, methods=methods, docstring=doc,
            ))
    return classes


def _extract_imports(tree: ast.Module) -> List[str]:
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("core.") or alias.name.startswith("agents."):
                    imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("core.") or mod.startswith("agents."):
                imports.add(mod)
    return sorted(imports)


def _detect_risk_primitives(tree: ast.Module, source: str, filepath: str) -> List[RiskPrimitive]:
    primitives = []
    owner = filepath.replace("\\", "/").split("/")[0] if "/" in filepath.replace("\\", "/") else "root"

    def _check_call(node: ast.AST, patterns: dict, category: str):
        if isinstance(node, ast.Call):
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            for mod, funcs in patterns.items():
                if name in funcs:
                    enclosing = _get_enclosing_function(tree, node.lineno)
                    primitives.append(RiskPrimitive(
                        file=filepath, line=node.lineno,
                        function=enclosing, category=category,
                        detail=f"{name}()",
                        owner_module=owner,
                    ))
                    return

    for node in ast.walk(tree):
        _check_call(node, NETWORK_IO_PATTERNS, "network_io")
        _check_call(node, PROCESS_EXEC_PATTERNS, "process_exec")
        _check_call(node, BROWSER_PATTERNS, "browser_action")
        _check_call(node, FILESYSTEM_WRITE_PATTERNS, "filesystem_write")
        _check_call(node, DYNAMIC_EXEC_PATTERNS, "dynamic_exec")
        _check_call(node, CREDENTIAL_ACCESS_PATTERNS, "credential_access")

    # SQL/DB mutation detection via string literals
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value.upper()
            for kw in STATE_MUTATION_KEYWORDS:
                if kw in val and len(node.value) > 5:
                    enclosing = _get_enclosing_function(tree, node.lineno)
                    primitives.append(RiskPrimitive(
                        file=filepath, line=node.lineno,
                        function=enclosing, category="state_mutation",
                        detail=f"SQL: {kw}",
                        owner_module=owner,
                    ))
                    break

    return primitives


def _extract_call_edges(tree: ast.Module, filepath: str) -> List[Dict[str, str]]:
    edges = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            caller = f"{filepath}:{node.name}"
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee = ""
                    if isinstance(child.func, ast.Attribute):
                        callee = child.func.attr
                    elif isinstance(child.func, ast.Name):
                        callee = child.func.id
                    if callee and callee not in ("str", "int", "float", "bool", "list", "dict", "set", "len", "range", "isinstance", "getattr", "setattr", "hasattr", "super", "print", "type", "sorted", "enumerate", "zip", "map", "filter", "any", "all", "min", "max", "sum", "abs", "round", "format"):
                        edges.append({"caller": caller, "callee": callee, "line": child.lineno})
    return edges


# ── Duplicate detection ───────────────────────────────────────────────────

RESPONSIBILITY_GROUPS = {
    "authorization": [
        "core/security/authorization.py",
        "core/security/authorization_service.py",
        "agents/authorization.py",
        "core/decisions/policy_engine.py",
        "core/security/policy_engine.py",
    ],
    "coverage_tracking": [
        "core/coverage/coverage_tracker.py",
        "core/coverage/coverage_engine.py",
        "core/exploitation/coverage_tracker.py",
        "core/orchestration/endpoint_coverage.py",
    ],
    "hypothesis_engine": [
        "core/hypothesis/hypothesis_engine.py",
        "core/reasoning/hypothesis_engine.py",
        "core/coverage/hypothesis_engine.py",
    ],
    "state_store": [
        "core/memory/shared_context.py",
        "core/memory/context.py",
        "core/intelligence/application_model.py",
        "core/knowledge/knowledge_graph.py",
    ],
    "scheduling": [
        "core/orchestration/scheduler.py",
        "core/orchestration/legacy_scheduler.py",
        "core/scheduling/experiment_scheduler.py",
    ],
    "evidence_findings": [
        "core/evidence/evidence.py",
        "core/evidence/evidence_chain.py",
        "core/findings/finding.py",
        "core/findings/finding_store.py",
        "core/domain/finding.py",
        "core/domain/evidence.py",
    ],
    "convergence": [
        "core/convergence/convergence_engine.py",
        "core/coverage/convergence_engine.py",
    ],
    "error_handling": [
        "core/error/error_classifier.py",
        "core/common/error_classifier.py",
    ],
}


def _find_duplicates() -> List[Dict[str, Any]]:
    dupes = []
    for group_name, files in RESPONSIBILITY_GROUPS.items():
        existing = [f for f in files if (PROJECT_ROOT / f).exists()]
        if len(existing) > 1:
            dupes.append({
                "responsibility": group_name,
                "competing_files": existing,
                "count": len(existing),
            })
    return dupes


# ── Test mapping ──────────────────────────────────────────────────────────

def _find_test_for(module_path: str) -> Optional[str]:
    tests_dir = PROJECT_ROOT / "tests"
    if not tests_dir.exists():
        return None
    module_name = Path(module_path).stem
    for test_file in tests_dir.rglob("test_*.py"):
        rel = test_file.relative_to(PROJECT_ROOT).as_posix()
        if module_name in rel:
            return rel
    return None


# ── Main inventory builder ────────────────────────────────────────────────

def build_inventory() -> Inventory:
    from datetime import datetime, timezone
    inv = Inventory(generated_at=datetime.now(timezone.utc).isoformat())

    all_files: List[str] = []
    for d in SOURCE_DIRS:
        src = PROJECT_ROOT / d
        if src.exists():
            for pyfile in src.rglob("*.py"):
                rel = pyfile.relative_to(PROJECT_ROOT).as_posix()
                if "__pycache__" in rel:
                    continue
                all_files.append(rel)
    for f in SOURCE_FILES:
        if (PROJECT_ROOT / f).exists():
            all_files.append(f)

    risk_counts: Dict[str, int] = defaultdict(int)
    all_edges: List[Dict[str, str]] = []

    for filepath in sorted(all_files):
        fullpath = PROJECT_ROOT / filepath
        try:
            source = fullpath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=filepath)
        except (SyntaxError, UnicodeDecodeError):
            continue

        comp_type = classify_component(filepath)
        classes = _extract_classes(tree, filepath)
        imports = _extract_imports(tree)
        risks = _detect_risk_primitives(tree, source, filepath)
        edges = _extract_call_edges(tree, filepath)
        test_file = _find_test_for(filepath)

        doc = ast.get_docstring(tree)
        desc = doc.split("\n")[0][:120] if doc else ""

        for r in risks:
            risk_counts[r.category] += 1

        all_edges.extend(edges)

        inv.components.append(ComponentInfo(
            module_path=filepath,
            component_type=comp_type,
            description=desc,
            classes=classes,
            risk_primitives=risks,
            imports_from=imports,
            test_file=test_file,
        ))

    inv.call_graph_edges = all_edges
    inv.duplicates = _find_duplicates()
    inv.risk_summary = dict(risk_counts)

    # Find unowned risk primitives (no test coverage)
    for comp in inv.components:
        if comp.risk_primitives and not comp.test_file:
            for rp in comp.risk_primitives:
                inv.unowned_paths.append(f"{rp.file}:{rp.line} ({rp.category}: {rp.detail})")

    # Compute checksum of source files for staleness detection
    h = hashlib.sha256()
    for filepath in sorted(all_files):
        fullpath = PROJECT_ROOT / filepath
        try:
            h.update(fullpath.read_bytes())
        except Exception:
            pass
    inv.checksum = h.hexdigest()[:16]

    return inv


# ── Serialization ─────────────────────────────────────────────────────────

def _dataclass_to_dict(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _dataclass_to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj


def emit_json(inv: Inventory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _dataclass_to_dict(inv)
    # Trim call_graph_edges for readability (keep in JSON, summarize in MD)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def emit_markdown(inv: Inventory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Architecture Inventory",
        "",
        f"**Generated**: {inv.generated_at}  ",
        f"**Source checksum**: `{inv.checksum}`  ",
        f"**Components**: {len(inv.components)}  ",
        "",
        "## Risk Summary",
        "",
        "| Category | Count |",
        "|----------|-------|",
    ]
    for cat, count in sorted(inv.risk_summary.items(), key=lambda x: -x[1]):
        lines.append(f"| {RISK_CATEGORIES.get(cat, cat)} | {count} |")

    lines += ["", "## Duplicate/Competing Implementations", ""]
    if inv.duplicates:
        for d in inv.duplicates:
            lines.append(f"### {d['responsibility']} ({d['count']} files)")
            for f in d["competing_files"]:
                lines.append(f"- `{f}`")
            lines.append("")
    else:
        lines.append("None detected.")

    lines += ["", "## Components by Type", ""]
    by_type: Dict[str, List[ComponentInfo]] = defaultdict(list)
    for comp in inv.components:
        by_type[comp.component_type].append(comp)

    for ctype in sorted(by_type):
        comps = by_type[ctype]
        lines.append(f"### {ctype} ({len(comps)} modules)")
        lines.append("")
        lines.append("| Module | Classes | Risk Primitives | Test |")
        lines.append("|--------|---------|-----------------|------|")
        for comp in sorted(comps, key=lambda c: c.module_path):
            cls_names = ", ".join(c.name for c in comp.classes[:3])
            if len(comp.classes) > 3:
                cls_names += f" +{len(comp.classes)-3}"
            risk_count = len(comp.risk_primitives)
            test = f"`{comp.test_file}`" if comp.test_file else "-"
            lines.append(f"| `{comp.module_path}` | {cls_names} | {risk_count} | {test} |")
        lines.append("")

    if inv.unowned_paths:
        lines += ["## Unowned High-Risk Paths (no test coverage)", ""]
        shown = inv.unowned_paths[:50]
        for p in shown:
            lines.append(f"- `{p}`")
        if len(inv.unowned_paths) > 50:
            lines.append(f"- ... and {len(inv.unowned_paths) - 50} more")
        lines.append("")

    lines += [
        "## Call Graph",
        "",
        f"Total edges: {len(inv.call_graph_edges)}  ",
        "Full graph available in `architecture_inventory.json`.",
        "",
        "---",
        "*Auto-generated by `scripts/inventory_generator.py`. Regenerate in CI.*",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate architecture inventory")
    parser.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    parser.add_argument("--check", action="store_true",
                        help="CI mode: exit 1 if inventory files are stale")
    parser.add_argument("--output-dir", default="docs", help="Output directory")
    args = parser.parse_args()

    inv = build_inventory()

    out_dir = PROJECT_ROOT / args.output_dir
    json_path = out_dir / "architecture_inventory.json"
    md_path = out_dir / "architecture_inventory.md"

    if args.check:
        if not json_path.exists():
            print("FAIL: architecture_inventory.json not found. Run: python scripts/inventory_generator.py")
            sys.exit(1)
        existing = json.loads(json_path.read_text(encoding="utf-8"))
        if existing.get("checksum") != inv.checksum:
            print(f"FAIL: inventory stale. Expected checksum {inv.checksum}, got {existing.get('checksum')}")
            print("Run: python scripts/inventory_generator.py")
            sys.exit(1)
        print(f"OK: inventory up-to-date (checksum {inv.checksum})")
        sys.exit(0)

    if args.format in ("json", "both"):
        emit_json(inv, json_path)
        print(f"Wrote {json_path}")
    if args.format in ("markdown", "both"):
        emit_markdown(inv, md_path)
        print(f"Wrote {md_path}")

    print(f"\nComponents: {len(inv.components)}")
    print(f"Risk primitives: {sum(inv.risk_summary.values())}")
    print(f"Call graph edges: {len(inv.call_graph_edges)}")
    print(f"Duplicates: {len(inv.duplicates)}")
    print(f"Unowned paths: {len(inv.unowned_paths)}")


if __name__ == "__main__":
    main()
