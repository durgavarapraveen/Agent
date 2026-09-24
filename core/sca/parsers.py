"""Dependency manifest / lockfile parsers (spec §5, §21).

Each parser turns a manifest's *content* into a list of ``Package`` records with
an OSV-aligned ecosystem name (PyPI/npm/Go/crates.io/Maven). Lockfiles yield
exact pinned versions (the reliable input for vuln matching); loose manifests
(package.json, requirements ranges) yield a best-effort cleaned version.

All parsing is defensive: a malformed file yields [] rather than raising, and
file content is UNTRUSTED data (spec §31) — never executed, only parsed.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

try:  # py311+
    import tomllib  # type: ignore
except Exception:  # pragma: no cover
    tomllib = None


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str
    path: str = ""

    def key(self):
        return (self.ecosystem, self.name.lower(), self.version)


def _clean_version(spec: str) -> str:
    """Strip range operators from a loose spec → a plausible concrete version."""
    if not spec:
        return ""
    s = spec.strip().lstrip("^~=><! ").strip()
    m = re.match(r"[vV]?(\d+(?:\.\d+)*(?:[-.][0-9A-Za-z.]+)?)", s)
    return m.group(1) if m else ""


# ── PyPI ──────────────────────────────────────────────────────────────
def parse_requirements(content: str, path: str = "requirements.txt") -> List[Package]:
    out: List[Package] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()  # drop env markers
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*==\s*([^\s,]+)", line)
        if m:
            out.append(Package(m.group(1), m.group(3), "PyPI", path))
    return out


def parse_pipfile_lock(content: str, path: str = "Pipfile.lock") -> List[Package]:
    out: List[Package] = []
    try:
        doc = json.loads(content)
    except json.JSONDecodeError:
        return out
    for section in ("default", "develop"):
        for name, meta in (doc.get(section, {}) or {}).items():
            ver = _clean_version(str((meta or {}).get("version", "")))
            if ver:
                out.append(Package(name, ver, "PyPI", path))
    return out


def parse_poetry_lock(content: str, path: str = "poetry.lock") -> List[Package]:
    return _parse_toml_packages(content, "PyPI", path)


# ── npm ───────────────────────────────────────────────────────────────
def parse_package_lock(content: str, path: str = "package-lock.json") -> List[Package]:
    out: List[Package] = []
    try:
        doc = json.loads(content)
    except json.JSONDecodeError:
        return out

    # lockfile v2/v3: "packages": {"node_modules/foo": {"version": ...}}
    for pkgpath, meta in (doc.get("packages", {}) or {}).items():
        if not pkgpath:
            continue  # root project
        name = pkgpath.split("node_modules/")[-1]
        ver = str((meta or {}).get("version", ""))
        if name and ver:
            out.append(Package(name, ver, "npm", path))

    # lockfile v1: nested "dependencies"
    def _walk(deps: Dict):
        for name, meta in (deps or {}).items():
            ver = str((meta or {}).get("version", ""))
            if name and ver:
                out.append(Package(name, ver, "npm", path))
            _walk((meta or {}).get("dependencies", {}))

    if "packages" not in doc:
        _walk(doc.get("dependencies", {}))
    return _dedupe(out)


def parse_package_json(content: str, path: str = "package.json") -> List[Package]:
    out: List[Package] = []
    try:
        doc = json.loads(content)
    except json.JSONDecodeError:
        return out
    for section in ("dependencies", "devDependencies"):
        for name, spec in (doc.get(section, {}) or {}).items():
            ver = _clean_version(str(spec))
            if ver:
                out.append(Package(name, ver, "npm", path))
    return out


# ── Go ────────────────────────────────────────────────────────────────
def parse_go_mod(content: str, path: str = "go.mod") -> List[Package]:
    out: List[Package] = []
    in_block = False
    for raw in content.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([^\s]+)\s+(v[0-9][^\s]*)", line)
        if m and (in_block or line.startswith("require ")):
            out.append(Package(m.group(1), m.group(2).lstrip("v"), "Go", path))
    return out


# ── Rust ──────────────────────────────────────────────────────────────
def parse_cargo_lock(content: str, path: str = "Cargo.lock") -> List[Package]:
    return _parse_toml_packages(content, "crates.io", path)


# ── Maven ─────────────────────────────────────────────────────────────
def parse_pom_xml(content: str, path: str = "pom.xml") -> List[Package]:
    out: List[Package] = []
    for m in re.finditer(
            r"<dependency>(.*?)</dependency>", content, re.DOTALL | re.IGNORECASE):
        block = m.group(1)
        gid = _xml_tag(block, "groupId")
        aid = _xml_tag(block, "artifactId")
        ver = _xml_tag(block, "version")
        if gid and aid and ver and "${" not in ver:
            out.append(Package(f"{gid}:{aid}", ver, "Maven", path))
    return out


# ── helpers ───────────────────────────────────────────────────────────
def _xml_tag(block: str, tag: str) -> str:
    m = re.search(rf"<{tag}>\s*([^<]+?)\s*</{tag}>", block, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _parse_toml_packages(content: str, ecosystem: str, path: str) -> List[Package]:
    """Both poetry.lock and Cargo.lock use [[package]] name=/version= tables."""
    out: List[Package] = []
    if tomllib is not None:
        try:
            doc = tomllib.loads(content)
            for p in doc.get("package", []) or []:
                name, ver = p.get("name"), p.get("version")
                if name and ver:
                    out.append(Package(name, str(ver), ecosystem, path))
            return out
        except Exception as e:
            logger.debug("[sca] tomllib parse failed (%s), regex fallback: %s", path, e)
    # Regex fallback for environments without tomllib.
    name = None
    for raw in content.splitlines():
        line = raw.strip()
        nm = re.match(r'name\s*=\s*"([^"]+)"', line)
        vm = re.match(r'version\s*=\s*"([^"]+)"', line)
        if nm:
            name = nm.group(1)
        elif vm and name:
            out.append(Package(name, vm.group(1), ecosystem, path))
            name = None
    return out


def _dedupe(pkgs: List[Package]) -> List[Package]:
    seen, out = set(), []
    for p in pkgs:
        if p.key() not in seen:
            seen.add(p.key())
            out.append(p)
    return out


# filename (basename) → parser
_PARSERS: List[tuple] = [
    ("requirements.txt", parse_requirements),
    ("pipfile.lock", parse_pipfile_lock),
    ("poetry.lock", parse_poetry_lock),
    ("package-lock.json", parse_package_lock),
    ("package.json", parse_package_json),
    ("go.mod", parse_go_mod),
    ("cargo.lock", parse_cargo_lock),
    ("pom.xml", parse_pom_xml),
]


def parser_for(filename: str) -> Optional[Callable[[str, str], List[Package]]]:
    base = filename.replace("\\", "/").split("/")[-1].lower()
    for name, fn in _PARSERS:
        if base == name:
            return fn
    # requirements-*.txt variants
    if base.startswith("requirements") and base.endswith(".txt"):
        return parse_requirements
    return None


def parse_files(files: Dict[str, str]) -> List[Package]:
    """Parse a {path: content} map; unknown files are ignored."""
    out: List[Package] = []
    for path, content in (files or {}).items():
        fn = parser_for(path)
        if not fn:
            continue
        try:
            out.extend(fn(content or "", path))
        except Exception as e:
            logger.warning("[sca] parse %s failed: %s", path, e)
    return _dedupe(out)
