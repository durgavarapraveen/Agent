from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / "skills"


class Skill:
    __slots__ = ("name", "category", "description", "attack_types",
                 "severity_range", "content", "path")

    def __init__(self, name: str, category: str, description: str,
                 attack_types: List[str], severity_range: List[str],
                 content: str, path: str):
        self.name = name
        self.category = category
        self.description = description
        self.attack_types = attack_types
        self.severity_range = severity_range
        self.content = content
        self.path = path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "attack_types": self.attack_types,
            "severity_range": self.severity_range,
        }


class SkillLoader:

    def __init__(self, skill_dirs: Optional[List[str]] = None):
        self._dirs: List[Path] = []
        if skill_dirs:
            for d in skill_dirs:
                p = Path(d)
                if p.is_dir():
                    self._dirs.append(p)
        if SKILLS_DIR.is_dir():
            self._dirs.append(SKILLS_DIR)
        self._cache: Dict[str, Skill] = {}
        self._index_built = False

    def _build_index(self) -> None:
        if self._index_built:
            return
        for d in self._dirs:
            for md_file in sorted(d.glob("*.md")):
                try:
                    skill = self._parse_file(md_file)
                    if skill and skill.name not in self._cache:
                        self._cache[skill.name] = skill
                except Exception as e:
                    logger.warning(f"Failed to parse skill {md_file}: {e}")
        self._index_built = True
        logger.info(f"[SkillLoader] Indexed {len(self._cache)} skills from {len(self._dirs)} directories")

    @staticmethod
    def _parse_file(path: Path) -> Optional[Skill]:
        text = path.read_text(encoding="utf-8", errors="replace")
        if not text.startswith("---"):
            return None
        parts = text.split("---", 2)
        if len(parts) < 3:
            return None
        meta = yaml.safe_load(parts[1])
        if not isinstance(meta, dict):
            return None
        body = parts[2].strip()
        return Skill(
            name=meta.get("name", path.stem),
            category=meta.get("category", "general"),
            description=meta.get("description", ""),
            attack_types=meta.get("attack_types", []),
            severity_range=meta.get("severity_range", []),
            content=body,
            path=str(path),
        )

    def load_all(self) -> List[Skill]:
        self._build_index()
        return list(self._cache.values())

    def load_by_name(self, name: str) -> Optional[Skill]:
        self._build_index()
        return self._cache.get(name)

    def load_by_category(self, category: str) -> List[Skill]:
        self._build_index()
        return [s for s in self._cache.values() if s.category == category]

    def load_for_attack_type(self, attack_type: str) -> List[Skill]:
        self._build_index()
        at_lower = attack_type.lower().replace("-", "_").replace(" ", "_")
        results = []
        for s in self._cache.values():
            skill_types = [t.lower().replace("-", "_").replace(" ", "_") for t in s.attack_types]
            if at_lower in skill_types:
                results.append(s)
        if not results:
            for s in self._cache.values():
                if at_lower in s.name.lower().replace("-", "_") or at_lower in s.description.lower():
                    results.append(s)
        return results

    def format_for_prompt(self, skills: List[Skill], max_chars: int = 8000) -> str:
        if not skills:
            return ""
        parts = ["## Testing Methodology (from loaded skills)\n"]
        budget = max_chars - len(parts[0])
        for s in skills:
            header = f"\n### Skill: {s.name} ({s.category})\n{s.description}\n\n"
            if len(header) + len(s.content) > budget:
                truncated = s.content[:budget - len(header) - 20] + "\n[...truncated]"
                parts.append(header + truncated)
                break
            parts.append(header + s.content)
            budget -= len(header) + len(s.content)
        return "\n".join(parts)

    def register_dir(self, path: str) -> None:
        p = Path(path)
        if p.is_dir():
            self._dirs.insert(0, p)
            self._index_built = False
            self._cache.clear()
