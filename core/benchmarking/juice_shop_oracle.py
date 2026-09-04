"""
JuiceShopOracle — ground-truth solved/unsolved status via Juice Shop's own API.

OWASP Juice Shop exposes GET /api/Challenges/ listing every challenge with a
`solved` boolean, `name`, `category`, `difficulty`, `description` and `hint`.
This is the authoritative oracle: instead of guessing whether an exploit worked,
the solver re-reads this endpoint and trusts the app itself.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class Challenge:
    key: str
    name: str
    category: str
    difficulty: int
    solved: bool
    description: str = ""
    hint: str = ""
    id: Optional[int] = None

    @classmethod
    def from_api(cls, d: Dict[str, Any]) -> "Challenge":
        return cls(
            key=str(d.get("key") or d.get("name") or ""),
            name=str(d.get("name") or ""),
            category=str(d.get("category") or ""),
            difficulty=int(d.get("difficulty") or 0),
            solved=bool(d.get("solved")),
            description=str(d.get("description") or ""),
            hint=str(d.get("hint") or ""),
            id=d.get("id"),
        )


class JuiceShopOracle:
    def __init__(self, base_url: str, timeout: int = 15,
                 auth_headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.auth_headers = auth_headers or {}

    async def fetch(self) -> List[Challenge]:
        """Return all challenges with current solved status (empty on failure)."""
        url = f"{self.base_url}/api/Challenges/"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                r = await client.get(url, headers=self.auth_headers)
                if r.status_code != 200:
                    logger.warning(f"[JuiceOracle] /api/Challenges returned {r.status_code}")
                    return []
                data = r.json().get("data", [])
                return [Challenge.from_api(c) for c in data]
        except Exception as e:
            logger.warning(f"[JuiceOracle] fetch failed ({url}): {e}")
            return []

    async def is_reachable(self) -> bool:
        return bool(await self.fetch())

    @staticmethod
    def summarize(challenges: List[Challenge]) -> Dict[str, Any]:
        total = len(challenges)
        solved = [c for c in challenges if c.solved]
        by_cat: Dict[str, Dict[str, int]] = {}
        by_diff: Dict[int, Dict[str, int]] = {}
        for c in challenges:
            cat = by_cat.setdefault(c.category, {"solved": 0, "total": 0})
            cat["total"] += 1
            cat["solved"] += 1 if c.solved else 0
            dif = by_diff.setdefault(c.difficulty, {"solved": 0, "total": 0})
            dif["total"] += 1
            dif["solved"] += 1 if c.solved else 0
        return {
            "solved": len(solved),
            "total": total,
            "pct": round(100.0 * len(solved) / total, 1) if total else 0.0,
            "by_category": by_cat,
            "by_difficulty": dict(sorted(by_diff.items())),
            "solved_names": [c.name for c in solved],
        }
