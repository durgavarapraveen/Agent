from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict


@dataclass
class Evidence:
    tool_name: str
    command: str
    stdout: str = ""
    stderr: str = ""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict:
        return {
            "evidence_id": self.evidence_id,
            "tool_name": self.tool_name,
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timestamp": self.timestamp.isoformat(),
        }

    def is_credible(self) -> bool:
        if not self.stdout and not self.stderr:
            return False
        if self.tool_name in ("", "unknown"):
            return False
        return True
