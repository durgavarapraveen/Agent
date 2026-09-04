from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type


@dataclass
class CapabilityDefinition:
    name: str
    executor_class: Type
    input_schema: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    description: str = ""


class CapabilityRegistry:

    def __init__(self) -> None:
        self._capabilities: Dict[str, CapabilityDefinition] = {}

    def register(self, definition: CapabilityDefinition) -> None:
        self._capabilities[definition.name] = definition

    def resolve(self, capability_name: str) -> Optional[Type]:
        defn = self._capabilities.get(capability_name)
        return defn.executor_class if defn else None

    def exists(self, capability_name: str) -> bool:
        return capability_name in self._capabilities

    def list_capabilities(self) -> List[str]:
        return list(self._capabilities.keys())

    def get_definition(self, capability_name: str) -> Optional[CapabilityDefinition]:
        return self._capabilities.get(capability_name)
