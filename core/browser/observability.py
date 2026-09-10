
import logging
import asyncio
import json
import time
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class BrowserObservability:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.observations = []

    def capture_network_event(self, event_type: str, url: str, details: Dict[str, Any]):
        """Capture navigation, requests, responses, redirects."""
        # Normalize into the evidence model
        observation = {
            "session_id": self.session_id,
            "type": "network",
            "event_type": event_type,
            "url": url,
            "details": details,
            "timestamp": time.time(),
            "untrusted": True  # Tagged as untrusted target content
        }
        self.observations.append(observation)
        logger.debug(f"Captured network event for {url}")

    def capture_dom_mutation(self, mutation_type: str, element_data: Dict[str, Any]):
        """Capture DOM changes, storage mutations."""
        observation = {
            "session_id": self.session_id,
            "type": "dom",
            "mutation_type": mutation_type,
            "data": element_data,
            "timestamp": time.time(),
            "untrusted": True
        }
        self.observations.append(observation)

    def capture_console_event(self, level: str, message: str, source: str):
        """Capture console events, service worker activity."""
        observation = {
            "session_id": self.session_id,
            "type": "console",
            "level": level,
            "message": message[:1000],  # Bound large traces
            "source": source,
            "timestamp": time.time(),
            "untrusted": True
        }
        self.observations.append(observation)

    def get_evidence(self) -> List[Dict[str, Any]]:
        """Return normalized observation data as evidence."""
        return self.observations

    def clear(self):
        """Clear the current buffer (bounded tracing)."""
        self.observations = []
