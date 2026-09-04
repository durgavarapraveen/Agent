"""
Actuation layer — target-agnostic "hands" for the autonomous agent.

Reusable across ANY authorized target (localhost, deployed, or remote URLs):
  - Actuators       : authenticated HTTP, JWT decode/forge, encode/decode, upload
  - BrowserActuator : headless Chromium (Playwright in the Kali container) for
                      DOM/JS/SPA/client-side actions
  - ObjectiveAgentLoop : an oracle/evidence-driven ReAct loop that plans, acts,
                      observes, and reports verified findings

Every action is scope-validated so the agent only touches authorized hosts.
"""

from core.actuation.actuators import Actuators, ACTUATOR_TOOLS
from core.actuation.browser_actuator import BrowserActuator, BROWSER_TOOL
from core.actuation.agent_loop import ObjectiveAgentLoop

__all__ = [
    "Actuators", "ACTUATOR_TOOLS",
    "BrowserActuator", "BROWSER_TOOL",
    "ObjectiveAgentLoop",
]
