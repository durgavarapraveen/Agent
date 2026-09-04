"""
Adversarial finding verification (Feature #4: Planner-Worker-Critic loop).

Provides a semantic second opinion on candidate findings to autonomously
suppress false positives, complementing the mechanical RetestEngine.
"""

from core.verification.critic_agent import CriticAgent, CriticVerdict, Verdict

__all__ = ["CriticAgent", "CriticVerdict", "Verdict"]
