from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class SecretState(str, Enum):
    ACTIVE = "active"
    ROTATING = "rotating"
    EXPIRED = "expired"
    REVOKED = "revoked"
    HELD = "held"  # legal hold — cannot be deleted


@dataclass
class SecretLifecycleRule:
    name: str
    max_age_seconds: float = 3600.0
    auto_rotate: bool = False
    rotate_interval_seconds: float = 86400.0
    revoke_on_leak: bool = True
    legal_hold: bool = False
    tenant_scoped: bool = True
    notify_on_expiry: bool = True


@dataclass
class ManagedSecret:
    secret_ref: str
    rule: SecretLifecycleRule
    state: SecretState = SecretState.ACTIVE
    created_at: float = field(default_factory=time.monotonic)
    last_rotated_at: float = 0.0
    tenant_id: str = ""


class SecretLifecycleManager:
    """Formal lifecycle policy management for secrets.

    Delegates to SecretVault for storage/retrieval but adds:
    - explicit lifecycle rules (expiry, rotation, revocation)
    - legal hold hooks (prevents deletion while held)
    - tenant-scoped secret ownership
    - leak-triggered revocation
    """

    def __init__(self) -> None:
        self._managed: Dict[str, ManagedSecret] = {}
        self._rules: Dict[str, SecretLifecycleRule] = {}
        self._on_expiry_callbacks: List[Callable[[ManagedSecret], None]] = []

    def register_rule(self, rule: SecretLifecycleRule) -> None:
        self._rules[rule.name] = rule

    def track(self, secret_ref: str, rule_name: str, tenant_id: str = "") -> ManagedSecret:
        rule = self._rules.get(rule_name)
        if not rule:
            raise ValueError(f"Unknown lifecycle rule: {rule_name}")

        managed = ManagedSecret(
            secret_ref=secret_ref,
            rule=rule,
            tenant_id=tenant_id,
        )
        self._managed[secret_ref] = managed
        logger.info("[SecretLifecycle] Tracking secret=%s rule=%s tenant=%s", secret_ref, rule_name, tenant_id)
        return managed

    def check_expiry(self, secret_ref: str) -> bool:
        managed = self._managed.get(secret_ref)
        if not managed:
            return False

        age = time.monotonic() - managed.created_at
        if age > managed.rule.max_age_seconds and managed.state == SecretState.ACTIVE:
            managed.state = SecretState.EXPIRED
            logger.warning("[SecretLifecycle] Secret expired: %s", secret_ref)
            for cb in self._on_expiry_callbacks:
                try:
                    cb(managed)
                except Exception as e:
                    logger.error("[SecretLifecycle] Expiry callback error: %s", e)
            return True
        return False

    def set_legal_hold(self, secret_ref: str) -> bool:
        managed = self._managed.get(secret_ref)
        if not managed:
            return False
        managed.state = SecretState.HELD
        managed.rule.legal_hold = True
        logger.info("[SecretLifecycle] Legal hold set on secret=%s", secret_ref)
        return True

    def release_legal_hold(self, secret_ref: str) -> bool:
        managed = self._managed.get(secret_ref)
        if not managed:
            return False
        if managed.state == SecretState.HELD:
            managed.state = SecretState.ACTIVE
            managed.rule.legal_hold = False
            logger.info("[SecretLifecycle] Legal hold released on secret=%s", secret_ref)
            return True
        return False

    def revoke(self, secret_ref: str, reason: str = "") -> bool:
        managed = self._managed.get(secret_ref)
        if not managed:
            return False
        if managed.rule.legal_hold:
            logger.warning("[SecretLifecycle] Cannot revoke secret=%s — under legal hold", secret_ref)
            return False
        managed.state = SecretState.REVOKED
        logger.warning("[SecretLifecycle] Secret revoked: %s reason=%s", secret_ref, reason)
        return True

    def delete(self, secret_ref: str) -> bool:
        managed = self._managed.get(secret_ref)
        if not managed:
            return False
        if managed.rule.legal_hold:
            logger.warning("[SecretLifecycle] Cannot delete secret=%s — under legal hold", secret_ref)
            return False
        del self._managed[secret_ref]
        logger.info("[SecretLifecycle] Secret deleted: %s", secret_ref)
        return True

    def get_tenant_secrets(self, tenant_id: str) -> List[ManagedSecret]:
        return [m for m in self._managed.values() if m.tenant_id == tenant_id]

    def on_expiry(self, callback: Callable[[ManagedSecret], None]) -> None:
        self._on_expiry_callbacks.append(callback)

    def enforce_all(self) -> Dict[str, int]:
        """Run lifecycle enforcement across all tracked secrets."""
        expired = 0
        needs_rotation = 0
        now = time.monotonic()

        for ref, managed in list(self._managed.items()):
            if self.check_expiry(ref):
                expired += 1

            if (managed.rule.auto_rotate and managed.state == SecretState.ACTIVE
                    and managed.last_rotated_at > 0
                    and (now - managed.last_rotated_at) > managed.rule.rotate_interval_seconds):
                needs_rotation += 1
                managed.state = SecretState.ROTATING
                logger.info("[SecretLifecycle] Secret needs rotation: %s", ref)

        return {"expired": expired, "needs_rotation": needs_rotation}
