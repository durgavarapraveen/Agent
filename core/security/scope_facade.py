from __future__ import annotations

import logging
import threading
from typing import List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ScopeAuthority:

    _instance: Optional["ScopeAuthority"] = None
    _init_lock = threading.RLock()

    @classmethod
    def get(cls) -> "ScopeAuthority":
        with cls._init_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        with cls._init_lock:
            cls._instance = None

    def __init__(self):
        self._lock = threading.RLock()
        self._scope_manager = None
        self._target_scope_validator = None
        self._legal_validator = None
        self._auto_scope: List[str] = []  # last-resort explicit allowlist

    # ── Back-end wiring ──────────────────────────────────────────────────
    def wire_scope_manager(self, mgr) -> None:
        with self._lock:
            self._scope_manager = mgr

    def wire_target_scope_validator(self, v) -> None:
        with self._lock:
            self._target_scope_validator = v

    def wire_legal_validator(self, lv) -> None:
        with self._lock:
            self._legal_validator = lv

    # ── Mutations propagate ──────────────────────────────────────────────
    def add_domain(self, domain: str) -> None:
        with self._lock:
            d = (domain or "").strip().lower()
            if not d:
                return
            if d not in self._auto_scope:
                self._auto_scope.append(d)
            # Best-effort push to each back-end.
            sm = self._scope_manager
            if sm is not None and hasattr(sm, "allowed_domains"):
                try:
                    sm.allowed_domains.add(d)
                except Exception as e:
                    raise SystemError(f"Policy enforcement failed: {e}") from e
            tsv = self._target_scope_validator
            if tsv is not None:
                try:
                    if hasattr(tsv, "authorized_scope"):
                        norm = tsv._normalize_target(d) if hasattr(tsv, "_normalize_target") else d
                        if norm not in tsv.authorized_scope:
                            tsv.authorized_scope.append(norm)
                except Exception as e:
                    raise SystemError(f"Policy enforcement failed: {e}") from e

    def add_ip(self, ip: str) -> None:
        with self._lock:
            i = (ip or "").strip()
            if not i:
                return
            sm = self._scope_manager
            if sm is not None and hasattr(sm, "allowed_ips"):
                try:
                    sm.allowed_ips.add(i)
                except Exception as e:
                    raise SystemError(f"Policy enforcement failed: {e}") from e
            tsv = self._target_scope_validator
            if tsv is not None and hasattr(tsv, "_authorized_ips"):
                try:
                    tsv._authorized_ips.add(i)
                except Exception as e:
                    raise SystemError(f"Policy enforcement failed: {e}") from e

    # ── The one question every caller asks ────────────────────────────────
    def is_authorized(self, target: str) -> bool:
        if not target:
            return False
        with self._lock:
            checks_run = 0
            if self._scope_manager is not None:
                checks_run += 1
                try:
                    ok = self._consult_scope_manager(target)
                except Exception as e:
                    logger.warning("ScopeAuthority: ScopeManager raised %s; failing closed", e)
                    return False
                if not ok:
                    return False
            if self._target_scope_validator is not None:
                checks_run += 1
                try:
                    self._target_scope_validator.validate(target)
                    ok = True  # validate() raises on denial, returns None on success
                except Exception as e:
                    logger.warning("ScopeAuthority: TargetScopeValidator raised %s; failing closed", e)
                    return False
                if not ok:
                    return False
            if self._legal_validator is not None:
                checks_run += 1
                try:
                    ok = self._consult_legal(target)
                except Exception as e:
                    logger.warning("ScopeAuthority: LegalValidator raised %s; failing closed", e)
                    return False
                if not ok:
                    return False
            if checks_run == 0:
                # Nothing wired — permit only exact matches against the auto
                # allowlist, if any. Otherwise fail closed.
                if not self._auto_scope:
                    return False
                host = self._extract_host(target)
                return any(host == d or host.endswith("." + d) for d in self._auto_scope)
            return True

    def enforcement_status(self) -> dict:
        with self._lock:
            return {
                "scope_manager": self._scope_manager is not None,
                "target_scope_validator": self._target_scope_validator is not None,
                "legal_validator": self._legal_validator is not None,
                "auto_scope_size": len(self._auto_scope),
            }

    # ── Helpers ──────────────────────────────────────────────────────────
    def _consult_scope_manager(self, target: str) -> bool:
        sm = self._scope_manager
        if hasattr(sm, "validate_url"):
            candidate = target if "://" in target else "http://" + target
            return bool(sm.validate_url(candidate))
        # Unknown interface — fail-closed per platform contract.
        logger.warning("ScopeAuthority: ScopeManager has no validate_url; failing closed")
        return False

    def _consult_legal(self, target: str) -> bool:
        lv = self._legal_validator
        if hasattr(lv, "is_target_authorized"):
            return bool(lv.is_target_authorized(target))
        if hasattr(lv, "validate"):
            return bool(lv.validate(target))
        # Unknown interface — fail-closed per platform contract.
        logger.warning("ScopeAuthority: LegalValidator has unknown interface; failing closed")
        return False

    @staticmethod
    def _extract_host(target: str) -> str:
        try:
            candidate = target if "://" in target else "http://" + target
            parsed = urlparse(candidate)
            return (parsed.hostname or "").strip().lower().rstrip(".")
        except Exception:
            return (target or "").strip().lower()


def get_scope_authority() -> ScopeAuthority:
    return ScopeAuthority.get()
