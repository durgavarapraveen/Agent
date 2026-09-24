"""Engagement aggregate — fail-closed authorization tests (spec §1, §2)."""
from datetime import datetime, timedelta

import pytest

from core.domain.engagement import Engagement, EngagementStatus


def _active(**kw) -> Engagement:
    base = dict(
        name="e1",
        allowed_domains=["example.com"],
        status=EngagementStatus.ACTIVE,
    )
    base.update(kw)
    return Engagement(**base)


def test_in_scope_target_authorized():
    eng = _active()
    assert eng.is_target_authorized("https://app.example.com/login") is True
    ok, reason = eng.authorize("https://app.example.com/login", "scan")
    assert ok and reason == "authorized"


def test_out_of_scope_target_denied():
    eng = _active()
    assert eng.is_target_authorized("https://evil.com/") is False
    ok, reason = eng.authorize("https://evil.com/", "scan")
    assert not ok and reason == "target_not_authorized"


def test_excluded_target_wins_over_allow():
    eng = _active(excluded_targets=["admin.example.com"])
    # host is in allowed_domains but explicitly excluded → denied.
    assert eng.is_target_authorized("https://admin.example.com/panel") is False


def test_exact_authorized_target_allowed_without_domain():
    eng = _active(allowed_domains=[], authorized_targets=["https://only.this/x"])
    assert eng.is_target_authorized("https://only.this/x") is True
    assert eng.is_target_authorized("https://only.this/y") is False


def test_forbidden_operation_denied():
    eng = _active(forbidden_operations=["destroy_data"])
    ok, reason = eng.authorize("https://app.example.com/", "destroy_data")
    assert not ok and reason == "operation_not_authorized"


def test_operation_allowlist_denies_unlisted():
    eng = _active(allowed_operations=["scan", "read"])
    assert eng.is_operation_authorized("scan") is True
    assert eng.is_operation_authorized("write") is False


def test_time_window_before_start_denied():
    future = datetime.utcnow() + timedelta(hours=1)
    eng = _active(start_time=future)
    ok, reason = eng.authorize("https://app.example.com/", "scan")
    assert not ok and reason == "time_window_or_status_invalid"


def test_time_window_after_end_denied():
    past = datetime.utcnow() - timedelta(hours=1)
    eng = _active(end_time=past)
    assert eng.is_time_window_valid() is False


def test_draft_engagement_denies_everything():
    eng = _active(status=EngagementStatus.DRAFT)
    ok, reason = eng.authorize("https://app.example.com/", "scan")
    assert not ok and reason == "time_window_or_status_invalid"


def test_empty_or_malformed_target_fails_closed():
    eng = _active()
    assert eng.is_target_authorized("") is False
    assert eng.is_target_authorized("::::not a url") is False


def test_scope_manager_roundtrip_reuses_scope_engine():
    eng = _active(allowed_ips=["10.0.0.0/24"])
    sm = eng.to_scope_manager()
    assert sm.validate_url("http://10.0.0.5/") is True
    assert sm.validate_url("http://10.0.1.5/") is False


def test_to_dict_from_dict_roundtrip_preserves_authorization():
    eng = _active(excluded_targets=["x.example.com"],
                  forbidden_operations=["drop"])
    clone = Engagement.from_dict(eng.to_dict())
    assert clone.is_target_authorized("https://x.example.com/") is False
    assert clone.is_operation_authorized("drop") is False
    assert clone.is_target_authorized("https://ok.example.com/") is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
