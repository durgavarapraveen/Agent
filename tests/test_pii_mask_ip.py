"""Regression: the PII scrubber's phone heuristic must NOT mask dotted-quad IPv4
addresses. A scan target/host like 10.54.144.124 matches the phone shape; masking
it to [MASKED_PHONE] made every IP in logs/scope undebuggable and muddied
target-scope lines. Real phone numbers must still be masked.
"""
import pytest

from core.reporting.reporting import mask_sensitive_data as mask


@pytest.mark.parametrize("ip", [
    "10.54.144.124",
    "172.17.0.2",
    "192.168.1.1",
    "8.8.8.8",
    "127.0.0.1",
])
def test_ipv4_targets_not_masked(ip):
    out = mask(f"Target: http://{ip}:3000/path")
    assert ip in out and "[MASKED_PHONE]" not in out, out


@pytest.mark.parametrize("phone", [
    "+1-555-123-4567",
    "555.867.5309",
    "+44 20 7946 0958",
])
def test_real_phones_still_masked(phone):
    assert "[MASKED_PHONE]" in mask(f"contact {phone}"), phone


def test_invalid_quad_is_masked():
    # 999.999.999.999 is not a valid IPv4 (octets > 255) -> treat as phone-ish PII
    assert "[MASKED_PHONE]" in mask("bad 999.999.999.999")
