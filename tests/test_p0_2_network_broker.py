import pytest
import socket
from unittest.mock import patch, MagicMock
from core.network.network_broker import (
    NetworkBroker, NetworkDecision, ResolvedTarget, DNSResolver,
    RequestBudget, get_network_broker,
    _is_dangerous_ip, _is_localhost_name, canonicalize_hostname,
    parse_url_target,
)


@pytest.fixture(autouse=True)
def reset_broker():
    NetworkBroker.reset_for_tests()
    yield
    NetworkBroker.reset_for_tests()


# ── IP classification ────────────────────────────────────────────────────

class TestDangerousIP:
    def test_private_ipv4(self):
        assert _is_dangerous_ip("192.168.1.1")
        assert _is_dangerous_ip("10.0.0.1")
        assert _is_dangerous_ip("172.16.0.1")

    def test_loopback(self):
        assert _is_dangerous_ip("127.0.0.1")
        assert _is_dangerous_ip("::1")

    def test_link_local(self):
        assert _is_dangerous_ip("169.254.1.1")
        assert _is_dangerous_ip("fe80::1")

    def test_carrier_grade_nat(self):
        assert _is_dangerous_ip("100.64.0.1")
        assert _is_dangerous_ip("100.127.255.254")

    def test_ipv4_mapped_ipv6(self):
        assert _is_dangerous_ip("::ffff:127.0.0.1")
        assert _is_dangerous_ip("::ffff:192.168.1.1")

    def test_6to4_embedding_private(self):
        # 2002:7f00:0001:: embeds 127.0.0.1
        assert _is_dangerous_ip("2002:7f00:1::1")

    def test_public_ip_safe(self):
        assert not _is_dangerous_ip("8.8.8.8")
        assert not _is_dangerous_ip("1.1.1.1")
        assert not _is_dangerous_ip("93.184.216.34")

    def test_invalid_ip_fails_closed(self):
        assert _is_dangerous_ip("not-an-ip")

    def test_multicast(self):
        assert _is_dangerous_ip("224.0.0.1")
        assert _is_dangerous_ip("ff02::1")

    def test_unspecified(self):
        assert _is_dangerous_ip("0.0.0.0")
        assert _is_dangerous_ip("::")


# ── Localhost aliases ────────────────────────────────────────────────────

class TestLocalhostAliases:
    def test_standard_names(self):
        assert _is_localhost_name("localhost")
        assert _is_localhost_name("LOCALHOST")
        assert _is_localhost_name("localhost.localdomain")

    def test_ip_literals(self):
        assert _is_localhost_name("127.0.0.1")
        assert _is_localhost_name("127.0.0.2")
        assert _is_localhost_name("::1")
        assert _is_localhost_name("0.0.0.0")

    def test_hex_encoded_loopback(self):
        # 0x7f000001 = 127.0.0.1
        assert _is_localhost_name("0x7f000001")

    def test_decimal_encoded_loopback(self):
        # 2130706433 = 127.0.0.1
        assert _is_localhost_name("2130706433")

    def test_lvh_me(self):
        assert _is_localhost_name("lvh.me")

    def test_normal_host_not_localhost(self):
        assert not _is_localhost_name("example.com")
        assert not _is_localhost_name("google.com")


# ── Hostname canonicalization ────────────────────────────────────────────

class TestCanonicalization:
    def test_lowercase(self):
        assert canonicalize_hostname("EXAMPLE.COM") == "example.com"

    def test_strip_brackets(self):
        assert canonicalize_hostname("[::1]") == "::1"

    def test_strip_trailing_dot(self):
        assert canonicalize_hostname("example.com.") == "example.com"

    def test_empty(self):
        assert canonicalize_hostname("") == ""
        assert canonicalize_hostname(None) == ""


class TestParseURL:
    def test_basic_https(self):
        s, h, p, path = parse_url_target("https://example.com/path")
        assert s == "https"
        assert h == "example.com"
        assert p == 443
        assert path == "/path"

    def test_http_with_port(self):
        s, h, p, path = parse_url_target("http://example.com:8080/")
        assert s == "http"
        assert p == 8080

    def test_default_port(self):
        _, _, p, _ = parse_url_target("http://example.com")
        assert p == 80


# ── DNS resolver ─────────────────────────────────────────────────────────

class TestDNSResolver:
    def test_ip_literal_no_dns(self):
        resolver = DNSResolver()
        result = resolver.resolve("93.184.216.34")
        assert result.ips == ("93.184.216.34",)
        assert result.canonical == "93.184.216.34"

    def test_cache_hit(self):
        resolver = DNSResolver(cache_ttl=300)
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            ]
            r1 = resolver.resolve("example.com")
            r2 = resolver.resolve("example.com")
            assert r1 is r2
            assert mock_dns.call_count == 1

    def test_unresolvable_returns_empty(self):
        resolver = DNSResolver()
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            result = resolver.resolve("nonexistent.invalid")
            assert result.ips == ()


# ── NetworkBroker.check_url ──────────────────────────────────────────────

class TestCheckURL:
    def _broker_with_mocked_dns(self, ips):
        resolver = DNSResolver()
        with patch.object(resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = ResolvedTarget(
                hostname="example.com", canonical="example.com",
                ips=tuple(ips),
            )
            broker = NetworkBroker(resolver=resolver)
            yield broker, mock_resolve

    def test_empty_url_denied(self):
        broker = NetworkBroker()
        d = broker.check_url("")
        assert not d.allowed
        assert d.reason_code == "SCHEMA_INVALID"

    def test_no_host_denied(self):
        broker = NetworkBroker()
        d = broker.check_url("http://")
        assert not d.allowed

    @patch("core.security.egress_firewall.assert_egress_allowed")
    def test_authorized_target_allowed(self, mock_egress):
        mock_egress.return_value = None
        resolver = DNSResolver()
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="example.com", canonical="example.com",
            ips=("93.184.216.34",),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.check_url("https://example.com")
            assert d.allowed
            assert d.resolved.ips == ("93.184.216.34",)

    def test_private_ip_denied(self):
        resolver = DNSResolver()
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="evil.com", canonical="evil.com",
            ips=("192.168.1.1",),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.check_url("https://evil.com")
            assert not d.allowed
            assert d.reason_code == "PRIVATE_IP_BLOCKED"

    def test_localhost_alias_denied(self):
        broker = NetworkBroker()
        d = broker.check_url("http://localhost/admin")
        assert not d.allowed
        assert d.reason_code == "PRIVATE_IP_BLOCKED"

    def test_dns_failure_denied(self):
        resolver = DNSResolver()
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="gone.example", canonical="gone.example", ips=(),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.check_url("https://gone.example")
            assert not d.allowed
            assert d.reason_code == "DNS_REBIND_BLOCKED"


# ── Redirect revalidation ───────────────────────────────────────────────

class TestRedirectValidation:
    @patch("core.security.egress_firewall.assert_egress_allowed")
    def test_redirect_to_private_ip_blocked(self, mock_egress):
        mock_egress.return_value = None
        resolver = DNSResolver()
        # First URL is fine
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="evil.com", canonical="evil.com",
            ips=("192.168.1.1",),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.validate_redirect(
                "https://example.com", "https://evil.com", hop=0,
            )
            assert not d.allowed
            assert "private" in d.reason.lower() or "192.168" in d.reason

    @patch("core.security.egress_firewall.assert_egress_allowed")
    def test_redirect_to_authorized_target(self, mock_egress):
        mock_egress.return_value = None
        resolver = DNSResolver()
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="other.example.com", canonical="other.example.com",
            ips=("93.184.216.35",),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.validate_redirect(
                "https://example.com", "https://other.example.com", hop=0,
            )
            assert d.allowed

    def test_too_many_redirects(self):
        broker = NetworkBroker(max_redirects=5)
        d = broker.validate_redirect("https://a.com", "https://b.com", hop=5)
        assert not d.allowed
        assert "too many" in d.reason.lower()


# ── DNS rebinding protection ────────────────────────────────────────────

class TestDNSRebinding:
    def test_rebind_to_dangerous_ip_blocked(self):
        resolver = DNSResolver()
        previous = ResolvedTarget(
            hostname="example.com", canonical="example.com",
            ips=("93.184.216.34",),
        )
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="example.com", canonical="example.com",
            ips=("127.0.0.1",),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.verify_no_rebind("example.com", previous)
            assert not d.allowed
            assert d.reason_code == "DNS_REBIND_BLOCKED"

    def test_no_rebind_allowed(self):
        resolver = DNSResolver()
        previous = ResolvedTarget(
            hostname="example.com", canonical="example.com",
            ips=("93.184.216.34",),
        )
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="example.com", canonical="example.com",
            ips=("93.184.216.34",),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.verify_no_rebind("example.com", previous)
            assert d.allowed


# ── IPv6 specific ────────────────────────────────────────────────────────

class TestIPv6:
    def test_ipv6_loopback_blocked(self):
        broker = NetworkBroker()
        d = broker.check_url("http://[::1]/admin")
        assert not d.allowed

    def test_ipv4_mapped_ipv6_private_blocked(self):
        resolver = DNSResolver()
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="mapped.example", canonical="mapped.example",
            ips=("::ffff:10.0.0.1",),
        )):
            broker = NetworkBroker(resolver=resolver)
            d = broker.check_url("https://mapped.example")
            assert not d.allowed
            assert d.reason_code == "PRIVATE_IP_BLOCKED"


# ── Request budget ───────────────────────────────────────────────────────

class TestRequestBudget:
    def test_budget_enforced(self):
        budget = RequestBudget(max_requests=2)
        assert budget.consume()
        assert budget.consume()
        assert not budget.consume()
        assert budget.remaining == 0
        assert budget.used == 2

    def test_budget_reset(self):
        budget = RequestBudget(max_requests=1)
        budget.consume()
        assert budget.remaining == 0
        budget.reset()
        assert budget.remaining == 1

    @patch("core.security.egress_firewall.assert_egress_allowed")
    def test_budget_exhausted_denies_request(self, mock_egress):
        mock_egress.return_value = None
        resolver = DNSResolver()
        with patch.object(resolver, "resolve", return_value=ResolvedTarget(
            hostname="example.com", canonical="example.com",
            ips=("93.184.216.34",),
        )):
            budget = RequestBudget(max_requests=0)
            broker = NetworkBroker(resolver=resolver, budget=budget)
            d = broker.check_url("https://example.com")
            assert not d.allowed
            assert d.reason_code == "BUDGET_EXCEEDED"


# ── Singleton ────────────────────────────────────────────────────────────

class TestSingleton:
    def test_get_returns_same_instance(self):
        a = NetworkBroker.get()
        b = NetworkBroker.get()
        assert a is b

    def test_reset_clears(self):
        a = NetworkBroker.get()
        NetworkBroker.reset_for_tests()
        b = NetworkBroker.get()
        assert a is not b

    def test_module_accessor(self):
        a = get_network_broker()
        b = get_network_broker()
        assert a is b


# ── Alternate IP representations ─────────────────────────────────────────

class TestAlternateIPRepresentations:
    def test_hex_loopback(self):
        assert _is_localhost_name("0x7f000001")

    def test_decimal_loopback(self):
        assert _is_localhost_name("2130706433")

    def test_ipv6_bracket_notation(self):
        broker = NetworkBroker()
        d = broker.check_url("http://[::1]:8080/")
        assert not d.allowed
