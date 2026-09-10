import asyncio
import pytest
from core.network.network_broker import NetworkBroker, canonicalize_hostname, ResolvedTarget

@pytest.mark.asyncio
async def test_telemetry_and_pinning():
    broker = NetworkBroker.get()
    
    # Pre-populate DNS resolver with a safe IP
    canonical = canonicalize_hostname("example.com")
    with broker.resolver._lock:
        broker.resolver._cache[canonical] = ResolvedTarget(
            hostname="example.com",
            canonical=canonical,
            ips=("1.1.1.1",)
        )
        
    decision = await broker.check_url_async("http://example.com")
    assert decision.allowed is True
    
    # Check that client gets created properly with pinning
    client = broker.create_client(redirect_chain=[])
    assert client is not None
    
    # We can't actually make a real HTTP request in a fast unit test without mocking a server,
    # but we can verify that the client wraps the PinnedNetworkBackend successfully.
    transport = client._transport
    # Base transport inside GovernedTransport
    assert hasattr(transport, "_inner")
    base_transport = transport._inner
    
    assert hasattr(base_transport, "_pool")
    assert hasattr(base_transport._pool, "_network_backend")
    
    pinned_backend = base_transport._pool._network_backend
    assert type(pinned_backend).__name__ == "PinnedNetworkBackend"

@pytest.mark.asyncio
async def test_private_ip_blocked():
    broker = NetworkBroker.get()
    
    # Pre-populate DNS resolver with a dangerous IP
    canonical = canonicalize_hostname("malicious.internal")
    with broker.resolver._lock:
        broker.resolver._cache[canonical] = ResolvedTarget(
            hostname="malicious.internal",
            canonical=canonical,
            ips=("192.168.1.1",)
        )
        
    decision = await broker.check_url_async("http://malicious.internal")
    assert decision.allowed is False
    assert decision.reason_code == "PRIVATE_IP_BLOCKED"
