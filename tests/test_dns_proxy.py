from dnslib import DNSRecord, RCODE

import pytest

from web_guard import dns_proxy
from web_guard.dns_proxy import DNSProxy, _blocked_reply, _query_name


def test_query_name_and_nxdomain_reply():
    packet = DNSRecord.question("bad.example", "A").pack()
    assert _query_name(packet) == "bad.example"
    reply = DNSRecord.parse(_blocked_reply(packet))
    assert reply.header.rcode == RCODE.NXDOMAIN
    assert reply.header.id == DNSRecord.parse(packet).header.id


def test_encrypted_provider_does_not_require_plain_dns_upstream(monkeypatch):
    class FakeResolver:
        def __init__(self, provider):
            self.provider = provider

        def close(self):
            pass

    class FakeCatalog:
        def __init__(self, path):
            self.path = path

        def close(self):
            pass

    monkeypatch.setattr(dns_proxy, "DoHResolver", FakeResolver)
    monkeypatch.setattr(dns_proxy, "ThreatCatalog", FakeCatalog)
    proxy = DNSProxy({"dns_provider": "cloudflare"}, [], "unused", local_port=5300)
    assert proxy.provider == "cloudflare"
    proxy.stop()

    with pytest.raises(RuntimeError, match="usable upstream"):
        DNSProxy({"dns_provider": "system"}, [], "unused", local_port=5300)
