import pytest
from dnslib import DNSRecord

from web_guard.encrypted_dns import DoHResolver


class FakeResponse:
    def __init__(self, body, status=200, will_close=True, content_type="application/dns-message"):
        self._body = body
        self.status = status
        self.will_close = will_close
        self.content_type = content_type

    def read(self, _limit):
        return self._body

    def getheader(self, name, default=None):
        return self.content_type if name.lower() == "content-type" else default


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.closed = False
        self.request_args = None

    def request(self, *args, **kwargs):
        self.request_args = (args, kwargs)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def test_encrypted_dns_accepts_matching_wire_response(monkeypatch):
    packet = DNSRecord.question("example.com", "A").pack()
    response = DNSRecord.parse(packet).reply().pack()
    connection = FakeConnection(FakeResponse(response))
    resolver = DoHResolver("cloudflare", timeout=.25, pool_size=1)
    monkeypatch.setattr(resolver, "_connection", lambda: connection)

    assert resolver.query(packet) == response
    assert connection.request_args[0][0:2] == ("POST", "/dns-query")
    assert resolver.status()["last_success"] is not None


def test_encrypted_dns_rejects_mismatched_transaction(monkeypatch):
    packet = DNSRecord.question("example.com", "A").pack()
    wrong = bytearray(DNSRecord.parse(packet).reply().pack())
    wrong[0] ^= 0xFF
    resolver = DoHResolver("cloudflare", timeout=.25, pool_size=1)
    monkeypatch.setattr(
        resolver, "_connection",
        lambda: FakeConnection(FakeResponse(bytes(wrong))),
    )

    with pytest.raises(OSError, match="did not answer"):
        resolver.query(packet)
    assert resolver.status()["last_error"]
