"""Small local DNS proxy backed by the bundled Web Guard threat catalog."""

from __future__ import annotations

import collections
import ipaddress
import socket
import socketserver
import struct
import threading
import time

from dnslib import DNSRecord, RCODE

from .catalog import ThreatCatalog, category_mask
from .encrypted_dns import DoHResolver, provider_label


DNS_PORT = 53
MAX_PACKET = 65535


class RuntimePolicy:
    def __init__(self, settings: dict):
        self._lock = threading.RLock()
        self.update(settings)

    def update(self, settings: dict):
        with self._lock:
            self.enabled_mask = category_mask(settings.get("categories", {}))
            self.allowlist = frozenset(settings.get("allowlist", []))
            self.custom_blocklist = frozenset(
                settings.get("custom_blocklist", [])
            )

    def snapshot(self):
        with self._lock:
            return self.enabled_mask, self.allowlist, self.custom_blocklist


class ProtectionStats:
    """Aggregate counters only; requested domain names are never retained."""

    def __init__(self):
        self._lock = threading.Lock()
        self._started = time.time()
        self._queries = 0
        self._blocked = 0
        self._categories = collections.Counter()

    def query(self, category: str | None):
        with self._lock:
            self._queries += 1
            if category:
                self._blocked += 1
                self._categories[category] += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "queries": self._queries,
                "blocked": self._blocked,
                "categories": dict(self._categories),
                "started": self._started,
            }


def _query_name(packet: bytes) -> str | None:
    try:
        request = DNSRecord.parse(packet)
        if not request.questions:
            return None
        return str(request.questions[0].qname).rstrip(".").lower()
    except Exception:
        return None


def _blocked_reply(packet: bytes) -> bytes:
    request = DNSRecord.parse(packet)
    reply = request.reply()
    reply.header.rcode = RCODE.NXDOMAIN
    return reply.pack()


def _socket_family(address: str):
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET


def _forward_udp(packet: bytes, servers: tuple[str, ...], timeout=2.0) -> bytes:
    last_error = None
    for address in servers:
        family = _socket_family(address)
        target = (address, DNS_PORT, 0, 0) if family == socket.AF_INET6 else (address, DNS_PORT)
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(timeout)
                # A connected UDP socket only accepts replies from the chosen
                # resolver instead of accepting any datagram sent to its port.
                upstream.connect(target)
                upstream.sendall(packet)
                response = upstream.recv(MAX_PACKET)
                if len(response) < 2 or response[:2] != packet[:2]:
                    raise OSError("The DNS resolver returned a mismatched response")
                return response
        except OSError as exc:
            last_error = exc
    raise OSError("Every configured DNS server failed") from last_error


def _read_tcp_message(connection: socket.socket) -> bytes:
    header = connection.recv(2)
    if len(header) != 2:
        raise OSError("Incomplete DNS-over-TCP header")
    expected = struct.unpack("!H", header)[0]
    parts = []
    received = 0
    while received < expected:
        part = connection.recv(expected - received)
        if not part:
            raise OSError("Incomplete DNS-over-TCP message")
        parts.append(part)
        received += len(part)
    return b"".join(parts)


def _forward_tcp(packet: bytes, servers: tuple[str, ...], timeout=3.0) -> bytes:
    last_error = None
    for address in servers:
        target = (address, DNS_PORT)
        try:
            with socket.create_connection(target, timeout=timeout) as upstream:
                upstream.sendall(struct.pack("!H", len(packet)) + packet)
                response = _read_tcp_message(upstream)
                if len(response) < 2 or response[:2] != packet[:2]:
                    raise OSError("The DNS resolver returned a mismatched response")
                return response
        except OSError as exc:
            last_error = exc
    raise OSError("Every configured DNS server failed") from last_error


class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadingUDPServer6(_ThreadingUDPServer):
    address_family = socket.AF_INET6


class _ThreadingTCPServer6(_ThreadingTCPServer):
    address_family = socket.AF_INET6


class _DNSHandlerMixin:
    def answer(self, packet: bytes, transport: str) -> bytes:
        domain = _query_name(packet)
        match = None
        if domain:
            mask, allowlist, custom = self.server.policy.snapshot()
            match = self.server.catalog.match(domain, mask, allowlist, custom)
        self.server.stats.query(match.category if match and match.blocked else None)
        if match and match.blocked:
            return _blocked_reply(packet)
        return self.server.forward(packet, transport)


class UDPHandler(_DNSHandlerMixin, socketserver.BaseRequestHandler):
    def handle(self):
        packet, connection = self.request
        try:
            connection.sendto(self.answer(packet, "udp"), self.client_address)
        except (OSError, ValueError):
            return


class TCPHandler(_DNSHandlerMixin, socketserver.BaseRequestHandler):
    def handle(self):
        try:
            packet = _read_tcp_message(self.request)
            response = self.answer(packet, "tcp")
            self.request.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, ValueError):
            return


class DNSProxy:
    def __init__(self, settings: dict, upstreams: list[str], catalog_path=None, local_port=DNS_PORT):
        cleaned = []
        for value in upstreams:
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if not ipaddress.ip_address(address).is_loopback and address not in cleaned:
                cleaned.append(address)
        self.provider = str(settings.get("dns_provider", "cloudflare"))
        if self.provider not in ("cloudflare", "system"):
            self.provider = "cloudflare"
        if self.provider == "system" and not cleaned:
            raise RuntimeError("Windows did not report a usable upstream DNS resolver")
        self.upstreams = tuple(cleaned)
        self.local_port = int(local_port)
        self._encrypted_resolver = (
            DoHResolver(self.provider) if self.provider != "system" else None
        )
        self.policy = RuntimePolicy(settings)
        self.stats = ProtectionStats()
        self.catalog = ThreatCatalog(catalog_path)
        self._servers = []
        self._threads = []

    def _create_server(self, server_class, address, handler):
        server = server_class(address, handler)
        server.catalog = self.catalog
        server.policy = self.policy
        server.stats = self.stats
        server.forward = self._forward
        return server

    def _forward(self, packet: bytes, transport: str) -> bytes:
        if self._encrypted_resolver:
            return self._encrypted_resolver.query(packet)
        if transport == "tcp":
            return _forward_tcp(packet, self.upstreams)
        return _forward_udp(packet, self.upstreams)

    def upstream_status(self):
        if self._encrypted_resolver:
            return self._encrypted_resolver.status()
        return {
            "provider": "system",
            "label": provider_label("system"),
            "encrypted": False,
            "last_success": None,
            "last_error": "",
        }

    def start(self):
        if self._servers:
            return
        if self._encrypted_resolver:
            # Verify HTTPS, certificate validation, and the provider response
            # before Windows is changed to use the local resolver.
            self._encrypted_resolver.query(DNSRecord.question("example.com", "A").pack())
        created = []
        try:
            created.append(self._create_server(_ThreadingUDPServer, ("127.0.0.1", self.local_port), UDPHandler))
            created.append(self._create_server(_ThreadingTCPServer, ("127.0.0.1", self.local_port), TCPHandler))
            created.append(self._create_server(_ThreadingUDPServer6, ("::1", self.local_port), UDPHandler))
            created.append(self._create_server(_ThreadingTCPServer6, ("::1", self.local_port), TCPHandler))
        except OSError:
            for server in created:
                server.server_close()
            raise
        self._servers = created
        for server in self._servers:
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.1},
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def update(self, settings: dict):
        self.policy.update(settings)

    def stop(self):
        for server in self._servers:
            server.shutdown()
        for server in self._servers:
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._servers.clear()
        self._threads.clear()
        if self._encrypted_resolver:
            self._encrypted_resolver.close()
        self.catalog.close()
