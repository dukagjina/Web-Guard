"""Encrypted DNS-over-HTTPS forwarding with certificate-verified endpoints.

Provider bootstrap IPs avoid a resolver loop when Windows already points to
Web Guard's local DNS listener. HTTPS still verifies the provider hostname via
SNI and the normal Windows/Python trust store; the IPs do not bypass TLS
authentication.
"""

from __future__ import annotations

import http.client
import itertools
import queue
import socket
import ssl
import threading
import time


PROVIDERS = {
    "cloudflare": {
        "label": "Cloudflare",
        "host": "cloudflare-dns.com",
        "path": "/dns-query",
        "ips": ("1.1.1.1", "1.0.0.1"),
    },
}

MAX_DNS_MESSAGE = 65535


def provider_label(provider: str) -> str:
    if provider == "system":
        return "System DNS"
    return PROVIDERS.get(provider, {}).get("label", "Encrypted DNS")


class DoHResolver:
    """Small bounded connection pool for RFC 8484 wire-format requests."""

    def __init__(self, provider: str, timeout=3.0, pool_size=8):
        if provider not in PROVIDERS:
            raise ValueError("Unsupported encrypted DNS provider")
        self.provider = provider
        self.config = PROVIDERS[provider]
        self.timeout = max(0.25, float(timeout))
        self._available = queue.LifoQueue(maxsize=max(1, int(pool_size)))
        self._slots = threading.BoundedSemaphore(max(1, int(pool_size)))
        self._ip_cycle = itertools.cycle(self.config["ips"])
        self._ip_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._closed = False
        self._last_success = None
        self._last_error = ""

    def _next_ip(self):
        with self._ip_lock:
            return next(self._ip_cycle)

    def _connection(self):
        host = self.config["host"]
        address = self._next_ip()
        connection = http.client.HTTPSConnection(
            host, 443, timeout=self.timeout, context=ssl.create_default_context()
        )

        def create_connection(_target, timeout=None, source_address=None):
            return socket.create_connection(
                (address, 443), timeout or self.timeout, source_address
            )

        # HTTPSConnection still uses ``host`` for SNI/certificate validation;
        # only the TCP bootstrap address is pinned here.
        connection._create_connection = create_connection
        return connection

    def _record_success(self):
        with self._state_lock:
            self._last_success = time.time()
            self._last_error = ""

    def _record_error(self, error):
        with self._state_lock:
            self._last_error = str(error)[:300]

    def query(self, packet: bytes) -> bytes:
        if not isinstance(packet, (bytes, bytearray)) or not 12 <= len(packet) <= MAX_DNS_MESSAGE:
            raise ValueError("Invalid DNS request")
        if self._closed:
            raise OSError("Encrypted DNS resolver is closed")
        if not self._slots.acquire(timeout=self.timeout):
            raise TimeoutError("Encrypted DNS is busy")
        try:
            last_error = None
            for _attempt in range(2):
                try:
                    connection = self._available.get_nowait()
                except queue.Empty:
                    connection = self._connection()
                reusable = False
                try:
                    connection.request(
                        "POST", self.config["path"], body=bytes(packet), headers={
                            "Accept": "application/dns-message",
                            "Content-Type": "application/dns-message",
                            "User-Agent": "Web-Guard/0.1",
                        },
                    )
                    response = connection.getresponse()
                    raw = response.read(MAX_DNS_MESSAGE + 1)
                    if response.status != 200:
                        raise OSError(f"Encrypted DNS returned HTTP {response.status}")
                    content_type = response.getheader("Content-Type", "")
                    if content_type.partition(";")[0].strip().lower() != "application/dns-message":
                        raise OSError("Encrypted DNS returned an unexpected content type")
                    if len(raw) < 12 or len(raw) > MAX_DNS_MESSAGE:
                        raise OSError("Encrypted DNS returned an invalid message")
                    if raw[:2] != bytes(packet[:2]):
                        raise OSError("Encrypted DNS returned a mismatched response")
                    if not raw[2] & 0x80:
                        raise OSError("Encrypted DNS did not return a response message")
                    reusable = not response.will_close and not self._closed
                    self._record_success()
                    return raw
                except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
                    last_error = exc
                finally:
                    if reusable:
                        try:
                            self._available.put_nowait(connection)
                        except queue.Full:
                            connection.close()
                    else:
                        connection.close()
            self._record_error(last_error or "Encrypted DNS failed")
            raise OSError("Encrypted DNS provider did not answer") from last_error
        finally:
            self._slots.release()

    def status(self):
        with self._state_lock:
            return {
                "provider": self.provider,
                "label": provider_label(self.provider),
                "encrypted": True,
                "last_success": self._last_success,
                "last_error": self._last_error,
            }

    def close(self):
        self._closed = True
        while True:
            try:
                self._available.get_nowait().close()
            except queue.Empty:
                break
