#!/usr/bin/env python3
"""Regression tests for the container proxy's forwarding-header boundary."""

import importlib.util
import socket
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("loopback-proxy.py")
SPEC = importlib.util.spec_from_file_location("loopback_proxy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
loopback_proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(loopback_proxy)


class RequestHeaderTests(unittest.TestCase):
    def test_replaces_client_supplied_forwarding_headers(self) -> None:
        client, proxy = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(proxy.close)
        client.sendall(
            b"GET /login HTTP/1.1\r\n"
            b"Host: vaultlink\r\n"
            b"X-Forwarded-For: 203.0.113.77\r\n"
            b"Forwarded: for=203.0.113.77\r\n"
            b"Connection: keep-alive\r\n\r\n"
        )

        request = loopback_proxy.read_request_headers(proxy, "198.51.100.42")

        self.assertEqual(
            request,
            b"GET /login HTTP/1.1\r\n"
            b"Host: vaultlink\r\n"
            b"X-Forwarded-For: 198.51.100.42\r\n"
            b"Connection: close\r\n\r\n",
        )


if __name__ == "__main__":
    unittest.main()
