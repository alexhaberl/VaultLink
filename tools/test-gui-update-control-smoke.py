#!/usr/bin/env python3
"""Check IPC rejection outcomes with real Unix sockets, without root or a VM."""

import importlib.util
from pathlib import Path
import socket
import threading
import unittest


SPEC = importlib.util.spec_from_file_location(
    "gui_update_control_smoke",
    Path(__file__).with_name("gui-update-control-smoke.py"),
)
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class PeerRejectionTests(unittest.TestCase):
    def test_close_before_write(self):
        client, peer = socket.socketpair()
        with client:
            peer.close()
            SMOKE.assert_peer_rejected(client)

    def test_eof_after_request(self):
        client, peer = socket.socketpair()
        with client, peer:
            # A write-half close gives EOF without discarding the request.
            peer.shutdown(socket.SHUT_WR)
            SMOKE.assert_peer_rejected(client)
            self.assertEqual(peer.recv(8192), b'{"command":"status"}\n')

    def test_reset_with_unread_request(self):
        client, peer = socket.socketpair()

        def reject():
            with peer:
                # Leave the request unread so closing resets the connection.
                peer.recv(8192, socket.MSG_PEEK)

        with client:
            client.settimeout(2)
            peer.settimeout(2)
            server = threading.Thread(target=reject)
            server.start()
            try:
                SMOKE.assert_peer_rejected(client)
            finally:
                server.join(timeout=3)
            self.assertFalse(server.is_alive())

    def test_response_is_not_rejection(self):
        client, peer = socket.socketpair()
        with client, peer:
            peer.sendall(b"x")
            with self.assertRaisesRegex(AssertionError, "authorized IPC client"):
                SMOKE.assert_peer_rejected(client)

    def test_timeout_is_not_rejection(self):
        client, peer = socket.socketpair()
        with client, peer:
            client.settimeout(0.02)
            with self.assertRaises(TimeoutError):
                SMOKE.assert_peer_rejected(client)


if __name__ == "__main__":
    unittest.main()
