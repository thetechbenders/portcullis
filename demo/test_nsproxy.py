"""Unprivileged tests of relay HTTP error honesty. No namespace operations."""
import os
import socket
import unittest
from unittest import mock

import nsproxy


class RelayErrorTests(unittest.TestCase):
    def check_error(self, error, expected_status):
        relay_end, browser_end = socket.socketpair()
        with browser_end:
            # The test does not call setns or attach to any real namespace.
            stub_fd = os.open(os.devnull, os.O_RDONLY)
            try:
                with mock.patch.object(nsproxy.os, "open", return_value=stub_fd), \
                     mock.patch.object(nsproxy.os, "setns", create=True), \
                     mock.patch.object(nsproxy.socket, "create_connection", side_effect=error):
                    nsproxy.handle(relay_end, "/irrelevant", ("198.18.0.2", 8080), 0.1)
            finally:
                # handle closes the stub fd after the mocked setns.
                pass
            browser_end.settimeout(1)
            chunks = []
            while True:
                data = browser_end.recv(65536)
                if not data:
                    break
                chunks.append(data)
        reply = b"".join(chunks).decode()
        self.assertIn(expected_status, reply.split("\r\n", 1)[0])
        self.assertIn("does not by itself prove", reply)
        self.assertNotIn("guard dropped the packets", reply)
        self.assertNotIn("because this device has no active grant", reply)

    def test_timeout_never_claims_enforcement(self):
        self.check_error(TimeoutError("timed out"), "504 Gateway Timeout")

    def test_refused_never_claims_enforcement(self):
        self.check_error(ConnectionRefusedError("service unavailable"), "502 Bad Gateway")

    def test_unreachable_never_claims_enforcement(self):
        self.check_error(OSError("network unreachable"), "502 Bad Gateway")


if __name__ == "__main__":
    unittest.main()
