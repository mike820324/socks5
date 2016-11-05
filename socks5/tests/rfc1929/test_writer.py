from __future__ import absolute_import, division, print_function, unicode_literals
import unittest
import struct


from socks5.define import RESP_STATUS

from socks5.auth.rfc1929.events import AuthRequest, AuthResponse
from socks5.auth.rfc1929._writer import write_auth_request, write_auth_response


class TestWriter(unittest.TestCase):
    def test_auth_request(self):
        event = AuthRequest("user", "password")
        data = write_auth_request(event)
        expected_data = struct.pack("!BB4sB8s", 0x1, 0x4, b"user", 0x8, b"password")
        self.assertEqual(data, expected_data)

    def test_auth_response(self):
        event = AuthResponse(RESP_STATUS["SUCCESS"])
        data = write_auth_response(event)
        expected_data = struct.pack("!BB", 0x1, 0x0)
        self.assertEqual(data, expected_data)
