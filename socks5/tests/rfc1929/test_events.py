from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from socks5.define import RESP_STATUS
from socks5.auth.rfc1929.events import NeedMoreData, AuthRequest, AuthResponse


class TestEvents(unittest.TestCase):
    def test_need_more_data(self):
        event = NeedMoreData()
        self.assertEqual(event, "NeedMoreData")

    def test_rfc1929_auth_request(self):
        event = AuthRequest("user", "password")
        self.assertEqual(event, "AuthRequest")
        self.assertEqual(event.username, "user")
        self.assertEqual(event.password, "password")

    def test_rfc1929_auth_request_username_too_long(self):
        with self.assertRaises(ValueError):
            AuthRequest("a" * 256, "password")

    def test_rfc1929_auth_request_password_too_long(self):
        with self.assertRaises(ValueError):
            AuthRequest("user", "a" * 256)

    def test_rfc1929_auth_request_incorrect_username_type(self):
        with self.assertRaises(ValueError):
            AuthRequest(b"user", "a")

    def test_rfc1929_auth_request_incorrect_password_type(self):
        with self.assertRaises(ValueError):
            AuthRequest("user", b"a")

    def test_rfc1929_auth_response(self):
        event = AuthResponse(RESP_STATUS["SUCCESS"])
        self.assertEqual(event, "AuthResponse")

        self.assertEqual(event.status, RESP_STATUS["SUCCESS"])

    def test_rfc1929_auth_response_failed_unsupported_status(self):
        with self.assertRaises(ValueError):
            AuthResponse(0xff)
