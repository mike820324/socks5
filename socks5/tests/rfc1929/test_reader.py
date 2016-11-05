from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import struct

from socks5.exception import ParserError
from socks5.events import NeedMoreData

from socks5.auth.rfc1929._reader import read_auth_request, read_auth_response


class TestReader(unittest.TestCase):
    def test_auth_request(self):
        auth_request = read_auth_request(
            struct.pack("!BB4sB8s", 0x1, 0x4, b"user", 0x8, b"password"))
        self.assertEqual(auth_request.username, "user")
        self.assertEqual(auth_request.password, "password")

    def test_auth_request_not_enough_data(self):
        event = read_auth_request(
            struct.pack("!B", 0x1))
        self.assertIsInstance(event, NeedMoreData)

    def test_auth_request_failed_incorrect_version(self):
        with self.assertRaises(ParserError):
            read_auth_request(
                struct.pack("!B", 0x4))

    def test_auth_response(self):
        auth_response = read_auth_response(
            struct.pack("!BB", 0x1, 0x0))
        self.assertEqual(auth_response.status, 0)

    def test_auth_response_not_enough_data(self):
        event = read_auth_response(
            struct.pack("!B", 0x1))
        self.assertIsInstance(event, NeedMoreData)

    def test_auth_response_failed_incorrect_version(self):
        with self.assertRaises(ParserError):
            read_auth_response(
                struct.pack("!B", 0x4))
