import unittest
import struct


from socks5.reader import (
    read_greeting_request, read_greeting_response,
    read_auth_request, read_auth_response, read_request,
    read_response)
from socks5.reader import ParserError


class TestReader(unittest.TestCase):
    def test_greeting_request(self):
        request = read_greeting_request(
            struct.pack("!BB2B", 0x5, 0x2, 0x00, 0x01))
        self.assertEqual(request.version, 5)
        self.assertEqual(request.nmethod, 2)
        self.assertIn(0, request.methods)
        self.assertIn(1, request.methods)

        request = read_greeting_request(
            struct.pack("!BB3B", 0x5, 0x3, 0x00, 0x01, 0x02))
        self.assertEqual(request.version, 5)
        self.assertEqual(request.nmethod, 3)
        self.assertIn(0, request.methods)
        self.assertIn(1, request.methods)
        self.assertIn(2, request.methods)

    def test_greeting_request_failed(self):
        with self.assertRaises(ParserError):
            read_greeting_request(
                struct.pack("!BB2B", 0x5, 0x3, 0x00, 0x01))

    def test_greeting_response(self):
        response = read_greeting_response(
            struct.pack("!BB", 0x5, 0x0))
        self.assertEqual(response.version, 5)
        self.assertEqual(response.auth_type, 0)

    def test_greeting_response_failed(self):
        with self.assertRaises(ParserError):
            read_greeting_response(
                struct.pack("!B", 0x5))

    def test_auth_request(self):
        auth_request = read_auth_request(
            struct.pack("!BB4sB8s", 0x5, 0x4, b"user", 0x8, b"password"))
        self.assertEqual(auth_request.version, 5)
        self.assertEqual(auth_request.username, "user")
        self.assertEqual(auth_request.password, "password")

    def test_auth_request_failed(self):
        with self.assertRaises(ParserError):
            read_auth_request(
                struct.pack("!B", 0x5))

    def test_auth_response(self):
        auth_response = read_auth_response(
            struct.pack("!BB", 0x5, 0x0))
        self.assertEqual(auth_response.version, 5)
        self.assertEqual(auth_response.status, 0)

    def test_auth_response_failed(self):
        with self.assertRaises(ParserError):
            read_auth_response(
                struct.pack("!B", 0x5))

    def test_read_request_ipv4(self):
        request = read_request(
            struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080))
        self.assertEqual(request.version, 5)
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.atyp, 1)
        self.assertEqual(request.addr, "127.0.0.1")
        self.assertEqual(request.port, 8080)

    def test_read_request_ipv6(self):
        request = read_request(
            struct.pack("!BBxB8HH",
                        0x5, 0x1, 0x4,
                        0, 0, 0, 0, 0, 0, 0, 1,
                        8080))
        self.assertEqual(request.version, 5)
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.atyp, 4)
        self.assertEqual(request.addr, u"::1")
        self.assertEqual(request.port, 8080)

    def test_read_request_hostname(self):
        request = read_request(
            struct.pack("!BBxBB10sH", 0x5, 0x1, 0x3, 10, b"google.com", 8080))
        self.assertEqual(request.version, 5)
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.atyp, 3)
        self.assertEqual(request.addr, "google.com")
        self.assertEqual(request.port, 8080)

    def test_read_request_failed(self):
        with self.assertRaises(ParserError):
            read_request(
                struct.pack("!B", 0x5))

    def test_read_response_ipv4(self):
        response = read_response(
            struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080))
        self.assertEqual(response.version, 5)
        self.assertEqual(response.status, 0)
        self.assertEqual(response.atyp, 1)
        self.assertEqual(response.addr, "127.0.0.1")
        self.assertEqual(response.port, 8080)

    def test_read_response_ipv6(self):
        response = read_response(
            struct.pack("!BBxB8HH",
                        0x5, 0x0, 0x4,
                        0, 0, 0, 0, 0, 0, 0, 1,
                        8080))
        self.assertEqual(response.version, 5)
        self.assertEqual(response.status, 0)
        self.assertEqual(response.atyp, 4)
        self.assertEqual(response.addr, u"::1")
        self.assertEqual(response.port, 8080)

    def test_read_response_hostname(self):
        response = read_response(
            struct.pack("!BBxBB10sH", 0x5, 0x0, 0x3, 10, b"google.com", 8080))
        self.assertEqual(response.version, 5)
        self.assertEqual(response.status, 0)
        self.assertEqual(response.atyp, 3)
        self.assertEqual(response.addr, "google.com")
        self.assertEqual(response.port, 8080)

    def test_read_response_failed(self):
        with self.assertRaises(ParserError):
            read_response(
                struct.pack("!B", 0x5))
