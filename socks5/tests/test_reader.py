from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import struct
import ipaddress

from socks5.exception import ParserError
from socks5.events import NeedMoreData
from socks5.events import GreetingRequest, GreetingResponse
from socks5.events import Socks4Request, Socks4Response

from socks5._reader import (
    read_greeting_request, read_greeting_response,
    read_request, read_response)


class TestReader(unittest.TestCase):
    def test_greeting_request_socks5(self):
        request = read_greeting_request(
            struct.pack("!BB2B", 0x5, 0x2, 0x00, 0x01))
        self.assertIsInstance(request, GreetingRequest)
        self.assertEqual(request.nmethod, 2)
        self.assertIn(0, request.methods)
        self.assertIn(1, request.methods)

        request = read_greeting_request(
            struct.pack("!BB3B", 0x5, 0x3, 0x00, 0x01, 0x02))
        self.assertIsInstance(request, GreetingRequest)
        self.assertEqual(request.nmethod, 3)
        self.assertIn(0, request.methods)
        self.assertIn(1, request.methods)
        self.assertIn(2, request.methods)

    def test_greeting_request_socks4(self):
        raw_data = struct.pack("!BBH4B6sB", 0x4, 0x1, 5580, 127, 0, 0, 1, "Johnny".encode("ascii"), 0)

        request = read_greeting_request(raw_data)
        self.assertIsInstance(request, Socks4Request)
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.port, 5580)
        self.assertEqual(request.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(request.name, "Johnny")

        raw_data = struct.pack(
            "!BBH4B6sB14sB", 0x4, 0x1, 5580, 0, 0, 0, 1, "Johnny".encode("ascii"), 0, "www.google.com".encode("idna"), 0)

        request = read_greeting_request(raw_data)
        self.assertIsInstance(request, Socks4Request)
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.port, 5580)
        self.assertEqual(request.addr, ipaddress.IPv4Address("0.0.0.1"))
        self.assertEqual(request.name, "Johnny")
        self.assertEqual(request.domainname, "www.google.com")

    def test_greeting_request_not_enough_data(self):
        request = read_greeting_request(
            struct.pack("!BB2B", 0x5, 0x3, 0x00, 0x01))
        self.assertIsInstance(request, NeedMoreData)

    def test_greeting_request_failed_invalid_version(self):
        with self.assertRaises(ParserError):
            read_greeting_request(
                struct.pack("!BB2B", 0x3, 0x3, 0x00, 0x01))

    def test_greeting_response_socks5(self):
        response = read_greeting_response(
            struct.pack("!BB", 0x5, 0x0))
        self.assertIsInstance(response, GreetingResponse)
        self.assertEqual(response.auth_type, 0)

    def test_greeting_response_socks4(self):
        raw_data = struct.pack("!BBH4B", 0, 0x5a, 5580, 127, 0, 0, 1)
        response = read_greeting_response(raw_data)
        self.assertIsInstance(response, Socks4Response)
        self.assertEqual(response.status, 0x5a)
        self.assertEqual(response.port, 5580)
        self.assertEqual(response.addr, ipaddress.IPv4Address("127.0.0.1"))

    def test_greeting_response_not_enouch_data(self):
        event = read_greeting_response(
            struct.pack("!B", 0x5))
        self.assertIsInstance(event, NeedMoreData)

    def test_greeting_response_failed_incorrect_version(self):
        with self.assertRaises(ParserError):
            read_greeting_response(
                struct.pack("!B", 0x1))

    def test_read_request_ipv4(self):
        request = read_request(
            struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080))
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.atyp, 1)
        self.assertEqual(request.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(request.port, 8080)

    def test_read_request_ipv6(self):
        request = read_request(
            struct.pack("!BBxB8HH",
                        0x5, 0x1, 0x4,
                        0, 0, 0, 0, 0, 0, 0, 1,
                        8080))
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.atyp, 4)
        self.assertEqual(request.addr, ipaddress.IPv6Address("::1"))
        self.assertEqual(request.port, 8080)

    def test_read_request_hostname(self):
        request = read_request(
            struct.pack("!BBxBB10sH", 0x5, 0x1, 0x3, 10, b"google.com", 8080))
        self.assertEqual(request.cmd, 1)
        self.assertEqual(request.atyp, 3)
        self.assertEqual(request.addr, "google.com")
        self.assertEqual(request.port, 8080)

    def test_read_request_not_enough_data(self):
        event = read_request(
            struct.pack("!B", 0x5))
        self.assertIsInstance(event, NeedMoreData)

    def test_read_request_failed_incorrect_version(self):
        with self.assertRaises(ParserError):
            read_request(
                struct.pack("!B", 0x4))

    def test_read_response_ipv4(self):
        response = read_response(
            struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080))
        self.assertEqual(response.status, 0)
        self.assertEqual(response.atyp, 1)
        self.assertEqual(response.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(response.port, 8080)

    def test_read_response_ipv6(self):
        response = read_response(
            struct.pack("!BBxB8HH",
                        0x5, 0x0, 0x4,
                        0, 0, 0, 0, 0, 0, 0, 1,
                        8080))
        self.assertEqual(response.status, 0)
        self.assertEqual(response.atyp, 4)
        self.assertEqual(response.addr, ipaddress.IPv6Address("::1"))
        self.assertEqual(response.port, 8080)

    def test_read_response_hostname(self):
        response = read_response(
            struct.pack("!BBxBB10sH", 0x5, 0x0, 0x3, 10, b"google.com", 8080))
        self.assertEqual(response.status, 0)
        self.assertEqual(response.atyp, 3)
        self.assertEqual(response.addr, "google.com")
        self.assertEqual(response.port, 8080)

    def test_read_response_not_enough_data(self):
        event = read_response(
            struct.pack("!B", 0x5))
        self.assertIsInstance(event, NeedMoreData)

    def test_read_response_failed_incorrect_version(self):
        with self.assertRaises(ParserError):
            read_response(
                struct.pack("!B", 0x4))
