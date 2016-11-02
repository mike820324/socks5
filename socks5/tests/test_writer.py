from __future__ import absolute_import, division, print_function, unicode_literals
import unittest
import struct


from socks5.writer import (
    write_greeting_request, write_greeting_response,
    write_auth_request, write_auth_response, write_request,
    write_response)

from socks5.events import (
    GreetingRequest, GreetingResponse,
    AuthRequest, AuthResponse,
    Request, Response)

from socks5.define import (
    VERSION, REQ_COMMAND, AUTH_TYPE,
    RESP_STATUS, ADDR_TYPE)


class TestWriter(unittest.TestCase):
    def test_greeting_request(self):
        event = GreetingRequest(VERSION, 1, [AUTH_TYPE["NO_AUTH"]])
        data = write_greeting_request(event)
        expected_data = struct.pack("!BBB", 0x5, 0x1, 0x00)
        self.assertEqual(data, expected_data)

        event = GreetingRequest(VERSION, 2, [AUTH_TYPE["NO_AUTH"], AUTH_TYPE["GSSAPI"]])
        data = write_greeting_request(event)
        expected_data = struct.pack("!BB2B", 0x5, 0x2, 0x00, 0x01)
        self.assertEqual(data, expected_data)

    def test_greeting_response(self):
        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        data = write_greeting_response(event)
        expected_data = struct.pack("!BB", 0x5, 0x0)
        self.assertEqual(data, expected_data)

    def test_auth_request(self):
        event = AuthRequest(VERSION, "user", "password")
        data = write_auth_request(event)
        expected_data = struct.pack("!BB4sB8s", 0x5, 0x4, b"user", 0x8, b"password")
        self.assertEqual(data, expected_data)

    def test_auth_response(self):
        event = AuthResponse(VERSION, RESP_STATUS["SUCCESS"])
        data = write_auth_response(event)
        expected_data = struct.pack("!BB", 0x5, 0x0)
        self.assertEqual(data, expected_data)

    def test_write_request_ipv4(self):
        event = Request(VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = write_request(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(data, expected_data)

    def test_write_request_ipv6(self):
        event = Request(VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV6"], u"::1", 8080)
        data = write_request(event)
        expected_data = struct.pack("!BBxB8HH",
                                    0x5, 0x1, 0x4,
                                    0, 0, 0, 0, 0, 0, 0, 1,
                                    8080)
        self.assertEqual(data, expected_data)

    def test_write_request_hostname(self):
        event = Request(VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["DOMAINNAME"], u"google.com", 8080)
        data = write_request(event)
        expected_data = struct.pack("!BBxBB10sH", 0x5, 0x1, 0x3, 10, b"google.com", 8080)
        self.assertEqual(data, expected_data)

    def test_write_response_ipv4(self):
        event = Response(VERSION, RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = write_response(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(data, expected_data)

    def test_write_response_ipv6(self):
        event = Response(VERSION, RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV6"], u"::1", 8080)
        data = write_response(event)
        expected_data = struct.pack("!BBxB8HH",
                                    0x5, 0x0, 0x4,
                                    0, 0, 0, 0, 0, 0, 0, 1,
                                    8080)
        self.assertEqual(data, expected_data)

    def test_write_response_hostname(self):
        event = Response(VERSION, RESP_STATUS["SUCCESS"], ADDR_TYPE["DOMAINNAME"], u"google.com", 8080)
        data = write_response(event)
        expected_data = struct.pack("!BBxBB10sH", 0x5, 0x0, 0x3, 10, b"google.com", 8080)
        self.assertEqual(data, expected_data)
