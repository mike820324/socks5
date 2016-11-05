from __future__ import absolute_import, division, print_function, unicode_literals
import unittest
import struct


from socks5.events import (
    Socks4Request, Socks4Response,
    GreetingRequest, GreetingResponse,
    Request, Response)

from socks5.define import (
    REQ_COMMAND, AUTH_TYPE,
    RESP_STATUS, ADDR_TYPE)

from socks5._writer import (
    write_greeting_request, write_greeting_response,
    write_request, write_response)


class TestWriter(unittest.TestCase):
    def test_greeting_request_socks5(self):
        event = GreetingRequest([AUTH_TYPE["NO_AUTH"]])
        data = write_greeting_request(event)
        expected_data = struct.pack("!BBB", 0x5, 0x1, 0x00)
        self.assertEqual(data, expected_data)

        event = GreetingRequest([AUTH_TYPE["NO_AUTH"], AUTH_TYPE["GSSAPI"]])
        data = write_greeting_request(event)
        expected_data = struct.pack("!BB2B", 0x5, 0x2, 0x00, 0x01)
        self.assertEqual(data, expected_data)

    def test_greeting_request_socks4(self):
        event = Socks4Request(1, "127.0.0.1", 5580, "Johnny")
        data = write_greeting_request(event)

        expected_data = struct.pack("!BBH4B6sB", 0x4, 0x1, 5580, 127, 0, 0, 1, "Johnny".encode("ascii"), 0)
        self.assertEqual(data, expected_data)

        event = Socks4Request(1, "0.0.0.1", 5580, "Johnny", "www.google.com")
        data = write_greeting_request(event)

        expected_data = struct.pack(
            "!BBH4B6sB14sB", 0x4, 0x1, 5580, 0, 0, 0, 1, "Johnny".encode("ascii"), 0, "www.google.com".encode("idna"), 0)
        self.assertEqual(data, expected_data)

    def test_greeting_response_socks5(self):
        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        data = write_greeting_response(event)
        expected_data = struct.pack("!BB", 0x5, 0x0)
        self.assertEqual(data, expected_data)

    def test_greeting_response_socks4(self):
        event = Socks4Response(0x5a, "127.0.0.1", 5580)
        data = write_greeting_response(event)

        expected_data = struct.pack("!BBH4B", 0, 0x5a, 5580, 127, 0, 0, 1)
        self.assertEqual(data, expected_data)

    def test_write_request_ipv4(self):
        event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = write_request(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(data, expected_data)

    def test_write_request_ipv6(self):
        event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV6"], u"::1", 8080)
        data = write_request(event)
        expected_data = struct.pack("!BBxB8HH",
                                    0x5, 0x1, 0x4,
                                    0, 0, 0, 0, 0, 0, 0, 1,
                                    8080)
        self.assertEqual(data, expected_data)

    def test_write_request_hostname(self):
        event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["DOMAINNAME"], u"google.com", 8080)
        data = write_request(event)
        expected_data = struct.pack("!BBxBB10sH", 0x5, 0x1, 0x3, 10, b"google.com", 8080)
        self.assertEqual(data, expected_data)

    def test_write_response_ipv4(self):
        event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = write_response(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(data, expected_data)

    def test_write_response_ipv6(self):
        event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV6"], u"::1", 8080)
        data = write_response(event)
        expected_data = struct.pack("!BBxB8HH",
                                    0x5, 0x0, 0x4,
                                    0, 0, 0, 0, 0, 0, 0, 1,
                                    8080)
        self.assertEqual(data, expected_data)

    def test_write_response_hostname(self):
        event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["DOMAINNAME"], u"google.com", 8080)
        data = write_response(event)
        expected_data = struct.pack("!BBxBB10sH", 0x5, 0x0, 0x3, 10, b"google.com", 8080)
        self.assertEqual(data, expected_data)
