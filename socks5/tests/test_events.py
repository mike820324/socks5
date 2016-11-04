from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import ipaddress

from socks5.events import (
    NeedMoreData,
    Socks4Request, Socks4Response,
    GreetingRequest, GreetingResponse,
    AuthRequest, AuthResponse,
    Request, Response)

from socks5.define import (
    REQ_COMMAND, AUTH_TYPE,
    RESP_STATUS, ADDR_TYPE)


class TestEvents(unittest.TestCase):
    def test_need_more_data(self):
        event = NeedMoreData()
        self.assertEqual(event, "NeedMoreData")

    def test_socks4_request(self):
        event = Socks4Request(1, "127.0.0.1", 5580, "Johnny")
        self.assertEqual(event.cmd, 1)
        self.assertEqual(event.port, 5580)
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(event.name, "Johnny")
        self.assertEqual(event.domainname, "")

        event = Socks4Request(1, "127.0.0.1", 5580, "Johnny", "www.google.com")
        self.assertEqual(event.cmd, 1)
        self.assertEqual(event.port, 5580)
        self.assertEqual(event.addr, ipaddress.IPv4Address("0.0.0.1"))
        self.assertEqual(event.name, "Johnny")
        self.assertEqual(event.domainname, "www.google.com")

    def test_socks4_request_domainname_not_specified(self):
        with self.assertRaises(ValueError):
            Socks4Request(1, "0.0.0.1", 5580, "Johnny")

    def test_socks4_request_unsupported_cmd_type(self):
        with self.assertRaises(ValueError):
            Socks4Request(0, "127.0.0.1", 5580, "Johnny")

    def test_socks4_request_unsupported_addr_format(self):
        with self.assertRaises(ValueError):
            Socks4Request(1, "0.0.0.1.0", 5580, "Johnny")

    def test_socks4_request_unsupported_name_format(self):
        with self.assertRaises(ValueError):
            Socks4Request(1, "0.0.0.1", 5580, b"Johnny")

    def test_socks4_request_unsupported_domainname_format(self):
        with self.assertRaises(ValueError):
            Socks4Request(1, "0.0.0.1", 5580, "Johnny", b"www.google.com")

    def test_socks4_response(self):
        event = Socks4Response(0x5a, "127.0.0.1", 5580)
        self.assertEqual(event.status, 0x5a)
        self.assertEqual(event.port, 5580)
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))

    def test_socks4_response_unsupported_status_code(self):
        with self.assertRaises(ValueError):
            Socks4Response(0xff, "127.0.0.1", 5580)

    def test_socks4_response_unsupported_addr_format(self):
        with self.assertRaises(ValueError):
            Socks4Response(0xff, "127.0.0.1.1", 5580)

    def test_greeting_request(self):
        event = GreetingRequest([AUTH_TYPE["NO_AUTH"]])
        self.assertEqual(event, "GreetingRequest")
        self.assertEqual(event.nmethod, 1)
        self.assertEqual(event.methods, [AUTH_TYPE["NO_AUTH"]])

    def test_greeting_request_incorrect_methods_type(self):
        with self.assertRaises(ValueError):
            GreetingRequest(AUTH_TYPE["NO_AUTH"])

    def test_greeting_response(self):
        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        self.assertEqual(event, "GreetingResponse")
        self.assertEqual(event.auth_type, AUTH_TYPE["NO_AUTH"])

    def test_auth_request(self):
        event = AuthRequest("user", "password")
        self.assertEqual(event, "AuthRequest")
        self.assertEqual(event.username, "user")
        self.assertEqual(event.password, "password")

    def test_auth_request_username_too_long(self):
        with self.assertRaises(ValueError):
            AuthRequest("a" * 256, "password")

    def test_auth_request_password_too_long(self):
        with self.assertRaises(ValueError):
            AuthRequest("user", "a" * 256)

    def test_auth_request_incorrect_username_type(self):
        with self.assertRaises(ValueError):
            AuthRequest(b"user", "a")

    def test_auth_request_incorrect_password_type(self):
        with self.assertRaises(ValueError):
            AuthRequest("user", b"a")

    def test_auth_response(self):
        event = AuthResponse(RESP_STATUS["SUCCESS"])
        self.assertEqual(event, "AuthResponse")

        self.assertEqual(event.status, RESP_STATUS["SUCCESS"])

    def test_auth_response_failed_unsupported_status(self):
        with self.assertRaises(ValueError):
            AuthResponse(0xff)

    def test_request(self):
        event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], "127.0.0.1", 8080)
        self.assertEqual(event, "Request")

        self.assertEqual(event.cmd, REQ_COMMAND["CONNECT"])
        self.assertEqual(event.atyp, ADDR_TYPE["IPV4"])
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(event.port, 8080)

    def test_request_unsupported_cmd_type(self):
        with self.assertRaises(ValueError):
            Request(
                0xff, ADDR_TYPE["IPV4"], "127.0.0.1", 8080)

    def test_request_unsupported_addr_type(self):
        with self.assertRaises(ValueError):
            Request(
                REQ_COMMAND["CONNECT"], 0xff, "127.0.0.1", 8080)

    def test_request_incorrect_domainname_type(self):
        with self.assertRaises(ValueError):
            Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["DOMAINNAME"], b"www.google.com", 8080)

    def test_request_incorrect_ipv4_format(self):
        with self.assertRaises(ValueError):
            Request(
                REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], "127.0.0.1.1", 8080)

    def test_request_incorrect_ipv6_format(self):
        with self.assertRaises(ValueError):
            Request(
                REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV6"], ":::::::1", 8080)

    def test_response(self):
        event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], "127.0.0.1", 8080)
        self.assertEqual(event, "Response")

        self.assertEqual(event.status, RESP_STATUS["SUCCESS"])
        self.assertEqual(event.atyp, ADDR_TYPE["IPV4"])
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(event.port, 8080)

    def test_response_incorrect_status_code(self):
        with self.assertRaises(ValueError):
            Response(
                0xff, ADDR_TYPE["IPV4"], "127.0.0.1", 8080)

    def test_response_unsupported_addr_type(self):
        with self.assertRaises(ValueError):
            Response(
                RESP_STATUS["SUCCESS"], 0xff, "127.0.0.1", 8080)

    def test_response_incorrect_domainname_type(self):
        with self.assertRaises(ValueError):
            Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["DOMAINNAME"], b"www.google.com", 8080)

    def test_response_incorrect_ipv4_format(self):
        with self.assertRaises(ValueError):
            Response(
                REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], "127.0.0.1.1", 8080)

    def test_response_incorrect_ipv6_format(self):
        with self.assertRaises(ValueError):
            Response(
                REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV6"], ":::::::1", 8080)
