from __future__ import absolute_import, division, print_function, unicode_literals
import unittest

from socks5.events import (
    NeedMoreData,
    GreetingRequest, GreetingResponse,
    AuthRequest, AuthResponse,
    Request, Response)

from socks5.define import (
    VERSION, REQ_COMMAND, AUTH_TYPE,
    RESP_STATUS, ADDR_TYPE)


class TestEvents(unittest.TestCase):
    def test_need_more_data(self):
        event = NeedMoreData()
        self.assertEqual(event, "NeedMoreData")

    def test_greeting_request(self):
        event = GreetingRequest(VERSION, 1, [AUTH_TYPE["NO_AUTH"]])
        self.assertEqual(event, "GreetingRequest")
        self.assertEqual(event.version, VERSION)
        self.assertEqual(event.nmethod, 1)
        self.assertEqual(event.methods, [AUTH_TYPE["NO_AUTH"]])

    def test_greeting_request_incorrect_version(self):
        with self.assertRaises(ValueError):
            GreetingRequest(0x4, 1, [AUTH_TYPE["NO_AUTH"]])

    def test_greeting_request_incorrect_methods_type(self):
        with self.assertRaises(ValueError):
            GreetingRequest(VERSION, 1, AUTH_TYPE["NO_AUTH"])

    def test_greeting_request_methods_num_mismatch(self):
        with self.assertRaises(ValueError):
            GreetingRequest(VERSION, 2, [AUTH_TYPE["NO_AUTH"]])

    def test_greeting_response(self):
        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        self.assertEqual(event, "GreetingResponse")
        self.assertEqual(event.version, VERSION)
        self.assertEqual(event.auth_type, AUTH_TYPE["NO_AUTH"])

    def test_greeting_response_incorrect_version(self):
        with self.assertRaises(ValueError):
            GreetingResponse(0x4, AUTH_TYPE["NO_AUTH"])

    def test_auth_request(self):
        event = AuthRequest(VERSION, "user", "password")
        self.assertEqual(event, "AuthRequest")
        self.assertEqual(event.version, VERSION)
        self.assertEqual(event.username, "user")
        self.assertEqual(event.password, "password")

    def test_auth_request_incorrect_version(self):
        with self.assertRaises(ValueError):
            AuthRequest(0x04, "user", "password")

    def test_auth_request_username_too_long(self):
        with self.assertRaises(ValueError):
            AuthRequest(VERSION, "a" * 256, "password")

    def test_auth_request_password_too_long(self):
        with self.assertRaises(ValueError):
            AuthRequest(VERSION, "user", "a" * 256)

    def test_auth_response(self):
        event = AuthResponse(VERSION, RESP_STATUS["SUCCESS"])
        self.assertEqual(event, "AuthResponse")
        self.assertEqual(event.version, VERSION)
        self.assertEqual(event.status, RESP_STATUS["SUCCESS"])

    def test_auth_response_incorrect_version(self):
        with self.assertRaises(ValueError):
            AuthResponse(0x04, RESP_STATUS["SUCCESS"])

    def test_request(self):
        event = Request(VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        self.assertEqual(event, "Request")
        self.assertEqual(event.version, VERSION)
        self.assertEqual(event.cmd, REQ_COMMAND["CONNECT"])
        self.assertEqual(event.atyp, ADDR_TYPE["IPV4"])
        self.assertEqual(event.addr, u"127.0.0.1")
        self.assertEqual(event.port, 8080)

    def test_request_incorrect_version(self):
        with self.assertRaises(ValueError):
            Request(
                0x04, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)

    def test_request_unsupported_cmd_type(self):
        with self.assertRaises(ValueError):
            Request(
                VERSION, 0xff, ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)

    def test_request_unsupported_addr_type(self):
        with self.assertRaises(ValueError):
            Request(
                VERSION, REQ_COMMAND["CONNECT"], 0xff, u"127.0.0.1", 8080)

    def test_request_incorrect_ipv4_format(self):
        with self.assertRaises(ValueError):
            Request(
                VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1.1", 8080)

    def test_request_incorrect_ipv6_format(self):
        with self.assertRaises(ValueError):
            Request(
                VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV6"], u":::::::1", 8080)

    def test_response(self):
        event = Response(VERSION, RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        self.assertEqual(event, "Response")
        self.assertEqual(event.version, VERSION)
        self.assertEqual(event.status, RESP_STATUS["SUCCESS"])
        self.assertEqual(event.atyp, ADDR_TYPE["IPV4"])
        self.assertEqual(event.addr, u"127.0.0.1")
        self.assertEqual(event.port, 8080)

    def test_response_incorrect_version(self):
        with self.assertRaises(ValueError):
            Response(
                0x04, RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)

    def test_response_incorrect_status_code(self):
        with self.assertRaises(ValueError):
            Response(
                VERSION, 0xff, ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)

    def test_response_unsupported_addr_type(self):
        with self.assertRaises(ValueError):
            Response(
                VERSION, RESP_STATUS["SUCCESS"], 0xff, u"127.0.0.1", 8080)

    def test_response_incorrect_ipv4_format(self):
        with self.assertRaises(ValueError):
            Response(
                VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1.1", 8080)

    def test_response_incorrect_ipv6_format(self):
        with self.assertRaises(ValueError):
            Response(
                VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV6"], u":::::::1", 8080)
