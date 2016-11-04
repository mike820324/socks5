from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import struct
import ipaddress

from socks5.exception import ProtocolError
from socks5.connection import Connection

from socks5.events import (
    Socks4Request, Socks4Response,
    GreetingRequest, GreetingResponse,
    UsernamePasswordAuthRequest, UsernamePasswordAuthResponse,
    Request, Response)

from socks5.define import (
    REQ_COMMAND, AUTH_TYPE,
    RESP_STATUS, ADDR_TYPE)


class TestServerConnection(unittest.TestCase):
    def test_initiate_connection(self):
        conn = Connection(our_role="server")
        self.assertEqual(conn._conn.state, "init")

        conn.initiate_connection()
        self.assertEqual(conn._conn.state, "greeting_request")

    def test_incorrect_role(self):
        with self.assertRaises(ValueError):
            Connection(our_role="yoyo")

    def test_send_greeting_response_socks4(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_response")

        event = Socks4Response(0x5a, "127.0.0.1", 5580)
        data = conn.send(event)
        expected_data = struct.pack("!BBH4B", 0, 0x5a, 5580, 127, 0, 0, 1)

        self.assertEqual(conn._conn.state, "end")
        self.assertEqual(data, expected_data)

    def test_send_greeting_response_no_auth(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_response")

        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        data = conn.send(event)
        expected_data = struct.pack("!BB", 0x5, 0x0)

        self.assertEqual(conn._conn.state, "request")
        self.assertEqual(data, expected_data)

    def test_send_greeting_response_with_rfc1929_auth(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_response")

        event = GreetingResponse(AUTH_TYPE["USERNAME_PASSWD"])
        data = conn.send(event)
        expected_data = struct.pack("!BB", 0x5, 0x2)

        self.assertEqual(conn._conn.state, "rfc1929_auth_request")
        self.assertEqual(data, expected_data)

    def test_send_greeting_response_with_unsupported_auth(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_response")
        event = GreetingResponse(AUTH_TYPE["GSSAPI"])

        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_greeting_response_incorrect_event(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_response")

        event = GreetingRequest((AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_rfc1929_auth_response(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("rfc1929_auth_response")

        event = UsernamePasswordAuthResponse(RESP_STATUS["SUCCESS"])
        data = conn.send(event)
        expected_data = struct.pack("!BB", 0x1, 0x0)
        self.assertEqual(conn._conn.state, "request")
        self.assertEqual(data, expected_data)

    def test_send_rfc1929_auth_response_incorrect_event(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("rfc1929_auth_response")

        event = GreetingRequest((AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_response(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("response")

        event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = conn.send(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(conn._conn.state, "end")
        self.assertEqual(data, expected_data)

    def test_send_response_incorrect_event(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("response")

        event = GreetingRequest((AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_greeting_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_request")

        event = GreetingRequest((AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_rfc1929_auth_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("rfc1929_auth_request")

        event = GreetingRequest((AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("request")

        event = GreetingRequest((AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_recv_need_more_data(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_request")

        raw_data = b"\x05"
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "greeting_request")
        self.assertEqual(event, "NeedMoreData")

    def test_recv_in_greeting_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_request")

        raw_data = struct.pack("!BB2B", 0x5, 0x2, 0x00, 0x01)
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "greeting_response")
        self.assertEqual(event, "GreetingRequest")
        self.assertEqual(event.nmethod, 2)
        self.assertIn(0, event.methods)
        self.assertIn(1, event.methods)

    def test_recv_in_greeting_request_socks4(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_request")
        raw_data = struct.pack("!BBH4B6sB", 0x4, 0x1, 5580, 127, 0, 0, 1, "Johnny".encode("ascii"), 0)
        event = conn.recv(raw_data)
        self.assertEqual(event, "Socks4Request")
        self.assertEqual(event.cmd, 1)
        self.assertEqual(event.port, 5580)
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(event.name, "Johnny")

    def test_recv_in_rfc1929_auth_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("rfc1929_auth_request")

        raw_data = struct.pack("!BB4sB8s", 0x1, 0x4, b"user", 0x8, b"password")
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "rfc1929_auth_response")
        self.assertEqual(event, "UsernamePasswordAuthRequest")
        self.assertEqual(event.username, "user")
        self.assertEqual(event.password, "password")

    def test_recv_in_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("request")

        raw_data = struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080)
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "response")
        self.assertEqual(event, "Request")
        self.assertEqual(event.cmd, 1)
        self.assertEqual(event.atyp, 1)
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(event.port, 8080)

    def test_recv_incorrect_state_greeting_response(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("greeting_response")

        with self.assertRaises(ProtocolError):
            conn.recv(b"")

    def test_recv_incorrect_state_rfc1929_auth_response(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("rfc1929_auth_response")

        with self.assertRaises(ProtocolError):
            conn.recv(b"")

    def test_recv_incorrect_state_response(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("response")

        with self.assertRaises(ProtocolError):
            conn.recv(b"")


class TestClientConnection(unittest.TestCase):
    def test_initiate_connection(self):
        conn = Connection(our_role="client")
        self.assertEqual(conn._conn.state, "init")

        conn.initiate_connection()
        self.assertEqual(conn._conn.state, "greeting_request")

    def test_send_in_greeting_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_request")

        event = GreetingRequest((AUTH_TYPE["NO_AUTH"], ))
        data = conn.send(event)
        expected_data = struct.pack("!BBB", 0x5, 0x1, 0x00)
        self.assertEqual(conn._conn.state, "greeting_response")
        self.assertEqual(data, expected_data)

    def test_send_in_greeting_request_socks4(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_request")

        event = Socks4Request(1, "127.0.0.1", 5580, "Johnny")
        data = conn.send(event)
        expected_data = struct.pack("!BBH4B6sB", 0x4, 0x1, 5580, 127, 0, 0, 1, "Johnny".encode("ascii"), 0)
        self.assertEqual(conn._conn.state, "greeting_response")
        self.assertEqual(data, expected_data)

    def test_send_in_greeting_request_incorrect_event(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_request")

        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_in_rfc1929_auth_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("rfc1929_auth_request")

        event = UsernamePasswordAuthRequest("user", "password")
        data = conn.send(event)
        expected_data = struct.pack("!BB4sB8s", 0x1, 0x4, b"user", 0x8, b"password")
        self.assertEqual(conn._conn.state, "rfc1929_auth_response")
        self.assertEqual(data, expected_data)

    def test_send_in_rfc1929_auth_request_incorrect_event(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("rfc1929_auth_request")

        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_in_request_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("request")

        event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = conn.send(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(conn._conn.state, "response")
        self.assertEqual(data, expected_data)

    def test_send_in_request_request_incorrect_event(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("request")

        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_greeting_response(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_response")

        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_rfc1929_auth_response(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("rfc1929_auth_response")

        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_response(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("response")

        event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_recv_need_more_data(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_response")

        raw_data = b"\x05"
        event = conn.recv(raw_data)

        self.assertEqual(conn._conn.state, "greeting_response")
        self.assertEqual(event, "NeedMoreData")

    def test_recv_in_greeting_response_no_auth(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_response")

        raw_data = struct.pack("!BB", 0x5, 0x0)
        event = conn.recv(raw_data)

        self.assertEqual(conn._conn.state, "request")
        self.assertEqual(event, "GreetingResponse")
        self.assertEqual(event.auth_type, 0)

    def test_recv_in_greeting_response_socks4(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_response")

        raw_data = struct.pack("!BBH4B", 0, 0x5a, 5580, 127, 0, 0, 1)
        event = conn.recv(raw_data)

        self.assertEqual(conn._conn.state, "end")
        self.assertEqual(event, "Socks4Response")
        self.assertEqual(event.status, 0x5a)
        self.assertEqual(event.port, 5580)
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))

    def test_recv_in_greeting_response_with_rfc1929_auth(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_response")

        raw_data = struct.pack("!BB", 0x5, 0x2)
        event = conn.recv(raw_data)

        self.assertEqual(conn._conn.state, "rfc1929_auth_request")
        self.assertEqual(event, "GreetingResponse")
        self.assertEqual(event.auth_type, 2)

    def test_recv_in_greeting_response_with_unsupported_auth(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_response")

        raw_data = struct.pack("!BB", 0x5, 0x1)
        with self.assertRaises(ProtocolError):
            conn.recv(raw_data)

    def test_recv_in_rfc1929_auth_response(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("rfc1929_auth_response")

        raw_data = struct.pack("!BB", 0x1, 0x0)
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "request")
        self.assertEqual(event, "UsernamePasswordAuthResponse")
        self.assertEqual(event.status, 0)

    def test_recv_in_response(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("response")

        raw_data = struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080)
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "end")
        self.assertEqual(event, "Response")
        self.assertEqual(event.status, 0)
        self.assertEqual(event.atyp, 1)
        self.assertEqual(event.addr, ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(event.port, 8080)

    def test_recv_incorrect_state_greeting_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("greeting_request")

        raw_data = b""
        with self.assertRaises(ProtocolError):
            conn.recv(raw_data)

    def test_recv_incorrect_state_rfc1929_auth_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("rfc1929_auth_request")

        raw_data = b""
        with self.assertRaises(ProtocolError):
            conn.recv(raw_data)

    def test_recv_incorrect_state_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("request")

        raw_data = b""
        with self.assertRaises(ProtocolError):
            conn.recv(raw_data)
