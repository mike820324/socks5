from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import struct

from socks5.exception import ProtocolError
from socks5.auth.rfc1929 import Connection

from socks5.auth.rfc1929.events import AuthRequest, AuthResponse

from socks5.define import RESP_STATUS


class TestServerConnection(unittest.TestCase):
    def test_initiate_connection(self):
        conn = Connection(our_role="server")
        self.assertEqual(conn._conn.state, "init")

        conn.initiate_connection()
        self.assertEqual(conn._conn.state, "auth_request")

    def test_incorrect_role(self):
        with self.assertRaises(ValueError):
            Connection(our_role="yoyo")

    def test_recv_need_more_data(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("auth_request")

        raw_data = b"\x01"
        event = conn.recv(raw_data)

        self.assertEqual(conn._conn.state, "auth_request")
        self.assertEqual(event, "NeedMoreData")

    def test_send_auth_response(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("auth_response")

        event = AuthResponse(RESP_STATUS["SUCCESS"])
        data = conn.send(event)
        expected_data = struct.pack("!BB", 0x1, 0x0)
        self.assertEqual(conn._conn.state, "end")
        self.assertEqual(data, expected_data)

    def test_send_auth_response_incorrect_event(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("auth_response")

        event = AuthRequest("user", "passwd")
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_auth_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("auth_request")

        event = AuthResponse(0)
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_recv_in_auth_request(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("auth_request")

        raw_data = struct.pack("!BB4sB8s", 0x1, 0x4, b"user", 0x8, b"password")
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "auth_response")
        self.assertEqual(event, "AuthRequest")
        self.assertEqual(event.username, "user")
        self.assertEqual(event.password, "password")

    def test_recv_incorrect_state_auth_response(self):
        conn = Connection(our_role="server")
        conn._conn.machine.set_state("auth_response")

        with self.assertRaises(ProtocolError):
            conn.recv(b"")


class TestClientConnection(unittest.TestCase):
    def test_initiate_connection(self):
        conn = Connection(our_role="client")
        self.assertEqual(conn._conn.state, "init")

        conn.initiate_connection()
        self.assertEqual(conn._conn.state, "auth_request")

    def test_send_in_auth_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("auth_request")

        event = AuthRequest("user", "password")
        data = conn.send(event)
        expected_data = struct.pack("!BB4sB8s", 0x1, 0x4, b"user", 0x8, b"password")
        self.assertEqual(conn._conn.state, "auth_response")
        self.assertEqual(data, expected_data)

    def test_send_in_auth_request_incorrect_event(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("auth_request")

        event = AuthResponse(0)
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_auth_response(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("auth_response")

        event = AuthRequest("user", "passwd")
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_recv_need_more_data(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("auth_response")

        raw_data = b"\x01"
        event = conn.recv(raw_data)

        self.assertEqual(conn._conn.state, "auth_response")
        self.assertEqual(event, "NeedMoreData")

    def test_recv_in_auth_response(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("auth_response")

        raw_data = struct.pack("!BB", 0x1, 0x0)
        event = conn.recv(raw_data)
        self.assertEqual(conn._conn.state, "end")
        self.assertEqual(event, "AuthResponse")
        self.assertEqual(event.status, 0)

    def test_recv_incorrect_state_auth_request(self):
        conn = Connection(our_role="client")
        conn._conn.machine.set_state("auth_request")

        raw_data = b""
        with self.assertRaises(ProtocolError):
            conn.recv(raw_data)
