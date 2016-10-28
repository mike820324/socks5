import unittest
import struct

from socks5.connection import (
    ServerConnection, ClientConnection,
    ProtocolError)

from socks5.events import (
    NeedMoreData,
    GreetingRequest, GreetingResponse,
    AuthRequest, AuthResponse,
    Request, Response)

from socks5.define import (
    VERSION, REQ_COMMAND, AUTH_TYPE,
    RESP_STATUS, ADDR_TYPE)


class TestServerConnection(unittest.TestCase):
    def test_initiate_connection(self):
        conn = ServerConnection()
        self.assertEqual(conn.state, "init")

        conn.initiate_connection()
        self.assertEqual(conn.state, "greeting_request")

    def test_end_connection(self):
        conn = ServerConnection()
        conn.machine.set_state("response")

        conn.end_connection()
        self.assertEqual(conn.state, "end")

    def test_end_connection_incorrect_state(self):
        conn = ServerConnection()
        with self.assertRaises(ProtocolError):
            conn.end_connection()

    def test_send_greeting_response_no_auth(self):
        conn = ServerConnection()
        conn.machine.set_state("greeting_response")

        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        data = conn.send(event)
        expected_data = struct.pack("!BB", 0x5, 0x0)

        self.assertEqual(conn.state, "request")
        self.assertEqual(data, expected_data)

    def test_send_greeting_response_with_auth(self):
        conn = ServerConnection()
        conn.machine.set_state("greeting_response")

        event = GreetingResponse(VERSION, AUTH_TYPE["USERNAME_PASSWD"])
        data = conn.send(event)
        expected_data = struct.pack("!BB", 0x5, 0x2)

        self.assertEqual(conn.state, "auth_request")
        self.assertEqual(data, expected_data)

    def test_send_greeting_response_incorrect_event(self):
        conn = ServerConnection()
        conn.machine.set_state("greeting_response")

        event = GreetingRequest(VERSION, 1, (AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_auth_response(self):
        conn = ServerConnection()
        conn.machine.set_state("auth_response")

        event = AuthResponse(VERSION, RESP_STATUS["SUCCESS"])
        data = conn.send(event)
        expected_data = struct.pack("!BB", 0x5, 0x0)
        self.assertEqual(conn.state, "request")
        self.assertEqual(data, expected_data)

    def test_send_auth_response_incorrect_event(self):
        conn = ServerConnection()
        conn.machine.set_state("auth_response")

        event = GreetingRequest(VERSION, 1, (AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_response(self):
        conn = ServerConnection()
        conn.machine.set_state("response")

        event = Response(VERSION, RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = conn.send(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(conn.state, "end")
        self.assertEqual(data, expected_data)

    def test_send_response_incorrect_event(self):
        conn = ServerConnection()
        conn.machine.set_state("response")

        event = GreetingRequest(VERSION, 1, (AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_greeting_request(self):
        conn = ServerConnection()
        conn.machine.set_state("greeting_request")

        event = GreetingRequest(VERSION, 1, (AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_auth_request(self):
        conn = ServerConnection()
        conn.machine.set_state("auth_request")

        event = GreetingRequest(VERSION, 1, (AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_request(self):
        conn = ServerConnection()
        conn.machine.set_state("request")

        event = GreetingRequest(VERSION, 1, (AUTH_TYPE["NO_AUTH"], ))
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_recv_need_more_data(self):
        conn = ServerConnection()
        conn.machine.set_state("greeting_request")

        raw_data = b"\x05"
        event = conn.receive(raw_data)
        self.assertEqual(conn.state, "greeting_request")
        self.assertEqual(event, "NeedMoreData")

    def test_recv_in_greeting_request(self):
        conn = ServerConnection()
        conn.machine.set_state("greeting_request")

        raw_data = struct.pack("!BB2B", 0x5, 0x2, 0x00, 0x01)
        event = conn.receive(raw_data)
        self.assertEqual(conn.state, "greeting_response")
        self.assertEqual(event, "GreetingRequest")
        self.assertEqual(event.version, 5)
        self.assertEqual(event.nmethod, 2)
        self.assertEqual(event.methods, (0, 1))

    def test_recv_in_auth_request(self):
        conn = ServerConnection()
        conn.machine.set_state("auth_request")

        raw_data = struct.pack("!BB4sB8s", 0x5, 0x4, b"user", 0x8, b"password")
        event = conn.receive(raw_data)
        self.assertEqual(conn.state, "auth_response")
        self.assertEqual(event, "AuthRequest")
        self.assertEqual(event.version, 5)
        self.assertEqual(event.username, "user")
        self.assertEqual(event.password, "password")

    def test_recv_in_request(self):
        conn = ServerConnection()
        conn.machine.set_state("request")

        raw_data = struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080)
        event = conn.receive(raw_data)
        self.assertEqual(conn.state, "response")
        self.assertEqual(event, "Request")
        self.assertEqual(event.version, 5)
        self.assertEqual(event.cmd, 1)
        self.assertEqual(event.atyp, 1)
        self.assertEqual(event.addr, "127.0.0.1")
        self.assertEqual(event.port, 8080)

    def test_recv_incorrect_state_greeting_response(self):
        conn = ServerConnection()
        conn.machine.set_state("greeting_response")

        with self.assertRaises(ProtocolError):
            conn.receive(b"")

    def test_recv_incorrect_state_auth_response(self):
        conn = ServerConnection()
        conn.machine.set_state("auth_response")

        with self.assertRaises(ProtocolError):
            conn.receive(b"")

    def test_recv_incorrect_state_response(self):
        conn = ServerConnection()
        conn.machine.set_state("response")

        with self.assertRaises(ProtocolError):
            conn.receive(b"")


class TestClientConnection(unittest.TestCase):
    def test_initiate_connection(self):
        conn = ClientConnection()
        self.assertEqual(conn.state, "init")

        conn.initiate_connection()
        self.assertEqual(conn.state, "greeting_request")

    def test_end_connection(self):
        conn = ClientConnection()
        conn.machine.set_state("response")

        conn.end_connection()
        self.assertEqual(conn.state, "end")

    def test_end_connection_incorrect_state(self):
        conn = ClientConnection()
        with self.assertRaises(ProtocolError):
            conn.end_connection()

    def test_send_in_greeting_request(self):
        conn = ClientConnection()
        conn.machine.set_state("greeting_request")

        event = GreetingRequest(VERSION, 1, (AUTH_TYPE["NO_AUTH"], ))
        data = conn.send(event)
        expected_data = struct.pack("!BBB", 0x5, 0x1, 0x00)
        self.assertEqual(conn.state, "greeting_response")
        self.assertEqual(data, expected_data)

    def test_send_in_greeting_request_incorrect_event(self):
        conn = ClientConnection()
        conn.machine.set_state("greeting_request")

        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_in_auth_request(self):
        conn = ClientConnection()
        conn.machine.set_state("auth_request")

        event = AuthRequest(VERSION, "user", "password")
        data = conn.send(event)
        expected_data = struct.pack("!BB4sB8s", 0x5, 0x4, b"user", 0x8, b"password")
        self.assertEqual(conn.state, "auth_response")
        self.assertEqual(data, expected_data)

    def test_send_in_auth_request_incorrect_event(self):
        conn = ClientConnection()
        conn.machine.set_state("auth_request")

        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_in_request_request(self):
        conn = ClientConnection()
        conn.machine.set_state("request")

        event = Request(VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], u"127.0.0.1", 8080)
        data = conn.send(event)
        expected_data = struct.pack("!BBxB4BH", 0x5, 0x1, 0x1, 127, 0, 0, 1, 8080)
        self.assertEqual(conn.state, "response")
        self.assertEqual(data, expected_data)

    def test_send_in_request_request_incorrect_event(self):
        conn = ClientConnection()
        conn.machine.set_state("request")

        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_greeting_response(self):
        conn = ClientConnection()
        conn.machine.set_state("greeting_response")

        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_auth_response(self):
        conn = ClientConnection()
        conn.machine.set_state("auth_response")

        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_send_incorrect_state_response(self):
        conn = ClientConnection()
        conn.machine.set_state("response")

        event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
        with self.assertRaises(ProtocolError):
            conn.send(event)

    def test_recv_need_more_data(self):
        conn = ClientConnection()
        conn.machine.set_state("greeting_response")

        raw_data = b"\x05"
        event = conn.receive(raw_data)

        self.assertEqual(conn.state, "greeting_response")
        self.assertEqual(event, "NeedMoreData")

    def test_recv_in_greeting_response_no_auth(self):
        conn = ClientConnection()
        conn.machine.set_state("greeting_response")

        raw_data = struct.pack("!BB", 0x5, 0x0)
        event = conn.receive(raw_data)

        self.assertEqual(conn.state, "request")
        self.assertEqual(event, "GreetingResponse")
        self.assertEqual(event.version, 5)
        self.assertEqual(event.auth_type, 0)

    def test_recv_in_greeting_response_with_auth(self):
        conn = ClientConnection()
        conn.machine.set_state("greeting_response")

        raw_data = struct.pack("!BB", 0x5, 0x1)
        event = conn.receive(raw_data)

        self.assertEqual(conn.state, "auth_request")
        self.assertEqual(event, "GreetingResponse")
        self.assertEqual(event.version, 5)
        self.assertEqual(event.auth_type, 1)

    def test_recv_in_auth_response(self):
        conn = ClientConnection()
        conn.machine.set_state("auth_response")

        raw_data = struct.pack("!BB", 0x5, 0x0)
        event = conn.receive(raw_data)
        self.assertEqual(conn.state, "request")
        self.assertEqual(event, "AuthResponse")
        self.assertEqual(event.version, 5)
        self.assertEqual(event.status, 0)

    def test_recv_in_response(self):
        conn = ClientConnection()
        conn.machine.set_state("response")

        raw_data = struct.pack("!BBxB4BH", 0x5, 0x0, 0x1, 127, 0, 0, 1, 8080)
        event = conn.receive(raw_data)
        self.assertEqual(conn.state, "end")
        self.assertEqual(event, "Response")
        self.assertEqual(event.version, 5)
        self.assertEqual(event.status, 0)
        self.assertEqual(event.atyp, 1)
        self.assertEqual(event.addr, "127.0.0.1")
        self.assertEqual(event.port, 8080)

    def test_recv_incorrect_state_greeting_request(self):
        conn = ClientConnection()
        conn.machine.set_state("greeting_request")

        raw_data = b""
        with self.assertRaises(ProtocolError):
            conn.receive(raw_data)

    def test_recv_incorrect_state_auth_request(self):
        conn = ClientConnection()
        conn.machine.set_state("auth_request")

        raw_data = b""
        with self.assertRaises(ProtocolError):
            conn.receive(raw_data)

    def test_recv_incorrect_state_request(self):
        conn = ClientConnection()
        conn.machine.set_state("request")

        raw_data = b""
        with self.assertRaises(ProtocolError):
            conn.receive(raw_data)
