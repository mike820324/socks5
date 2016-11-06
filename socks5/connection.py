from __future__ import absolute_import, division, print_function, unicode_literals

from transitions import Machine

from socks5.exception import ProtocolError
from socks5.define import AUTH_TYPE
from socks5 import _reader as reader
from socks5 import _writer as writer


class _ClientConnection(object):
    states = [
        'init',
        'greeting_request',
        'greeting_response',
        'auth_inprogress',
        'request',
        'response',
        'end'
    ]

    def __init__(self):
        self._buffer = b""
        self.machine = Machine(
            model=self, states=self.states, initial='init')
        self._version = 0xff
        self._auth_methods = [AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"]]
        self._addr_type = 0xff
        self._addr = 0
        self._port = 0

    def initiate_connection(self):
        self.machine.set_state("greeting_request")

    def auth_end(self):
        if self.state != "auth_inprogress":
            raise ProtocolError("ClientConnection.auth_end: Incorrect state {}".format(self.state))
        self.machine.set_state("request")

    def recv(self, data):
        if self.state not in ("greeting_response", "response"):
            raise ProtocolError("ClientConnection.recv: Incorrect state {}".format(self.state))

        self._buffer += data
        _reader = getattr(reader, "read_" + self.state)
        current_event = _reader(self._buffer)

        if current_event == 'NeedMoreData':
            return current_event
        else:
            self._buffer = b""

        if self.state == 'greeting_response':
            if current_event == "GreetingResponse":
                if self._version != 5 or current_event.auth_type not in self._auth_methods:
                    raise ProtocolError("ClientConnection:recv: receive incorrect data from server")

                if current_event.auth_type == AUTH_TYPE["NO_AUTH"]:
                    self.machine.set_state('request')
                elif current_event.auth_type == AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"]:
                    self.machine.set_state("end")
                else:
                    self.machine.set_state('auth_inprogress')

            elif current_event == "Socks4Response":
                if self._version != 4 or self._port != current_event.port:
                    raise ProtocolError("ClientConnection:recv: receive incorrect data from server")

                self.machine.set_state("end")

        elif self.state == 'response':
            if (self._version != 5 or
               self._addr_type != current_event.atyp or
               self._addr != current_event.addr or
               self._port != current_event.port):
                    raise ProtocolError("ClientConnection:recv: receive incorrect data from server")
            self.machine.set_state('end')

        return current_event

    def send(self, event):
        if self.state not in ("greeting_request", "request"):
            raise ProtocolError("ClientConnection.send: Incorrect state {}".format(self.state))

        if self.state == "greeting_request" and (event != "GreetingRequest" and event != "Socks4Request"):
            raise ProtocolError("ClientConnection.send: Incorrect event {0} in state: {1}".format(event, self.state))

        if self.state == "request" and event != "Request":
            raise ProtocolError("ClientConnection.send: Incorrect event {0} in state: {1}".format(event, self.state))

        _writer = getattr(writer, "write_" + self.state)
        if self.state == "greeting_request":
            if event == "GreetingRequest":
                self._version = 5
                self._auth_methods.extend(event.methods)
            elif event == "Socks4Request":
                self._version = 4
                self._port = event.port
            self.machine.set_state("greeting_response")

        if self.state == "request":
            self._addr_type = event.atyp
            self._addr = event.addr
            self._port = event.port
            self.machine.set_state("response")

        return _writer(event)


class _ServerConnection(object):
    states = [
        'init',
        'greeting_request',
        'greeting_response',
        'auth_inprogress',
        'request',
        'response',
        'end'
    ]

    def __init__(self):
        self._buffer = b""
        self.machine = Machine(
            model=self, states=self.states, initial='init')

        self._version = 0xff
        self._auth_methods = [AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"]]
        self._addr_type = 0xff
        self._addr = 0
        self._port = 0

    def initiate_connection(self):
        self.machine.set_state("greeting_request")

    def auth_end(self):
        if self.state != "auth_inprogress":
            raise ProtocolError("ServerConnection.auth_end: Incorrect state {}".format(self.state))
        self.machine.set_state("request")

    def recv(self, data):
        if self.state not in ("greeting_request", "request"):
            raise ProtocolError("ServerConnection.recv: Incorrect state {}".format(self.state))

        self._buffer += data
        _reader = getattr(reader, "read_" + self.state)
        current_event = _reader(self._buffer)

        if current_event == "NeedMoreData":
            return current_event
        else:
            self._buffer = b""

        if self.state == 'greeting_request':
            if current_event == "GreetingRequest":
                self._version = 5
                self._auth_methods.extend(current_event.methods)
            elif current_event == "Socks4Request":
                self._version = 4
                self._port = current_event.port

            self.machine.set_state('greeting_response')

        elif self.state == 'request':
            if current_event == "Request":
                self._addr_type = current_event.atyp
                self._addr = current_event.addr
                self._port = current_event.port

            self.machine.set_state('response')

        self._buffer = b""
        return current_event

    def send(self, event):
        if self.state not in ("greeting_response", "response"):
            raise ProtocolError("ServerConnection.recv: Incorrect state {}".format(self.state))

        if self.state == "greeting_response" and (event != "GreetingResponse" and event != "Socks4Response"):
            raise ProtocolError("ServerConnection.send: Incorrect event {0} in state: {1}".format(event, self.state))

        if self.state == "response" and event != "Response":
            raise ProtocolError("ServerConnection.send: Incorrect event {0} in state: {1}".format(event, self.state))

        _writer = getattr(writer, "write_" + self.state)
        if self.state == "greeting_response":
            if event == "GreetingResponse":
                if (self._version != 5 or
                   event.auth_type not in self._auth_methods):
                    raise ProtocolError("ServerConnection.send: incorrect event from user.")

                if event.auth_type == AUTH_TYPE["NO_AUTH"]:
                    self.machine.set_state("request")
                elif event.auth_type == AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"]:
                    self.machine.set_state("end")
                else:
                    self.machine.set_state("auth_inprogress")

            elif event == "Socks4Response":
                if self._version != 4 or self._port != event.port:
                    raise ProtocolError("ServerConnection.send: incorrect event from user")

                self.machine.set_state("end")

        if self.state == "response":
            if (self._version != 5 or
               self._addr_type != event.atyp or
               self._addr != event.addr or
               self._port != event.port):
                    raise ProtocolError("ServerConnection.send: receive incorrect data from server")
            self.machine.set_state("end")
        return _writer(event)


class Connection(object):
    def __init__(self, our_role):
        if our_role == "server":
            self._conn = _ServerConnection()
        elif our_role == "client":
            self._conn = _ClientConnection()
        else:
            raise ValueError("unknonw role {}".format(our_role))

    def initiate_connection(self):
        self._conn.initiate_connection()

    def auth_end(self):
        self._conn.auth_end()

    def recv(self, data):
        return self._conn.recv(data)

    def send(self, event):
        return self._conn.send(event)
