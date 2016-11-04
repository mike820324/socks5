from __future__ import absolute_import, division, print_function, unicode_literals

from transitions import Machine

from socks5.define import AUTH_TYPE
from socks5.events import NeedMoreData
from socks5 import reader
from socks5 import writer


class ProtocolError(Exception):
    pass


class _ClientConnection(object):
    states = [
        'init',
        'greeting_request',
        'greeting_response',
        'auth_request',
        'auth_response',
        'request',
        'response',
        'end'
    ]

    def __init__(self):
        self._buffer = b""
        self._current_event = None
        self.machine = Machine(
            model=self, states=self.states, initial='init')

    def initiate_connection(self):
        self.machine.set_state("greeting_request")

    def end_connection(self):
        if self.state != "response":
            raise ProtocolError

        self.machine.set_state("end")

    def recv(self, data):
        if self.state not in ("greeting_response", "auth_response", "response"):
            raise ProtocolError

        try:
            self._buffer += data
            _reader = getattr(reader, "read_" + self.state)
            current_event = _reader(self._buffer)

        except reader.ParserError:
            return NeedMoreData()

        self._buffer = b""

        if self.state == 'greeting_response':
            if current_event == "GreetingResponse":
                if current_event.auth_type == AUTH_TYPE["NO_AUTH"]:
                    self.machine.set_state('request')
                else:
                    self.machine.set_state('auth_request')
            elif current_event == "Socks4Response":
                self.machine.set_state("end")

        elif self.state == 'auth_response':
            self.machine.set_state('request')

        elif self.state == 'response':
            self.machine.set_state('end')

        return current_event

    def send(self, event):
        if self.state not in ("greeting_request", "auth_request", "request"):
            raise ProtocolError

        if self.state == "greeting_request" and (event != "GreetingRequest" and event != "Socks4Request"):
            raise ProtocolError

        if self.state == "auth_request" and event != "AuthRequest":
            raise ProtocolError

        if self.state == "request" and event != "Request":
            raise ProtocolError

        _writer = getattr(writer, "write_" + self.state)
        if self.state == "greeting_request":
            self.machine.set_state("greeting_response")

        if self.state == "auth_request":
            self.machine.set_state("auth_response")

        if self.state == "request":
            self.machine.set_state("response")

        return _writer(event)


class _ServerConnection(object):
    states = [
        'init',
        'greeting_request',
        'greeting_response',
        'auth_request',
        'auth_response',
        'request',
        'response',
        'end'
    ]

    def __init__(self):
        self._buffer = b""
        self._current_event = None
        self.machine = Machine(
            model=self, states=self.states, initial='init')

    def initiate_connection(self):
        self.machine.set_state("greeting_request")

    def end_connection(self):
        if self.state != "response":
            raise ProtocolError

        self.machine.set_state("end")

    def recv(self, data):
        if self.state not in ("greeting_request", "auth_request", "request"):
            raise ProtocolError

        try:
            self._buffer += data
            _reader = getattr(reader, "read_" + self.state)
            current_event = _reader(self._buffer)

        except reader.ParserError:
            return NeedMoreData()

        if self.state == 'greeting_request':
            self.machine.set_state('greeting_response')

        elif self.state == 'auth_request':
            self.machine.set_state('auth_response')

        elif self.state == 'request':
            self.machine.set_state('response')

        self._buffer = b""
        return current_event

    def send(self, event):
        if self.state not in ("greeting_response", "auth_response", "response"):
            raise ProtocolError

        if self.state == "greeting_response" and (event != "GreetingResponse" and event != "Socks4Response"):
            raise ProtocolError

        if self.state == "auth_response" and event != "AuthResponse":
            raise ProtocolError

        if self.state == "response" and event != "Response":
            raise ProtocolError

        _writer = getattr(writer, "write_" + self.state)
        if self.state == "greeting_response":
            if event == "GreetingResponse":
                if event.auth_type == AUTH_TYPE["NO_AUTH"]:
                    self.machine.set_state("request")
                else:
                    self.machine.set_state("auth_request")

            elif event == "Socks4Response":
                self.machine.set_state("end")

        if self.state == "auth_response":
            self.machine.set_state("request")

        if self.state == "response":
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

    def end_connection(self):
        self._conn.end_connection()

    def recv(self, data):
        return self._conn.recv(data)

    def send(self, event):
        return self._conn.send(event)
