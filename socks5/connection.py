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
                if current_event.auth_type == AUTH_TYPE["NO_AUTH"]:
                    self.machine.set_state('request')
                elif current_event.auth_type == AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"]:
                    self.machine.set_state("end")
                else:
                    self.machine.set_state('auth_inprogress')

            elif current_event == "Socks4Response":
                self.machine.set_state("end")

        elif self.state == 'response':
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
            self.machine.set_state("greeting_response")

        if self.state == "request":
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
            self.machine.set_state('greeting_response')

        elif self.state == 'request':
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
                if event.auth_type == AUTH_TYPE["NO_AUTH"]:
                    self.machine.set_state("request")
                elif event.auth_type == AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"]:
                    self.machine.set_state("end")
                else:
                    self.machine.set_state("auth_inprogress")

            elif event == "Socks4Response":
                self.machine.set_state("end")

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

    def auth_end(self):
        self._conn.auth_end()

    def recv(self, data):
        return self._conn.recv(data)

    def send(self, event):
        return self._conn.send(event)
