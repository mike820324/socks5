from __future__ import absolute_import, division, print_function, unicode_literals

from transitions import Machine

from socks5.exception import ProtocolError
from ._reader import read_auth_request, read_auth_response
from ._writer import write_auth_request, write_auth_response


class _ClientConnection(object):
    states = [
        'init',
        'auth_request',
        'auth_response',
        'end'
    ]

    def __init__(self):
        self._buffer = b""
        self.machine = Machine(
            model=self, states=self.states, initial='init')

    def initiate_connection(self):
        self.machine.set_state("auth_request")

    def recv(self, data):
        if self.state != "auth_response":
            raise ProtocolError("ClientConnection.recv: Incorrect state {}".format(self.state))

        self._buffer += data
        current_event = read_auth_response(self._buffer)

        if current_event == 'NeedMoreData':
            return current_event
        else:
            self._buffer = b""

        if self.state == 'auth_response':
            self.machine.set_state('end')

        return current_event

    def send(self, event):
        if self.state != "auth_request":
            raise ProtocolError("ClientConnection.send: Incorrect state {}".format(self.state))

        if self.state == "auth_request" and event != "AuthRequest":
            raise ProtocolError("ClientConnection.send: Incorrect event {0} in state: {1}".format(event, self.state))

        if self.state == "auth_request":
            self.machine.set_state("auth_response")

        return write_auth_request(event)


class _ServerConnection(object):
    states = [
        'init',
        'auth_request',
        'auth_response',
        'end'
    ]

    def __init__(self):
        self._buffer = b""
        self.machine = Machine(
            model=self, states=self.states, initial='init')

    def initiate_connection(self):
        self.machine.set_state("auth_request")

    def recv(self, data):
        if self.state != "auth_request":
            raise ProtocolError("ServerConnection.recv: Incorrect state {}".format(self.state))

        self._buffer += data
        current_event = read_auth_request(self._buffer)

        if current_event == "NeedMoreData":
            return current_event
        else:
            self._buffer = b""

        if self.state == 'auth_request':
            self.machine.set_state('auth_response')

        return current_event

    def send(self, event):
        if self.state != "auth_response":
            raise ProtocolError("ServerConnection.recv: Incorrect state {}".format(self.state))

        if self.state == "auth_response" and event != "AuthResponse":
            raise ProtocolError("ServerConnection.send: Incorrect event {0} in state: {1}".format(event, self.state))

        if self.state == "auth_response":
            self.machine.set_state("end")
        return write_auth_response(event)


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

    def recv(self, data):
        return self._conn.recv(data)

    def send(self, event):
        return self._conn.send(event)
