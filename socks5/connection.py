from transitions import Machine
from define import AUTH_TYPE
from events import NeedMoreData, GreetingResponse, Response
from events import GreetingRequest, Request
from events import AuthRequest, AuthResponse
import reader
import writer


class ProtocolError(Exception):
    pass


class ClientConnection(object):
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

        self.set_state("end")

    def receive(self, data):
        try:
            self._buffer += data
            _reader = getattr(reader, "read_" + self.state)
            current_event = _reader(self._buffer)

        except reader.ParserError:
            return NeedMoreData()

        self._buffer = b""

        if self.state == 'greeting_response':
            if current_event.auth_type == AUTH_TYPE["NO_AUTH"]:
                self.machine.set_state('request')
            else:
                self.machine.set_state('auth_request')

        elif self.state == 'auth_response':
            self.machine.set_state('request')

        elif self.state == 'response':
            self.machine.set_state('end')

        else:
            raise ProtocolError

        return current_event

    def send(self, event):
        if self.state != "greeting_request" and self.state != "request" and self.state != "auth_request":
            raise ProtocolError

        if self.state == "greeting_request" and event != "GreetingRequest":
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

class ServerConnection(object):
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

        self.set_state("end")

    def receive(self, data):
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

        else:
            raise ProtocolError

        self._buffer = b""
        return current_event

    def send(self, event):
        if self.state != "greeting_response" and self.state != "response" and self.state != "auth_response":
            raise ProtocolError

        if self.state == "greeting_response" and event != "GreetingResponse":
            raise ProtocolError

        if self.state == "auth_response" and event != "AuthResponse":
            raise ProtocolError

        if self.state == "response" and event != "Response":
            raise ProtocolError

        _writer = getattr(writer, "write_" + self.state)
        if self.state == "greeting_response":
            if event.auth_type == AUTH_TYPE["NO_AUTH"]:
                self.machine.set_state("request")
            else:
                self.machine.set_state("auth_request")

        if self.state == "auth_response":
            self.machine.set_state("request")

        if self.state == "response":
            self.machine.set_state("end")

        return _writer(event)
