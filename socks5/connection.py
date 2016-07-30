from transitions import Machine
from parser import SocksParser, ParserError
from events import NeedMoreData, GreetingResponse, Response
from events import GreetingRequest, Request


class ProtocolError(Exception):
    pass


class ClientConnection(object):
    states = [
        'init',
        'greeting_request',
        'greeting_response',
        'request',
        'response',
        'end'
    ]

    def __init__(self):
        self._buffer = b""
        self._current_event = None
        self.machine = Machine(
            model=self, states=self.states, initial='init')

    def initialiate_connection(self):
        self.machine.set_state("greeting_request")

    def end_connection(self):
        if self.state != "response":
            raise ProtocolError

        self.set_state("end")

    def receive(self, data):
        self._buffer += data
        try:
            if self.state == 'greeting_response':
                current_event = SocksParser.parse_greeting_response(
                    self._buffer)
                self.machine.set_state('request')

            elif self.state == 'response':
                current_event = SocksParser.parse_response(self._buffer)
                self.machine.set_state('end')

            else:
                raise ProtocolError

            self._buffer = b""
        except ParserError:
            current_event = NeedMoreData()

        return current_event

    def send(self, event):
        if self.state != "greeting_request" and self.state != "request":
            raise ProtocolError

        if self.state == "greeting_request" and not isinstance(event, GreetingRequest):
            raise ProtocolError

        if self.state == "request" and not isinstance(event, Request):
            raise ProtocolError

        if self.state == "greeting_request":
            self.machine.set_state("greeting_response")

        if self.state == "request":
            self.machine.set_state("response")

        return event.get_raw_data()


class ServerConnection(object):
    states = [
        'init',
        'greeting_request',
        'greeting_response',
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
        self._buffer += data
        try:
            if self.state == 'greeting_request':
                current_event = SocksParser.parse_greeting_request(
                    self._buffer)
                self.machine.set_state('greeting_response')

            elif self.state == 'request':
                current_event = SocksParser.parse_request(self._buffer)
                self.machine.set_state('response')

            else:
                raise ProtocolError

            self._buffer = b""
        except ParserError:
            current_event = NeedMoreData()

        return current_event

    def send(self, event):
        if self.state != "greeting_response" and self.state != "response":
            raise ProtocolError

        if self.state == "greeting_response" and not isinstance(event, GreetingResponse):
            raise ProtocolError

        if self.state == "response" and not isinstance(event, Response):
            raise ProtocolError

        if self.state == "greeting_response":
            self.machine.set_state("request")

        if self.state == "response":
            self.machine.set_state("end")

        return event.get_raw_data()
