import struct
from define import SOCKS_ADDR_TYPE
from events import GreetingRequest, GreetingResponse
from events import Request, Response


class ParserError(Exception):
    pass

class SocksParser(object):
    # TODO: Input data validation
    @staticmethod
    def parse_greeting_request(data):
        try:
            version, nmethod = struct.unpack('BB', data[:2])

            methods = struct.unpack("{0}B".format(nmethod), data[2:])
        except struct.error:
            raise ParserError

        return GreetingRequest(version, nmethod, methods)

    @staticmethod
    def parse_greeting_response(data):
        try:
            version, auth_type = struct.unpack('BB', data)
        except struct.error:
            raise ParserError

        return GreetingResponse(version, auth_type)


    @staticmethod
    def parse_request(data):
        try:
            request_header_data = struct.unpack('!BBxB', data[0:4])
            version = request_header_data[0]
            cmd = request_header_data[1]
            atyp = request_header_data[2]

            data_without_header = data[4:]
            if atyp == SOCKS_ADDR_TYPE["IPV4"]:
                addr, port = struct.unpack('!4sH', data_without_header)

            if atyp == SOCKS_ADDR_TYPE["IPV6"]:
                addr, port = struct.unpack('!16sH', data_without_header)

            if atyp == SOCKS_ADDR_TYPE["DOMAINNAME"]:
                _length = int(struct.unpack('B', data_without_header[0])[0])
                addr, port = struct.unpack(
                    '!x{0}sH'.format(_length), data_without_header)

        except struct.error:
            raise ParserError


        return Request(version, cmd, atyp, addr, port)

    @staticmethod
    def parse_response(data):
        try:
            header_data = struct.unpack('!BBxB', data[0:4])
            version = header_data[0]
            status = header_data[1]
            atyp = header_data[2]

            data_without_header = data[4:]
            if atyp == SOCKS_ADDR_TYPE["IPV4"]:
                addr, port = struct.unpack('!4sH', data_without_header)

            if atyp == SOCKS_ADDR_TYPE["IPV6"]:
                addr, port = struct.unpack('!16sH', data_without_header)

            if atyp == SOCKS_ADDR_TYPE["DOMAINNAME"]:
                _length = int(struct.unpack('B', data_without_header[0])[0])
                addr, port = struct.unpack(
                    '!x{0}sH'.format(_length), data_without_header)

        except struct.error:
            raise ParserError

        return Response(version, status, atyp, addr, port)
