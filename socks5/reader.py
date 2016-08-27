import struct
import ipaddress
from define import ADDR_TYPE
from events import GreetingRequest, GreetingResponse
from events import AuthRequest, AuthResponse
from events import Request, Response


class ParserError(Exception):
    pass


def read_greeting_request(data):
    try:
        version, nmethod = struct.unpack('!BB', data[:2])

        methods = struct.unpack("!{0}B".format(nmethod), data[2:])
    except struct.error:
        raise ParserError

    return GreetingRequest(version, nmethod, methods)


def read_greeting_response(data):
    try:
        version, auth_type = struct.unpack('!BB', data)
    except struct.error:
        raise ParserError

    return GreetingResponse(version, auth_type)


def read_auth_request(data):
    try:
        version, _len = struct.unpack('!BB', data[:2])
        username = struct.unpack('{}s'.format(_len), data[2:2+_len])
        _data = data[2+_len:]
        _len = struct.unpack('B', _data[0])
        password = struct.unpack('{}s'.format(_len), _data[1:])

        return AuthRequest(version, username, password)
    except struct.error:
        raise ParserError


def read_auth_response(data):
    try:
        version, status = struct.unpack('!BB', data)
    except struct.error:
        raise ParserError

    return AuthResponse(version, status)


def read_request(data):
    try:
        request_header_data = struct.unpack('!BBxB', data[0:4])
        version = request_header_data[0]
        cmd = request_header_data[1]
        atyp = request_header_data[2]

        if atyp == ADDR_TYPE["IPV4"]:
            addr_raw_data = data[4: 8]
            port_raw_data = data[8:]
            addr = ipaddress.IPv4Address(addr_raw_data).compressed

        if atyp == ADDR_TYPE["IPV6"]:
            addr_raw_data = data[4:20]
            port_raw_data = data[20:]
            addr = ipaddress.IPv6Address(addr_raw_data).compressed

        if atyp == ADDR_TYPE["DOMAINNAME"]:
            _length = int(struct.unpack('!B', data[4])[0])
            addr_raw_data = data[5:(5 + _length)]
            port_raw_data = data[(5 + _length):]
            addr = addr_raw_data.decode('idna')

        port = struct.unpack('!H', port_raw_data)[0]

    except struct.error:
        raise ParserError

    return Request(version, cmd, atyp, addr, port)


def read_response(data):
    try:
        header_data = struct.unpack('!BBxB', data[0:4])
        version = header_data[0]
        status = header_data[1]
        atyp = header_data[2]

        if atyp == ADDR_TYPE["IPV4"]:
            addr_raw_data = data[4: 8]
            port_raw_data = data[8:]
            addr = ipaddress.IPv4Address(addr_raw_data).compressed

        if atyp == ADDR_TYPE["IPV6"]:
            addr_raw_data = data[4:20]
            port_raw_data = data[20:]
            addr = ipaddress.IPv6Address(addr_raw_data).compressed

        if atyp == ADDR_TYPE["DOMAINNAME"]:
            _length = int(struct.unpack('!B', data[4])[0])
            addr_raw_data = data[5:(5 + _length)]
            port_raw_data = data[(5 + _length):]
            addr = addr_raw_data.decode('idna')

        port = struct.unpack('!H', port_raw_data)[0]

    except struct.error:
        raise ParserError

    return Response(version, status, atyp, addr, port)
