import struct
from socks5 import ADDR_TYPE


def write_greeting_request(event):
    _data_header = struct.pack('BB', event.version, event.nmethod)
    _data_body = struct.pack('{}B'.format(event.nmethod), event.methods)
    return _data_header + _data_body


def write_greeting_response(event):
    _data = struct.pack('BB', event.version, event.auth_type)
    return _data


def write_auth_request(event):
    _data = struct.pack(
        "BB{0}s{1}s".format(len(event.username), len(event.password)),
        event.version, event.username, event.password)
    return _data


def write_auth_response(event):
    _data = struct.pack('BB', event.version, event.status)
    return _data


def write_request(event):
    _data_header = struct.pack("!BBxB", event.version, event.cmd, event.atyp)

    if event.atyp == ADDR_TYPE["IPV4"]:
        _data_body = struct.pack("4sH", event.addr, event.port)

    if event.atyp == ADDR_TYPE["IPV6"]:
        _data_body = struct.pack("16sH", event.addr, event.port)

    if event.atyp == ADDR_TYPE["DOMAINNAME"]:
        _length = len(event.addr)
        _data_body = struct.pack(
            "B{}sH".format(_length), _length, event.addr, event.port)

    return _data_header + _data_body


def write_response(event):
    _data_header = struct.pack(
        "!BBxB", event.version, event.status, event.atyp)

    if event.atyp == ADDR_TYPE["IPV4"]:
        _data_body = struct.pack("4sH", event.addr, event.port)

    if event.atyp == ADDR_TYPE["IPV6"]:
        _data_body = struct.pack("16sH", event.addr, event.port)

    if event.atyp == ADDR_TYPE["DOMAINNAME"]:
        _length = len(event.addr)
        _data_body = struct.pack(
            "B{}sH".format(_length), _length, event.addr, event.port)

    return _data_header + _data_body
