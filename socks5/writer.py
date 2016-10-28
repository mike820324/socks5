import struct
import ipaddress
from socks5 import ADDR_TYPE


def write_greeting_request(event):
    _data_header = struct.pack('!BB', event.version, event.nmethod)
    _data_body = struct.pack('!{}B'.format(event.nmethod), *event.methods)
    return _data_header + _data_body


def write_greeting_response(event):
    _data = struct.pack('!BB', event.version, event.auth_type)
    return _data


def write_auth_request(event):
    _data = struct.pack(
        "!BB{0}sB{1}s".format(len(event.username), len(event.password)),
        event.version, len(event.username), event.username, len(event.password), event.password)
    return _data


def write_auth_response(event):
    _data = struct.pack('!BB', event.version, event.status)
    return _data


def write_request(event):
    _data_header = struct.pack("!BBxB", event.version, event.cmd, event.atyp)

    if event.atyp == ADDR_TYPE["IPV4"]:
        _data_addr = ipaddress.IPv4Address(event.addr).packed

    if event.atyp == ADDR_TYPE["IPV6"]:
        _data_addr = ipaddress.IPv6Address(event.addr).packed

    if event.atyp == ADDR_TYPE["DOMAINNAME"]:
        _length = len(event.addr)
        _data_addr = struct.pack('!B', _length)
        _data_addr += event.addr.encode('idna')

    _data_port = struct.pack('!H', event.port)
    return _data_header + _data_addr + _data_port


def write_response(event):
    _data_header = struct.pack(
        "!BBxB", event.version, event.status, event.atyp)

    if event.atyp == ADDR_TYPE["IPV4"]:
        _data_addr = ipaddress.IPv4Address(event.addr).packed

    if event.atyp == ADDR_TYPE["IPV6"]:
        _data_addr = ipaddress.IPv6Address(event.addr).packed

    if event.atyp == ADDR_TYPE["DOMAINNAME"]:
        _length = len(event.addr)
        _data_addr = struct.pack('!B', _length)
        _data_addr += event.addr.encode('idna')

    _data_port = struct.pack('!H', event.port)
    return _data_header + _data_addr + _data_port
