import struct
import ipaddress
from define import SOCKS_VERSION, SOCKS_ADDR_TYPE


class NeedMoreData(object):
    def __str__(self):
        return "NeedMoreData"


class GreetingRequest(object):
    def __init__(self, version, nmethod, methods):
        print nmethod
        self.version = version
        self.nmethod = nmethod
        self.methods = methods

    def get_raw_data(self):
        _data_header = struct.pack('BB', self.version, self.nmethod)
        _data_body = struct.pack('{}B'.format(self.nmethod), self.methods)
        return _data_header + _data_body

    def __str__(self):
        return "Socks Greeting Request: Ver. {0}, number of method: {1}, Auth Types : {2}".format(
            self.version, self.nmethod, self.methods)


class GreetingResponse(object):
    def __init__(self, version, auth_type):
        self.version = version
        self.auth_type = auth_type

    def get_raw_data(self):
        _data = struct.pack('BB', self.version, self.auth_type)
        return _data

    def __str__(self):
        return "Socks Greeting Response: Ver. {0}, Auth Type : {1}".format(
            self.version, self.auth_type)


class Request(object):
    def __init__(self, version, cmd, atyp, addr, port):
        self.version = version
        self.cmd = cmd
        self.atyp = atyp
        self.addr = addr
        self.port = port

    def get_raw_data(self):
        _data_header = struct.pack("!BBxB", self.version, self.cmd, self.atyp)

        if self.atyp == SOCKS_ADDR_TYPE["IPV4"]:
            _data_body = struct.pack("4sH", self.addr, self.port)

        if self.atyp == SOCKS_ADDR_TYPE["IPV6"]:
            _data_body = struct.pack("16sH", self.addr, self.port)

        if self.atyp == SOCKS_ADDR_TYPE["DOMAINNAME"]:
            _length = len(self.addr)
            _data_body = struct.pack(
                "B{}sH".format(_length), _length, self.addr, self.port)

        return _data_header + _data_body

    def __str__(self):
        if self.atyp == SOCKS_ADDR_TYPE["IPV4"]:
            return "SOCKSv{0} Request: Command : {1}, Addr : {2} Port : {3}".format(
                self.version, self.cmd,
                ipaddress.IPv4Address(self.addr), self.port)

        if self.atyp == SOCKS_ADDR_TYPE["IPV6"]:
            return "SOCKSv{0} Request: Command : {1}, Addr : {2} Port : {3}".format(
                self.version, self.cmd,
                ipaddress.IPv6Address(self.addr), self.port)

        if self.atyp == SOCKS_ADDR_TYPE["DOMAINNAME"]:
            return "SOCKSv{0} Request: Command : {1}, Addr : {2} Port : {3}".format(
                self.version, self.cmd,
                self.addr, self.port)


class Response(object):
    def __init__(self, version, status, atyp, addr, port):
        self.version = version
        self.status = status
        self.atyp = atyp
        self.addr = addr
        self.port = port

    def get_raw_data(self):
        _data_header = struct.pack(
            "!BBxB", self.version, self.status, self.atyp)

        if self.atyp == SOCKS_ADDR_TYPE["IPV4"]:
            _data_body = struct.pack("4sH", self.addr, self.port)

        if self.atyp == SOCKS_ADDR_TYPE["IPV6"]:
            _data_body = struct.pack("16sH", self.addr, self.port)

        if self.atyp == SOCKS_ADDR_TYPE["DOMAINNAME"]:
            _length = len(self.addr)
            _data_body = struct.pack(
                "B{}sH".format(_length), _length, self.addr, self.port)

        return _data_header + _data_body

    def __str__(self):
        if self.atyp == SOCKS_ADDR_TYPE["IPV4"]:
            return "SOCKSv{0} Response: Status : {1}, Addr : {2} Port : {3}".format(
                self.version, self.status,
                ipaddress.IPv4Address(self.addr), self.port)

        if self.atyp == SOCKS_ADDR_TYPE["IPV6"]:
            return "SOCKSv{0} Response: Status : {1}, Addr : {2} Port : {3}".format(
                self.version, self.status,
                ipaddress.IPv6Address(self.addr), self.port)

        if self.atyp == SOCKS_ADDR_TYPE["DOMAINNAME"]:
            return "SOCKSv{0} Response: Status : {1}, Addr : {2} Port : {3}".format(
                self.version, self.status,
                self.addr, self.port)


