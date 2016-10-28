import ipaddress
from define import VERSION, ADDR_TYPE, REQ_COMMAND, RESP_STATUS


class NeedMoreData(object):
    event_type = "NeedMoreData"

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "NeedMoreData"


class GreetingRequest(object):
    event_type = "GreetingRequest"

    def __init__(self, version, nmethod, methods):
        if version != VERSION:
            raise ValueError("Only support socks version 5")

        if not isinstance(methods, list) and not isinstance(methods, tuple):
            raise ValueError("methods should be a list or tuple")

        if nmethod != len(methods):
            raise ValueError("methods and nmethod number mismatch")

        self.version = version
        self.nmethod = nmethod
        self.methods = methods

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv{0} Greeting Request: number of method: {1}, Auth Types : {2}".format(
            self.version, self.nmethod, self.methods)


class GreetingResponse(object):
    event_type = "GreetingResponse"

    def __init__(self, version, auth_type):
        if version != VERSION:
            raise ValueError("Only support socks version 5")

        self.version = version
        self.auth_type = auth_type

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv{0} Greeting Response: Auth Type : {1}".format(
            self.version, self.auth_type)


class AuthRequest(object):
    event_type = "AuthRequest"

    def __init__(self, version, username, password):
        if version != VERSION:
            raise ValueError("Only support socks version 5")

        if len(username) >= 256 or len(password) >= 256:
            raise ValueError("username or password too long")

        self.version = version
        self.username = username
        self.password = password

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv{0} Auth Request: username: {1}, password: {2}".format(
            self.version, self.username, self.password)


class AuthResponse(object):
    event_type = "AuthResponse"

    def __init__(self, version, status):
        if version != VERSION:
            raise ValueError("Only support socks version 5")

        self.version = version
        self.status = status

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv{0} Auth Response: status: {1}".format(
            self.version, self.status)


class Request(object):
    event_type = "Request"

    def __init__(self, version, cmd, atyp, addr, port):
        if version != VERSION:
            raise ValueError

        if cmd not in REQ_COMMAND.values():
            raise ValueError("Unsupported request command {}".format(cmd))

        if atyp not in ADDR_TYPE.values():
            raise ValueError("Unsupported address type {}".format(atyp))

        self.version = version
        self.cmd = cmd
        self.atyp = atyp
        # TODO: Add validation for addr and port
        # - addr: can use ipaddress module to validate
        self.addr = addr
        self.port = port

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        if self.atyp == ADDR_TYPE["IPV4"]:
            return "SOCKSv{0} Request: Command : {1}, Addr : {2} Port : {3}".format(
                self.version, self.cmd,
                ipaddress.IPv4Address(self.addr), self.port)

        if self.atyp == ADDR_TYPE["IPV6"]:
            return "SOCKSv{0} Request: Command : {1}, Addr : {2} Port : {3}".format(
                self.version, self.cmd,
                ipaddress.IPv6Address(self.addr), self.port)

        if self.atyp == ADDR_TYPE["DOMAINNAME"]:
            return "SOCKSv{0} Request: Command : {1}, Addr : {2} Port : {3}".format(
                self.version, self.cmd,
                self.addr, self.port)


class Response(object):
    event_type = "Response"

    def __init__(self, version, status, atyp, addr, port):
        if version != VERSION:
            raise ValueError

        if status not in RESP_STATUS.values():
            raise ValueError("Unsupported status code {}".format(status))

        if atyp not in ADDR_TYPE.values():
            raise ValueError("Unsupported address type {}".format(atyp))

        self.version = version
        self.status = status
        self.atyp = atyp
        self.addr = addr
        self.port = port

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        if self.atyp == ADDR_TYPE["IPV4"]:
            return "SOCKSv{0} Response: Status : {1}, Addr : {2} Port : {3}".format(
                self.version, self.status,
                ipaddress.IPv4Address(self.addr), self.port)

        if self.atyp == ADDR_TYPE["IPV6"]:
            return "SOCKSv{0} Response: Status : {1}, Addr : {2} Port : {3}".format(
                self.version, self.status,
                ipaddress.IPv6Address(self.addr), self.port)

        if self.atyp == ADDR_TYPE["DOMAINNAME"]:
            return "SOCKSv{0} Response: Status : {1}, Addr : {2} Port : {3}".format(
                self.version, self.status,
                self.addr, self.port)
