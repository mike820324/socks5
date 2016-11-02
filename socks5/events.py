from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import ipaddress
from socks5.define import VERSION, ADDR_TYPE, REQ_COMMAND, RESP_STATUS

if sys.version_info.major <= 2:
    string_func = unicode
else:
    string_func = str


class NeedMoreData(object):
    event_type = "NeedMoreData"

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "NeedMoreData"


class GreetingRequest(object):
    """
    This event represent the socks5 greeting request.

    Args:
        version (int): specify the socks version. Currently only 5 is supported.
            The supported socks version can be found in ::define.py::
        methods (list/tuple): a list of query methods.
            The supported methods can be found in ::define.py::

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.
            - methods type is not list or tuple.

    Example:
        >>> event = GreetingRequest(5, [0, 1])
        >>> event == "GreetingRequest"
        True
        >>> event.version == 5
        True
        >>> event.nmethod == 2
        True
        >>> event.methods == [0, 1]
        True
    """
    event_type = "GreetingRequest"

    def __init__(self, version, methods):
        if version != VERSION:
            raise ValueError("Only support socks version 5")

        if not isinstance(methods, list) and not isinstance(methods, tuple):
            raise ValueError("methods should be a list or tuple")

        self.version = version
        self.nmethod = len(methods)
        self.methods = list(methods)

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv{0} Greeting Request: number of method: {1}, Auth Types : {2}".format(
            self.version, self.nmethod, self.methods)


class GreetingResponse(object):
    """
    This event represent the socks5 greeting response.

    Args:
        version (int): specify the socks version. Currently only 5 is supported.
            The supported socks version can be found in ::define.py::
        auth_type (int): specify the auth type server selected.
            The supported auth_type can be found in ::define.py::

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.

    Example:
        >>> event = GreetingResponse(5, 0)
        >>> event == "GreetingResponse"
        True
        >>> event.version == 5
        True
        >>> event.auth_type == 0
        True
    """
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
    """
    This event represent the socks5 auth request.

    Args:
        version (int): specify the socks version. Currently only 5 is supported.
            The supported socks version can be found in ::define.py::
        username (unicode):  specify the username.
        password (unicode): specify the password.

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.
            - username type is not unicode.
            - password type is not unicode.

    Example:
        >>> # python 2 example
        >>> import sys
        >>> sys.version_info.major
        2
        >>> event = AuthRequest(5, u"user", u"password")
        >>> event == "AuthRequest"
        True
        >>> event.version == 5
        True
        >>> event.username == u"user"
        True
        >>> event.password == u"password"
        True
        >>> # python 3 example
        >>> import sys
        >>> sys.version_info.major
        3
        >>> event = AuthRequest(5, "user", "password")
        >>> event == "AuthRequest"
        True
        >>> event.version == 5
        True
        >>> event.username == "user"
        True
        >>> event.password == "password"
        True
    """
    event_type = "AuthRequest"

    def __init__(self, version, username, password):
        if version != VERSION:
            raise ValueError("Only support socks version 5")

        if not isinstance(username, string_func) or not isinstance(password, string_func):
            raise ValueError("username or password expect to be unicode string")

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
    """
    This event represent the socks5 auth response.

    Args:
        version (int): specify the socks version. Currently only 5 is supported.
            The supported socks version can be found in ::define.py::
        status (int):  specify the socks server response status code.
            The supported socks status code can be found in ::define.py::

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.
            - specify an unsupported status code.

    Example:
        >>> event = AuthResponse(5, 0)
        >>> event == "AuthResponse"
        True
        >>> event.version == 5
        True
        >>> event.status == 0
        True
    """
    event_type = "AuthResponse"

    def __init__(self, version, status):
        if version != VERSION:
            raise ValueError("Only support socks version 5")

        if status not in RESP_STATUS.values():
            raise ValueError("Unsupported status code")

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
    """
    This event represent the socks5 request.

    Args:
        version (int): specify the socks version. Currently only 5 is supported.
            The supported socks version can be found in ::define.py::
        cmd (int):  specify the request command type.
            The supported value can be found in ::define.py::
        atyp (int):  specify the request address type.
            The supported value can be found in ::define.py::
        addr (unicode/int):  specify the address.
        port (int):  specify the port.

    Note:
        The ::addr:: field can accept any ipaddress.ip_address compatible value.
        If the ::atyp:: type is domain name, the value **MUST** be a unicode type.

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.
            - specify an unsupported cmd type or atyp type.
            - addr field type incorrect.
            - addr field mismatched with atyp type.

    Example:
        >>> # python 2 example
        >>> import sys
        >>> sys.version_info.major_version
        2
        >>> event = Request(5, 1, 1, u"127.0.0.1", 5580)
        >>> event == "Request"
        True
        >>> event.version
        5
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('127.0.0.1')
        >>> event.port
        5580
        >>> # addr type is integer
        >>> event = Request(5, 1, 1, 1, 5580)
        >>> event == "Request"
        True
        >>> event.version
        5
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('0.0.0.1')
        >>> event.port
        5580
        >>> event = Request(5, 1, 3, u"google.com", 5580)
        >>> event == "Request"
        True
        >>> event.version
        5
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        u"google.com"
        >>> event.port
        5580
        >>> # python 3 example
        >>> import sys
        >>> sys.version_info.major_version
        3
        >>> event = Request(5, 1, 1, "127.0.0.1", 5580)
        >>> event == "Request"
        True
        >>> event.version
        5
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('127.0.0.1')
        >>> event.port
        5580
        >>> event = Request(5, 1, 3, "google.com", 5580)
        >>> event == "Request"
        True
        >>> event.version
        5
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        "google.com"
        >>> event.port
        5580
    """
    event_type = "Request"

    def __init__(self, version, cmd, atyp, addr, port):
        if version != VERSION:
            raise ValueError

        if cmd not in REQ_COMMAND.values():
            raise ValueError("Unsupported request command {}".format(cmd))

        if atyp not in ADDR_TYPE.values():
            raise ValueError("Unsupported address type {}".format(atyp))

        if atyp == ADDR_TYPE["IPV4"]:
            try:
                addr = ipaddress.IPv4Address(addr)
            except ipaddress.AddressValueError:
                raise ValueError("Invalid ipaddress format for IPv4")
        elif atyp == ADDR_TYPE["IPV6"]:
            try:
                addr = ipaddress.IPv6Address(addr)
            except ipaddress.AddressValueError:
                raise ValueError("Invalid ipaddress format for IPv6")
        elif atyp == ADDR_TYPE["DOMAINNAME"] and not isinstance(addr, string_func):
            raise ValueError("Domain name expect to be unicode string")

        self.version = version
        self.cmd = cmd
        self.atyp = atyp
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
    """
    This event represent the socks5 response.

    Args:
        version (int): specify the socks version. Currently only 5 is supported.
            The supported socks version can be found in ::define.py::
        status (int):  specify the socks server response status code.
            The supported value can be found in ::define.py::
        atyp (int):  specify the request address type.
            The supported value can be found in ::define.py::
        addr (unicode/int):  specify the address.
        port (int):  specify the port.

    Note:
        The ::addr:: field can accept any ipaddress.ip_address compatible value.
        If the ::atyp:: type is domain name, the value **MUST** be a unicode type.

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.
            - specify an unsupported status type or atyp type.
            - addr field type incorrect.
            - addr field mismatched with atyp type.

    Example:
        >>> # python 2 example
        >>> import sys
        >>> sys.version_info.major_version
        2
        >>> event = Response(5, 0, 1, u"127.0.0.1", 5580)
        >>> event == "Response"
        True
        >>> event.version
        5
        >>> event.status
        0
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('127.0.0.1')
        >>> int(event.addr)
        2130706433
        >>> event.port
        5580
        >>> event = Response(5, 0, 3, u"google.com", 5580)
        >>> event == "Response"
        True
        >>> event.version
        5
        >>> event.status
        0
        >>> event.atyp
        1
        >>> event.addr
        u"google.com"
        >>> event.port
        5580
        >>> # python 3 example
        >>> import sys
        >>> sys.version_info.major_version
        3
        >>> event = Respopnse(5, 0, 1, "127.0.0.1", 5580)
        >>> event == "Respopnse"
        True
        >>> event.version
        5
        >>> event.status
        0
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('127.0.0.1')
        >>> event.port
        5580
        >>> event = Response(5, 0, 3, "google.com", 5580)
        >>> event == "Response"
        True
        >>> event.version
        5
        >>> event.status
        0
        >>> event.atyp
        1
        >>> event.addr
        "google.com"
        >>> event.port
        5580
    """
    event_type = "Response"

    def __init__(self, version, status, atyp, addr, port):
        if version != VERSION:
            raise ValueError

        if status not in RESP_STATUS.values():
            raise ValueError("Unsupported status code {}".format(status))

        if atyp not in ADDR_TYPE.values():
            raise ValueError("Unsupported address type {}".format(atyp))

        if atyp == ADDR_TYPE["IPV4"]:
            try:
                addr = ipaddress.IPv4Address(addr)
            except ipaddress.AddressValueError:
                raise ValueError("Invalid ipaddress format for IPv4")
        elif atyp == ADDR_TYPE["IPV6"]:
            try:
                addr = ipaddress.IPv6Address(addr)
            except ipaddress.AddressValueError:
                raise ValueError("Invalid ipaddress format for IPv6")
        elif atyp == ADDR_TYPE["DOMAINNAME"] and not isinstance(addr, string_func):
            raise ValueError("Domain name expect to be unicode string")

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
