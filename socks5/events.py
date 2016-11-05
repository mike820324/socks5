from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import ipaddress
from socks5.define import ADDR_TYPE, REQ_COMMAND, RESP_STATUS

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


class Socks4Request(object):
    """
    This event represent the socksv4 request.

    Args:
        cmd (int):  specify the request socks4 command type.
            The supported value can be found in ::define.py::
        addr (unicode/int):  specify the address.
        port (int):  specify the port.
        name (unicode): specify the name identd name.
        domainname (unicode): specify the domain name.

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - ipaddress.IPv4Address incompatible address format type.
            - name is not unicode.
            - domainname is not unicode.
            - addr field is 1 but domainname not specified

    """

    event_type = "Socks4Request"

    def __init__(self, cmd, addr, port, name, domainname=""):
        if cmd not in [0x1, 0x2]:
            raise ValueError("cmd should be either command or bind")

        try:
            addr = ipaddress.IPv4Address(addr)
        except ipaddress.AddressValueError:
            raise ValueError("Invalid ipaddress format for IPv4")

        if int(addr) == 1 and len(domainname) == 0:
            raise ValueError("Domain name should be specified when addr is 1")

        if not isinstance(name, string_func) or not isinstance(domainname, string_func):
            raise ValueError("name or domainname must be a unicode string")

        self.cmd = cmd
        self.port = port
        self.name = name

        if domainname:
            self.addr = ipaddress.IPv4Address(1)
        else:
            self.addr = addr

        self.domainname = domainname

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "Sockv4 request"


class Socks4Response(object):
    """
    This event represent the socksv4 response.

    Args:
        status (int): sockv4 compatible status code.
        addr (unicode or int): ipv4 address.
        port (int): port number

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - unsupported status type.
            - ipaddress.IPv4Address incompatible address format type.
    """

    event_type = "Socks4Response"

    def __init__(self, status, addr, port):
        if status not in {0x5a, 0x5b, 0x5c, 0x5d}:
            raise ValueError("Incorrect status code")

        self.status = status
        try:
            self.addr = ipaddress.IPv4Address(addr)
        except ipaddress.AddressValueError:
            raise ValueError("Invalid ipaddress format for IPv4")

        self.port = port

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "Sockv4 Response"


class GreetingRequest(object):
    """
    This event represent the socks5 greeting request.

    Args:
        methods (list/tuple): a list of query methods.
            The supported methods can be found in ::define.py::

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - methods type is not list or tuple.

    Example:
        >>> event = GreetingRequest([0, 1])
        >>> event == "GreetingRequest"
        True
        >>> event.nmethod == 2
        True
        >>> event.methods == [0, 1]
        True
    """
    event_type = "GreetingRequest"

    def __init__(self, methods):
        if not isinstance(methods, list) and not isinstance(methods, tuple):
            raise ValueError("methods should be a list or tuple")

        self.nmethod = len(methods)
        self.methods = list(methods)

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv5 Greeting Request: number of method: {nmethod}, Auth Types : {methods}".format(**self.__dict__)


class GreetingResponse(object):
    """
    This event represent the socks5 greeting response.

    Args:
        auth_type (int): specify the auth type server selected.
            The supported auth_type can be found in ::define.py::

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.

    Example:
        >>> event = GreetingResponse(0)
        >>> event == "GreetingResponse"
        True
        >>> event.auth_type == 0
        True
    """
    event_type = "GreetingResponse"

    def __init__(self, auth_type):
        self.auth_type = auth_type

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv5 Greeting Response: Auth Type : {0}".format(self.auth_type)


class Request(object):
    """
    This event represent the socks5 request.

    Args:
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
            - specify an unsupported cmd type or atyp type.
            - addr field type incorrect.
            - addr field mismatched with atyp type.

    Example:
        >>> # python 2 example
        >>> import sys
        >>> sys.version_info.major_version
        2
        >>> event = Request(1, 1, u"127.0.0.1", 5580)
        >>> event == "Request"
        True
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('127.0.0.1')
        >>> event.port
        5580
        >>> # addr type is integer
        >>> event = Request(1, 1, 1, 5580)
        >>> event == "Request"
        True
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('0.0.0.1')
        >>> event.port
        5580
        >>> event = Request(1, 3, u"google.com", 5580)
        >>> event == "Request"
        True
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
        >>> event = Request(1, 1, "127.0.0.1", 5580)
        >>> event == "Request"
        True
        >>> event.cmd
        1
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('127.0.0.1')
        >>> event.port
        5580
        >>> event = Request(1, 3, "google.com", 5580)
        >>> event == "Request"
        True
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

    def __init__(self, cmd, atyp, addr, port):
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

        self.cmd = cmd
        self.atyp = atyp
        self.addr = addr
        self.port = port

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv5 Response: Command {cmd} : Address Type {atyp}, Addr : {addr} Port : {port}".format(**self.__dict__)


class Response(object):
    """
    This event represent the socks5 response.

    Args:
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
            - specify an unsupported status type or atyp type.
            - addr field type incorrect.
            - addr field mismatched with atyp type.

    Example:
        >>> # python 2 example
        >>> import sys
        >>> sys.version_info.major_version
        2
        >>> event = Response(0, 1, u"127.0.0.1", 5580)
        >>> event == "Response"
        True
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
        >>> event = Response(0, 3, u"google.com", 5580)
        >>> event == "Response"
        True
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
        >>> event = Respopnse(0, 1, "127.0.0.1", 5580)
        >>> event == "Respopnse"
        True
        >>> event.status
        0
        >>> event.atyp
        1
        >>> event.addr
        IPv4Address('127.0.0.1')
        >>> event.port
        5580
        >>> event = Response(0, 3, "google.com", 5580)
        >>> event == "Response"
        True
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

    def __init__(self, status, atyp, addr, port):
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

        self.status = status
        self.atyp = atyp
        self.addr = addr
        self.port = port

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv5 Response: Status : {status}, Addr : {addr} Port : {port}".format(**self.__dict__)
