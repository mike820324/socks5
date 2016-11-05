from __future__ import absolute_import, division, print_function, unicode_literals

import sys
from socks5.define import RESP_STATUS

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


class AuthRequest(object):
    """
    This event represent the socks5 auth request.

    Args:
        username (unicode):  specify the username.
        password (unicode): specify the password.

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - username type is not unicode.
            - password type is not unicode.

    Example:
        >>> # python 2 example
        >>> import sys
        >>> sys.version_info.major
        2
        >>> event = AuthRequest(u"user", u"password")
        >>> event == "AuthRequest"
        True
        >>> event.username == u"user"
        True
        >>> event.password == u"password"
        True
        >>> # python 3 example
        >>> import sys
        >>> sys.version_info.major
        3
        >>> event = AuthRequest("user", "password")
        >>> event == "AuthRequest"
        True
        >>> event.username == "user"
        True
        >>> event.password == "password"
        True
    """
    event_type = "AuthRequest"

    def __init__(self, username, password):
        if not isinstance(username, string_func) or not isinstance(password, string_func):
            raise ValueError("username or password expect to be unicode string")

        if len(username) >= 256 or len(password) >= 256:
            raise ValueError("username or password too long")

        self.username = username
        self.password = password

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv5 Auth Request: username: {username}, password: {password}".format(**self.__dict__)


class AuthResponse(object):
    """
    This event represent the socks5 auth response.

    Args:
        status (int):  specify the socks server response status code.
            The supported socks status code can be found in ::define.py::

    Raise:
        ValueError: ValueError will be raised when the following condition occured.
            - version is not supported. Currently, the supported version is 5.
            - specify an unsupported status code.

    Example:
        >>> event = AuthResponse(0)
        >>> event == "AuthResponse"
        True
        >>> event.version == 5
        True
        >>> event.status == 0
        True
    """
    event_type = "AuthResponse"

    def __init__(self, status):
        if status not in RESP_STATUS.values():
            raise ValueError("Unsupported status code")

        self.status = status

    def __eq__(self, value):
        return self.event_type == value

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return "SOCKSv5 Auth Response: status: {}".format(self.status)
