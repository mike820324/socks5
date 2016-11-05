from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import construct

from socks5.exception import ParserError
from socks5.events import NeedMoreData

from . import _data_structure as data_structure
from .events import AuthRequest, AuthResponse

if sys.version_info.major <= 2:
    string_func = unicode
else:
    string_func = str


def read_auth_request(data):
    try:
        parsed_data = dict(data_structure.AuthRequest.parse(data))
    except (construct.FieldError, construct.RangeError):
        return NeedMoreData()
    except construct.ValidationError:
        raise ParserError("read_auth_request: Incorrect version.")

    parsed_data.pop("version")
    parsed_data["username"] = string_func(parsed_data["username"], encoding="ascii")
    parsed_data["password"] = string_func(parsed_data["password"], encoding="ascii")

    return AuthRequest(**parsed_data)


def read_auth_response(data):
    try:
        parsed_data = dict(data_structure.AuthResponse.parse(data))
    except (construct.FieldError, construct.RangeError):
        return NeedMoreData()
    except construct.ValidationError:
        raise ParserError("read_auth_response: Incorrect version.")

    parsed_data.pop("version")
    return AuthResponse(**parsed_data)
