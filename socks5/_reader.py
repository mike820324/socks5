from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import construct

from socks5 import _data_structure as data_structure
from socks5.exception import ParserError
from socks5.define import ADDR_TYPE
from socks5.events import NeedMoreData
from socks5.events import Socks4Request, Socks4Response
from socks5.events import GreetingRequest, GreetingResponse
from socks5.events import Request, Response

if sys.version_info.major <= 2:
    string_func = unicode
else:
    string_func = str


def read_greeting_request(data):
    try:
        parsed_data = dict(data_structure.GreetingRequest.parse(data))
    except (construct.FieldError, construct.RangeError):
        return NeedMoreData()
    except construct.ValidationError:
        raise ParserError("read_greeting_request: Incorrect version.")

    if parsed_data["version"] == 5:
        parsed_data.pop("version")
        parsed_data.pop("nmethod")
        return GreetingRequest(**parsed_data)

    elif parsed_data["version"] == 4:
        parsed_data.pop("version")
        parsed_data["name"] = string_func(parsed_data["name"], encoding="ascii")
        if parsed_data["domainname"]:
            parsed_data["domainname"] = string_func(parsed_data["domainname"], encoding="ascii")
        else:
            parsed_data.pop("domainname")
        return Socks4Request(**parsed_data)


def read_greeting_response(data):
    try:
        parsed_data = dict(data_structure.GreetingResponse.parse(data))
    except (construct.FieldError, construct.RangeError):
        return NeedMoreData()
    except construct.ValidationError:
        raise ParserError("read_greeting_response: Incorrect version.")

    if parsed_data["version"] == 5:
        parsed_data.pop("version")
        return GreetingResponse(**parsed_data)

    # NOTE: socksv4 will have a null byte in front
    elif parsed_data["version"] == 0x0:
        parsed_data.pop("version")
        return Socks4Response(**parsed_data)


def read_request(data):
    try:
        parsed_data = dict(data_structure.Request.parse(data))
    except (construct.FieldError, construct.RangeError):
        return NeedMoreData()
    except construct.ValidationError:
        raise ParserError("read_request: Incorrect version.")

    parsed_data.pop("version")
    if parsed_data["atyp"] == ADDR_TYPE["DOMAINNAME"]:
        parsed_data["addr"] = string_func(parsed_data["addr"], encoding="ascii")

    return Request(**parsed_data)


def read_response(data):
    try:
        parsed_data = dict(data_structure.Response.parse(data))
    except (construct.FieldError, construct.RangeError):
        return NeedMoreData()
    except construct.ValidationError:
        raise ParserError("read_response: Incorrect version.")

    parsed_data.pop("version")
    if parsed_data["atyp"] == ADDR_TYPE["DOMAINNAME"]:
        parsed_data["addr"] = string_func(parsed_data["addr"], encoding="ascii")

    return Response(**parsed_data)
