from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import construct

from socks5 import data_structure
from socks5.define import ADDR_TYPE
from socks5.events import GreetingRequest, GreetingResponse
from socks5.events import AuthRequest, AuthResponse
from socks5.events import Request, Response

if sys.version_info.major <= 2:
    string_func = unicode
else:
    string_func = str


class ParserError(Exception):
    pass


def read_greeting_request(data):
    try:
        parsed_data = dict(data_structure.GreetingRequest.parse(data))
    except (construct.FieldError, construct.RangeError):
        raise ParserError

    parsed_data = dict(parsed_data)
    parsed_data.pop("nmethod")
    return GreetingRequest(**parsed_data)


def read_greeting_response(data):
    try:
        parsed_data = dict(data_structure.GreetingResponse.parse(data))
    except (construct.FieldError, construct.RangeError):
        raise ParserError

    return GreetingResponse(**parsed_data)


def read_auth_request(data):
    try:
        parsed_data = dict(data_structure.AuthRequest.parse(data))
        parsed_data["username"] = string_func(parsed_data["username"], encoding="ascii")
        parsed_data["password"] = string_func(parsed_data["password"], encoding="ascii")
    except (construct.FieldError, construct.RangeError):
        raise ParserError

    return AuthRequest(**parsed_data)


def read_auth_response(data):
    try:
        parsed_data = dict(data_structure.AuthResponse.parse(data))
    except (construct.FieldError, construct.RangeError):
        raise ParserError

    return AuthResponse(**parsed_data)


def read_request(data):
    try:
        parsed_data = dict(data_structure.Request.parse(data))
        if parsed_data["atyp"] == ADDR_TYPE["DOMAINNAME"]:
            parsed_data["addr"] = string_func(parsed_data["addr"], encoding="ascii")

    except (construct.FieldError, construct.RangeError):
        raise ParserError

    return Request(**parsed_data)


def read_response(data):
    try:
        parsed_data = dict(data_structure.Response.parse(data))
        if parsed_data["atyp"] == ADDR_TYPE["DOMAINNAME"]:
            parsed_data["addr"] = string_func(parsed_data["addr"], encoding="ascii")

    except (construct.FieldError, construct.RangeError):
        raise ParserError

    return Response(**parsed_data)
