import construct
import ipaddress
from define import ADDR_TYPE
from events import GreetingRequest, GreetingResponse
from events import AuthRequest, AuthResponse
from events import Request, Response
import data_structure


class ParserError(Exception):
    pass


def read_greeting_request(data):
    try:
        parsed_data = dict(data_structure.GreetingRequest.parse(data))
    except (construct.FieldError, construct.RangeError):
        raise ParserError

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
        if parsed_data["atyp"] == ADDR_TYPE["IPV4"]:
            parsed_data["addr"] = unicode(ipaddress.IPv4Address(parsed_data["addr"]))
        elif parsed_data["atyp"] == ADDR_TYPE["IPV6"]:
            parsed_data["addr"] = unicode(ipaddress.IPv6Address(parsed_data["addr"]))
        elif parsed_data["atyp"] == ADDR_TYPE["DOMAINNAME"]:
            parsed_data["addr"] = parsed_data["addr"].decode("idna")

    except (construct.FieldError, construct.RangeError):
        raise ParserError

    return Request(**parsed_data)


def read_response(data):
    try:
        parsed_data = dict(data_structure.Response.parse(data))
        if parsed_data["atyp"] == ADDR_TYPE["IPV4"]:
            parsed_data["addr"] = unicode(ipaddress.IPv4Address(parsed_data["addr"]))
        elif parsed_data["atyp"] == ADDR_TYPE["IPV6"]:
            parsed_data["addr"] = unicode(ipaddress.IPv6Address(parsed_data["addr"]))
        elif parsed_data["atyp"] == ADDR_TYPE["DOMAINNAME"]:
            parsed_data["addr"] = parsed_data["addr"].decode("idna")

    except (construct.FieldError, construct.RangeError):
        raise ParserError

    return Response(**parsed_data)
