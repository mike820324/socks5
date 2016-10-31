import ipaddress
from socks5 import ADDR_TYPE
from socks5.data_structure import GreetingRequest, GreetingResponse
from socks5.data_structure import AuthRequest, AuthResponse
from socks5.data_structure import Request, Response


def write_greeting_request(event):
    return GreetingRequest.build(event.__dict__)


def write_greeting_response(event):
    return GreetingResponse.build(event.__dict__)


def write_auth_request(event):
    return AuthRequest.build(event.__dict__)


def write_auth_response(event):
    return AuthResponse.build(event.__dict__)


def write_request(event):
    event_dict = event.__dict__

    if event.atyp == ADDR_TYPE["IPV4"]:
        event_dict["addr"] = int(ipaddress.IPv4Address(event.addr))

    elif event.atyp == ADDR_TYPE["IPV6"]:
        event_dict["addr"] = int(ipaddress.IPv6Address(event.addr))
    return Request.build(event_dict)


def write_response(event):
    event_dict = event.__dict__

    if event.atyp == ADDR_TYPE["IPV4"]:
        event_dict["addr"] = int(ipaddress.IPv4Address(event.addr))

    elif event.atyp == ADDR_TYPE["IPV6"]:
        event_dict["addr"] = int(ipaddress.IPv6Address(event.addr))

    return Response.build(event_dict)
