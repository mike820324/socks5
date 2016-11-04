from __future__ import absolute_import, division, print_function, unicode_literals

import ipaddress
from socks5.define import ADDR_TYPE
from socks5.data_structure import GreetingRequest, GreetingResponse
from socks5.data_structure import UsernamePasswordAuthRequest, UsernamePasswordAuthResponse
from socks5.data_structure import Request, Response


def write_greeting_request(event):
    event_dict = event.__dict__

    if event == "GreetingRequest":
        event_dict["version"] = 5
    if event == "Socks4Request":
        event_dict["version"] = 4
        event_dict["addr"] = int(event.addr)
        event_dict["name"] = event.name.encode("ascii")
        event_dict["domainname"] = event.domainname.encode("idna")

    return GreetingRequest.build(event_dict)


def write_greeting_response(event):
    event_dict = event.__dict__

    if event == "GreetingResponse":
        event_dict["version"] = 5
    if event == "Socks4Response":
        # NOTE: socksv4 will have a null byte in front
        event_dict["version"] = 0
        event_dict["addr"] = int(event.addr)

    return GreetingResponse.build(event_dict)


def write_rfc1929_auth_request(event):
    event_dict = event.__dict__

    event_dict["version"] = 1
    event_dict["username"] = event.username.encode("ascii")
    event_dict["password"] = event.password.encode("ascii")
    return UsernamePasswordAuthRequest.build(event_dict)


def write_rfc1929_auth_response(event):
    event_dict = event.__dict__

    event_dict["version"] = 1
    return UsernamePasswordAuthResponse.build(event_dict)


def write_request(event):
    event_dict = event.__dict__

    event_dict["version"] = 5
    if event.atyp == ADDR_TYPE["IPV4"]:
        event_dict["addr"] = int(ipaddress.IPv4Address(event.addr))

    elif event.atyp == ADDR_TYPE["IPV6"]:
        event_dict["addr"] = int(ipaddress.IPv6Address(event.addr))

    else:
        event_dict["addr"] = event.addr.encode("idna")

    return Request.build(event_dict)


def write_response(event):
    event_dict = event.__dict__

    event_dict["version"] = 5
    if event.atyp == ADDR_TYPE["IPV4"]:
        event_dict["addr"] = int(ipaddress.IPv4Address(event.addr))

    elif event.atyp == ADDR_TYPE["IPV6"]:
        event_dict["addr"] = int(ipaddress.IPv6Address(event.addr))

    else:
        event_dict["addr"] = event.addr.encode("idna")

    return Response.build(event_dict)
