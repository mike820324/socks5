from __future__ import absolute_import, unicode_literals, print_function

from socks5 import GreetingRequest, Request
from socks5 import VERSION, AUTH_TYPE, REQ_COMMAND, ADDR_TYPE
from socks5 import Connection

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 5580))

socks_conn = Connection(our_role="client")
socks_conn.initiate_connection()

_event = GreetingRequest(VERSION, (AUTH_TYPE["NO_AUTH"], ))
_data = socks_conn.send(_event)
sock.send(_data)

while True:
    _data = sock.recv(1024)
    _event = socks_conn.recv(_data)

    if _event != "NeedMoreData":
        break
print(_event)

_event = Request(VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["DOMAINNAME"], "google.com", 80)
_data = socks_conn.send(_event)
sock.send(_data)

while True:
    _data = sock.recv(1024)
    _event = socks_conn.recv(_data)

    if _event != "NeedMoreData":
        break

print(_event)
