from __future__ import absolute_import, division, print_function, unicode_literals

from socks5 import GreetingResponse, Response
from socks5 import VERSION, AUTH_TYPE, RESP_STATUS
from socks5.connection import ServerConnection
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 5581))

sock.listen(5)

while True:
    clientsock, address = sock.accept()
    socks_conn = ServerConnection()
    socks_conn.initiate_connection()

    while True:
        data = clientsock.recv(1024)
        _event = socks_conn.receive(data)
        if _event != "NeedMoreData":
            break

    print(_event)

    _event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])

    print(_event)
    _data = socks_conn.send(_event)
    clientsock.send(_data)

    while True:
        data = clientsock.recv(1024)
        _event = socks_conn.receive(data)
        if _event != "NeedMoreData":
            break

    print(_event)
    _event = Response(VERSION, RESP_STATUS["SUCCESS"], _event.atyp, _event.addr, _event.port)
    print(_event)
    _data = socks_conn.send(_event)
    clientsock.send(_data)
