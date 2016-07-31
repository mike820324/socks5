from socks5.connection import ServerConnection
from socks5.events import NeedMoreData, GreetingResponse, Response
from socks5.define import SOCKS_VERSION, SOCKS_AUTH_TYPE, SOCKS_RESP_STATUS
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 5580))

sock.listen(5)

while True:
    clientsock, address = sock.accept()
    socks_conn = ServerConnection()
    socks_conn.initiate_connection()

    while True:
        data = clientsock.recv(1024)
        _event = socks_conn.receive(data)
        if _event is not NeedMoreData:
            break

    print _event

    _event = GreetingResponse(SOCKS_VERSION, SOCKS_AUTH_TYPE["NO_AUTH"])

    print _event
    _data = socks_conn.send(_event)
    clientsock.send(_data)

    while True:
        data = clientsock.recv(1024)
        _event = socks_conn.receive(data)
        if _event is not NeedMoreData:
            break

    print _event
    _event = Response(SOCKS_VERSION, SOCKS_RESP_STATUS["SUCCESS"], _event.atyp, _event.addr, _event.port)
    print _event
    _data = socks_conn.send(_event)
    clientsock.send(_data)
