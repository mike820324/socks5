from __future__ import absolute_import, unicode_literals, print_function

import argparse
import socket

from socks5 import GreetingRequest, Request
from socks5 import VERSION, AUTH_TYPE, REQ_COMMAND, ADDR_TYPE
from socks5 import Connection


def connect(host, port):
    print("Starting socks server at {host} {port}".format(**options.__dict__))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    return sock


def do_socks_protocol(sock):
    socks_conn = Connection(our_role="client")
    socks_conn.initiate_connection()

    _event = GreetingRequest(VERSION, (AUTH_TYPE["NO_AUTH"], ))
    print("sending event: {}".format(_event))

    _data = socks_conn.send(_event)
    sock.send(_data)

    while True:
        _data = sock.recv(1024)
        _event = socks_conn.recv(_data)

        if _event != "NeedMoreData":
            break

    print("receiving event: {}".format(_event))

    _event = Request(VERSION, REQ_COMMAND["CONNECT"], ADDR_TYPE["DOMAINNAME"], "google.com", 80)
    print("sending event: {}".format(_event))
    _data = socks_conn.send(_event)
    sock.send(_data)

    while True:
        _data = sock.recv(1024)
        _event = socks_conn.recv(_data)

        if _event != "NeedMoreData":
            break

    print("receiving event: {}".format(_event))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple socks5 server")
    parser.add_argument("--host", dest="host", help="specify the host", default="127.0.0.1")
    parser.add_argument("--port", dest="port", type=int, help="specify the proxy port", default=5580)
    options = parser.parse_args()

    sock = connect(**options.__dict__)
    do_socks_protocol(sock)
