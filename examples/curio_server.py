"""
This example use the curio module to implement a simple socks5 server.

Note: This example can only works in python 3.5 and above due to the async/await syntax.

Author: Mike Jiang
License: MIT
"""

import argparse
from curio import run, spawn, tcp_server
from socks5 import Connection, GreetingResponse, Response
from socks5 import VERSION, AUTH_TYPE, RESP_STATUS, ADDR_TYPE


async def socks5_handler(client, addr):
    print("client connect from address: {}".format(addr))
    conn = Connection(our_role="server")
    conn.initiate_connection()

    # greeting request
    data = await client.recv(1024)
    _event = conn.recv(data)
    print("receiving event: {}".format(_event))

    # greeting response
    event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
    print("sending event: {}".format(event))
    data = conn.send(event)
    await client.send(data)

    # socks request
    data = await client.recv(1024)
    _event = conn.recv(data)
    print("receiving event: {}".format(_event))

    # socks response
    event = Response(VERSION, RESP_STATUS["SUCCESS"], _event.atyp, _event.addr, _event.port)
    print("sending event: {}".format(event))
    data = conn.send(event)
    await client.send(data)

    print("socks end")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple socks5 server")
    parser.add_argument("--host", dest="host", help="specify the host", default="127.0.0.1")
    parser.add_argument("--port", dest="port", type=int, help="specify the proxy port", default=5580)
    options = parser.parse_args()

    try:
        print("Starting socks server at {host} {port}".format(**options.__dict__))
        run(tcp_server(options.host, options.port, socks5_handler), with_monitor=False)
    except KeyboardInterrupt:
        print("bye")
