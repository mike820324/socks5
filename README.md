# socks5:

**socks5** is a small SOCKS version 5 library written fom scratch in Python,
which is highly inspired by [h11](https://github.com/njsmith/h11) and [hyper-h2](https://hyper-h2.readthedocs.io/en/stable/).


It's a "bring-your-own-IO" library; that is socks5 module does not contain any network related code.
socks5 only deal with the parsing and state management of the socks5 connection,
the underlying IO part is not cover in the internal code.

This means that you can use socks5 in networking library that you prefer.

## Installation:

Since we have not upload to pypi yet.

```bash
git clone https://github.com/mike820324/socks5
cd socks5
pip install .
```

## Quick Guide:

Here I will walk through a simple socks5 client/server communication.

First thing first, we have to initiate a connection.
You can initiate a connection by using the following code snippets.

```python
from socks5 import ClientConnection, ServerConnection
client_conn = ClientConnection()
client_conn.initiate_connection()

server_conn = ServerConnection()
server_conn.initiate_connection()
```

The **conn.initiate_connection()** method will initialize the internal state of each connection object.
We must call this method before the connection receive or send data.


Next, it's time to send some data to the server.
There are two important methods in Connection object which are,

- **send**
- **recv**

This is the only two methods that you need to deal with the connection object.
The following snippets shows how client send a greeting request to the server.


```python
from socks5 import GreetingRequest, GreetingResponse
from socks5 import VERSION, AUTH_TYPE

client_event = GreetingRequest(VERSION, [AUTH_TYPE["NO_AUTH"]])
raw_data = client_conn.send(event)

_event = server_conn.recv(raw_data)
if AUTH_TYPE["NO_AUTH"] in server_event.auth_type:
    server_event = GreetingResponse(VERSION, AUTH_TYPE["NO_AUTH"])
else:
    server_event = GreetingResponse(VERSION, AUTH_TYPE["NO_SUPPORTED_AUTH_METHOD"])

raw_data = server_conn.send(server_event)

_event = client_conn.recv(raw_data)
```

A simple walk through of the above example,

0. client first send a greeting request with auth type no auth.
1. server receive the raw data and check if client supported the no auth auth type.
  - if client support no auth, the greeting response will use no auth.
  - if client does not support no auth, a no supported auth method will be returned.
2. server send a greeting response to the client.
3. client receive the greeting response

On the above example, we have also introducecd the GreetingRequest/GreetingResponse event.

Event is a very important concept in socks5. An Event object abstract the socks5 raw data away.
There are seven types of event in socks5 which are,

- GreetingRequest
- GreetingResponse
- AuthRequest
- AuthResponse
- Request
- Response
- NeedMoreData

We will discussed these events in more detailed in later section.

From the example, the client side first use GreetingRequest to construct a greeting request event and
pass the event to the **client_conn.send** method. After that the method will return a raw data to you.

The server side then calling **server_conn.recv(raw_data)** to retrieve an event object.
And use the auty_type field of the GreetingRequest event.

When the check is complete, the server side create a new GreetingResponse event and pass to the **server_conn.send** method.
Just like the **client_conn.send**, it **send** method will return raw data to you.

In reality, the **raw_data** are the underlying IO layer such as the following code snippets.

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(host, port)

client_conn = ClientConnection()
client_conn.initiate_connection()
client_event = GreetingRequest(VERSION, [AUTH_TYPE["NO_AUTH"]])
raw_data = client_conn.send(event)
sock.send(raw_data)

raw_data = sock.recv(1024)
event = client_conn.recv(raw_data)
```

There are more realistic examples in the examples folder.

## LICENSE:
MIT

