# socks5:
[![Build Status](https://travis-ci.org/mike820324/socks5.svg?branch=master)](https://travis-ci.org/mike820324/socks5)
[![Coverage Status](https://coveralls.io/repos/github/mike820324/socks5/badge.svg?branch=master)](https://coveralls.io/github/mike820324/socks5?branch=master)

**socks5** is a small module SOCKS version 5 library written fom scratch in Python,
which is highly inspired by [h11](https://github.com/njsmith/h11) and [hyper-h2](https://hyper-h2.readthedocs.io/en/stable/).


It's a "bring-your-own-IO" library; that is socks5 module does not contain any network related code.
socks5 only deal with the parsing and state management of the socks5 connection,
the underlying IO part is not cover in the internal code.

Currently, socks5 module support the following protocol and rfc.

- socks4
- socks4a
- socks5 : rfc 1928
- socks5 username/password authentication: rfc 1929

## Installation:

Since we have not upload to pypi yet.

```bash
pip install socks5
```

## Quick Guide:

Here I will walk through a simple socks5 client/server communication.

First thing first, we have to initiate a connection.
You can initiate a connection by using the following code snippets.

```python
from socks5 import Connection
client_conn = Connection(our_role="client")
client_conn.initiate_connection()

server_conn = Connection(our_role="server")
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
from socks5 import AUTH_TYPE

client_event = GreetingRequest([AUTH_TYPE["NO_AUTH"]])
raw_data = client_conn.send(event)

_event = server_conn.recv(raw_data)
if AUTH_TYPE["NO_AUTH"] in server_event.auth_type:
    server_event = GreetingResponse(AUTH_TYPE["NO_AUTH"])
else:
    server_event = GreetingResponse(AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"])

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

- Socks4Request
- Socks4Response
- GreetingRequest
- GreetingResponse
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
client_event = GreetingRequest([AUTH_TYPE["NO_AUTH"]])
raw_data = client_conn.send(event)
sock.send(raw_data)

raw_data = sock.recv(1024)
event = client_conn.recv(raw_data)
```

There are more realistic examples in the examples folder.

## API Reference:

This section will introduce the avaliable data structures and api.

### Connection:

In socks5 module, a connection object represent a connected connection.
The connection object helped the user handle the connection state and internal buffer data.
There are two kinds of connection class defined in socks5 module: **socks connection** and **rfc1929 connection**.

#### Socks Connection:

A socks connection class. Can import via **socks5** module.


The following are methods of this class.

- **Conncection(our_role: str)**: the our_role parameter can be either "client" or "server".
- **initiate_connection()**: initiate the internal state for the current connection.
- **auth_end()**: indicate the authentication progress has ended and can deal with rest of the protocol.
- **recv(data: bytes) -> Event**: feed the raw data to the connection and return the corresponding events.
- **send(event: Event) -> bytes**: feed the event and return the corresponding raw data.

#### RFC1929 Auth Connection:

A RFC1929 Username/Password Auth connection class. Can import via **socks5.auth.rfc1929**.

The following are the methods within this class:

- **Conncection(our_role: str)**: the our_role parameter can be either "client" or "server"
- **initiate_connection()**: initiate the internal state for the current connection.
- **recv(data: bytes) -> Event**: feed the raw data to the connection and return the corresponding events.
- **send(event: Event) -> bytes**: feed the event and return the corresponding raw data.

### Events:

An event abstract the socks protocol related data away from the user.
Every socks 5 communication data is an event object in socks5. 
Currently, there are three events categories which are, **socks4**, **socks5** and **rfc 1929**.

#### Socks4 Events:

There are only two events in socks4 protocol implementation.

- **Socks4Request(cmd: int, addr: (unicode or int), port: int, username: unicode, domainname: unicode)**:

Socks4Request represent the socks4 request sent from the client.
The type of the addr should be a IPv4Address compatible type.


Example Usage:

```python
event = Socks4Request(REQ_COMMAND["CONNECT"], "192.168.0.1", 5580, "Johnny")

# Socks4a domainname support
event = Socks4Request(REQ_COMMAND["CONNECT"], "0.0.0.1", 5580, "Johnny", "www.google.com")
```

- **Socks4Response(status: int, addr: (unicode or int), port: int)**:

Socks4Response represent the socks4 resposne sent from the server.
The type of the addr should be a IPv4Address compatible type.


Example Usage:

```python
event = Socks4Response(RESP_STATUS["REQUEST_GRANTED"], "192.168.0.1", 5580)
```

#### Socks5 Events:

There are four events in socks5 protocol implementation.

- **GreetingRequest(methods: list[int])**:

An initial socks5 greeting request sent from the client.
The user only need to supply the supported methods.


Example usage:

```python
event = GreetingRequest([AUTH_TYPE["NO_AUTH"]])

# Support rfc1929
event = GreetingRequest([AUTH_TYPE["NO_AUTH"], AUTH_TYPE["USERNAME_PASSWD"]])
```

- **GreetingResponse(auth_type: int)**:

An initial socks5 greeting response sent from the server.
The auth_type is the authentication type the server choose.


Example usage:

```python
event = GreetingResponse(AUTH_TYPE["NO_AUTH"])

# Support rfc1929
event = GreetingResponse(AUTH_TYPE["USERNAME_PASSWD"])

# No Support method
event = GreetingResponse(AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"])
```

- **Request(cmd: int, atyp: int, addr: (unicode or int), port: int)**:

The socks5 request sent from the client.
One things to notice is that the addr type should be an ipaddress compatible type.


Example usage:

```python
event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV4"], "192.168.0.1", 5580)

# ipv6
event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["IPV6"], "::1", 5580)

# domain name
event = Request(REQ_COMMAND["CONNECT"], ADDR_TYPE["DOMAINNAME"], "www.google.com", 5580)
```

- **Response(status: int, atyp: int, addr: (unicode or int), port: int)**:

The socks5 response sent from the server.
One things to notice is that the addr type should be an ipaddress compatible type.


Example Usage:

```python
event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV4"], "192.168.0.1", 5580)

# ipv6
event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["IPV6"], "::1", 5580)

# domain name
event = Response(RESP_STATUS["SUCCESS"], ADDR_TYPE["DOMAINNAME"], "www.google.com", 5580)
```

#### RFC 1929 Username/Password Auth Events:

The rfc 1929 events can imported from **socks5.auth.rfc1929** modules.

- **AuthRequest(username: unicode, password: unicode)**:

The username/password authentication request defined in RFC1929.


Example Usage:

```python
event = AuthRequest("username", "password")
```
- **AuthResponse(status: int)**:

The username/password authentication response defined in RFC1929.


Example Usage:

```python
event = AuthResponse(RESP_STATUS["SUCCESS"])
```

### Misc:
- **NeedMoreData()**:

This event indicate the raw data is not enough to parsed the current event.
This event **should not** be used directly, only the connection object will return the event to you.

## Future Works:

- socks5 gssapi authentication: rfc 1961

## LICENSE:
MIT
