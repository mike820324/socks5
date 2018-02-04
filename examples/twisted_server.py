"""
This is a simple SOCKS5 server implementation based on Twisted.
Use it for educational purpose.

USAGE: twisted_server.py [LISTEN_PORT]

This does little error handling and is not designed for production.

Any production ready code should be contributed upstream to Twisted.

Terminology:

* "remote peer" is the peer to which we connect on behalf of the client.
* "client" - is the socks5 client requested this server to connect to the
             remote peer.

Also check proxy65 for a pure Twisted implementation
* https://code.google.com/archive/p/proxy65/ - Original. Google Code is Dead.
* https://github.com/mmatuska/proxy65 - GitHub Clone
"""
from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
    )

import sys

import ipaddress
from twisted.internet import reactor
from twisted.internet.endpoints import (
    connectProtocol,
    serverFromString,
    TCP4ClientEndpoint,
    )
from twisted.internet.protocol import Protocol, ServerFactory
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log

import socks5
from socks5.auth import rfc1929

# Credentials which are accepted by the server.
ACCEPTED_USERNAME = 'test'
ACCEPTED_PASSWORD = 'pass'

# Don't know why socks5 doesn't have this as constant.
SOCKS5_NEED_MORE = 'NeedMoreData'


class STATE(object):
    """
    The states of the server.
    """
    # Initial state before the first message is exchanged with the client.
    INITIALIZING = 'Initializing'
    # While we are waiting for credentials from the client.
    AUTHENTICATING = 'Authenticating'
    # Client was successfully authenticated.
    AUTHENTICATED = 'Authenticated'
    # While we are connecting to the remote peer.
    CONNECTING = 'Connecting'
    # Once we are connected to the remote peer.
    CONNECTED = 'Connected'


class _PeerConnection(Protocol):
    """
    Handles the connection to the remote peer, as requested by a socks client.

    It just forwards the events to the main server connection.
    """
    def __init__(self, server):
        self._server = server

    def connectionMade(self):
        """
        Called when we got a connection to the remote peer.
        """
        self._server.peerConnectionMade(self, self.transport.getPeer())

    def connectionLost(self, reason):
        """
        Called when we lost connect to the remote peer.
        """
        self._server.peerConnectionLost(reason)
        
    def loseConnection(self):
        """
        Called when we want to close the connection to the remote peer.
        """
        self.transport.loseConnection()

    def write(self, data):
        """
        Called when the client sends data to the remote peer.
        """
        self.transport.write(data)

    def dataReceived(self, data):
        """
        This is called when we receive data from the remote peer.
        """
        self._server.peerDataReceived(data)


class SOCKS5Server(Protocol, TimeoutMixin):
    """
    Handler for a socks5 connection for the server side.
    """
    _TIMEOUT = 60

    def __init__(self):
        self._state = STATE.INITIALIZING
        # Connection to the remote peer.
        self._remotePeer = None
        # Due to the API design, for authenticated request we need to
        # switch back and forth between different connection types.
        self._mainConnection = socks5.Connection(our_role="server")
        self._authConnection = rfc1929.Connection(our_role="server")
        # Start with the main connection.
        self._socksConnection = self._mainConnection

    def connectionMade(self):
        """
        Called when the client connects to us.
        """
        self.setTimeout(self._TIMEOUT)
        self._socksConnection.initiate_connection()

    def peerConnectionMade(self, protocol, address):
        """
        Called when we are connected to the remote peer.
        """
        self._remotePeer = protocol
        # Let the client know that we were successfully connected.
        response = socks5.Response(
            socks5.RESP_STATUS['SUCCESS'],
            1,  # Only IPV4 is supported.
            ipaddress.IPv4Address(address.host.decode('ascii')),
            address.port,
            )
        self._sendResponse(response)

    def _sendResponse(self, response):
        """
        Send the SOCKS5 response to the client.
        """
        self.transport.write(self._socksConnection.send(response))

    def connectionLost(self, reason):
        """
        Connection lost to the client.
        """
        log.msg(reason)
        if self._remotePeer:
            self._remotePeer.loseConnection()

    def peerConnectionLost(self, reason):
        """
        Connection lost to the remote peer.
        """
        log.msg(reason)
        self.transport.loseConnection()

    def dataReceived(self, data):
        """
        This is called when we receive data from the client.
        """
        self.resetTimeout()

        if self._state == STATE.CONNECTED:
            # We are already connected so we just forward the data from the
            # client to the remote peer.
            self._remotePeer.write(data)
            return

        event = self._socksConnection.recv(data)

        if event == SOCKS5_NEED_MORE:
            # Not ready to enter any other state now.
            return

        if self._state == STATE.INITIALIZING:
            if not isinstance(event, socks5.GreetingRequest):
                return self._failGeneral('Was waiting for a greeting request.')

            return self._onAuthRequest(event)

        if self._state == STATE.AUTHENTICATING:
            if not isinstance(event, rfc1929.AuthRequest):
                return self._failGeneral('Was waiting for an auth request.')

            return self._onAuthReceived(event)

        if self._state == STATE.AUTHENTICATED:
            if not isinstance(event, socks5.Request):
                return self._failGeneral('Was waiting for a connect request.')

            return self._onConnectRequest(event)

        self._failGeneral('Request received out of order.')

    def peerDataReceived(self, data):
        """
        Data received from the remote peer.
        """
        self.resetTimeout()
        # Just forward the data as the client.
        self.transport.write(data)

    def _onAuthRequest(self, event):
        """
        Called when we got an authentication request.
        """
        if socks5.AUTH_TYPE["USERNAME_PASSWD"] in event.methods:
            # We are already authenticated for anon requests.
            self._state = STATE.AUTHENTICATING
            response = socks5.GreetingResponse(
                socks5.AUTH_TYPE["USERNAME_PASSWD"])
            self._sendResponse(response)

            # Switch to AUTH protocol.
            self._socksConnection = self._authConnection
            self._socksConnection.initiate_connection()

        elif socks5.AUTH_TYPE["NO_AUTH"] in event.methods:
            # We are already authenticated for anon requests.
            self._state = STATE.AUTHENTICATED
            response = socks5.GreetingResponse(socks5.AUTH_TYPE["NO_AUTH"])
            return self._sendResponse(response)
        else:
            # At this point, there is no match between the auth methods
            # supported by the client and the server.
            return self._failAuthNotSupported(event)

    def _onAuthReceived(self, event):
        """
        Called when we got the authentication details from the client.
        """
        if (
            event.username == ACCEPTED_USERNAME and
            event.password == ACCEPTED_PASSWORD
                ):
            # Credentials are valid.
            self._state = STATE.AUTHENTICATED
            status = socks5.RESP_STATUS["SUCCESS"]
            response = rfc1929.AuthResponse(status)
            self._sendResponse(response)
            # Switch back to main protocol.
            self._socksConnection = self._mainConnection
            self._socksConnection.auth_end()
            return
        else:
            log.msg('AUTH rejected for %s:%s' % (
                event.username, event.password))
            status = socks5.RESP_STATUS["GENRAL_FAILURE"]
            response = rfc1929.AuthResponse(status)
            self._sendResponse(response)
            # The connection should be closed when authentication fails.
            self.transport.loseConnection()

    def _failAuthNotSupported(self, event):
        """
        Called when the client requested an authentication method which
        we don't support.
        """
        log.mgs(
            'Requested auth methods are not supported %s.' % (event.methods))
        response = socks5.GreetingResponse(
            socks5.AUTH_TYPE["NO_SUPPORT_AUTH_METHOD"])
        self._sendResponse(response)
        self.transport.loseConnection()

    def _onConnectRequest(self, event):
        """
        Called when the client request to connect to a remote peer.
        """
        if event.atyp != 1:
            return _failGeneral(details='Only IPV4 is supported.', event=event)

        self._state = STATE.CONNECTING
        log.msg('Initiating connection to (%s) %s:%s' % (
            event.atyp, event.addr, event.port))
        # Pause any data from client while we are connecting.
        self.transport.stopReading()

        def cb_peer_connected(protocol):
            """
            Called when we are connected to the remote peer as requested
            by the socks client.
            """
            self._state = STATE.CONNECTED
            # Ready to receive data from the client.
            self.transport.startReading()

        def eb_peer_connected(failure):
            """
            Called when we fail to connect to the peer.
            """
            log.msg(failure)
            self._failGeneral(
                details='Fail to connect to remote peer.', event=event)

        # Only TCP4 is supported.
        # `event.atyp` contains the protocol.
        self._remoteEndpoint = TCP4ClientEndpoint(
            reactor,
            host=str(event.addr),
            port=event.port,
            timeout=self._TIMEOUT,
            )
        deferred = connectProtocol(self._remoteEndpoint, _PeerConnection(self))

        deferred.addCallback(cb_peer_connected)
        deferred.addErrback(eb_peer_connected)

    def _failGeneral(self, details, event=None):
        """
        Called when we got a critical failure and client connection
        can't continue.
        """
        log.msg(details)
        if event:
            host = event.addr
            port = event.port
        else:
            host = ipaddress.IPv4Address('0.0.0.0')
            port = 0

        # FIXME: I am not sure how to respond to a failure
        # and if there is a type here.
        # https://github.com/mike820324/socks5/issues/17
        response = socks5.Response(
            socks5.RESP_STATUS['GENRAL_FAILURE'],
            1,
            host,
            port,
            )
        self._sendResponse(response)
        self.transport.loseConnection()


if __name__ == '__main__':
    """
    Rigging the TCP server.
    """
    log.startLogging(sys.stderr)
    try:
        port = int(sys.argv[1])
    except IndexError:
        port = 8899

    serverEndpointStr = "tcp:{0}".format(port)
    endpoint = serverFromString(reactor, serverEndpointStr.encode('ascii'))
    # Don't care what the deferred returned by listen is as no error
    # handling is provided.
    endpoint.listen(ServerFactory.forProtocol(SOCKS5Server))
    reactor.run()
