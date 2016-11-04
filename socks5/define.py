from __future__ import absolute_import, division, print_function, unicode_literals

AUTH_TYPE = {
    "NO_AUTH": 0x0,
    "GSSAPI": 0x1,
    "USERNAME_PASSWD": 0x2,
    "NO_SUPPORT_AUTH_METHOD": 0xFF
}

REQ_COMMAND = {
    "CONNECT": 0x1,
    "BIND": 0x02,
    "UDP_ASSOCIATE": 0x03
}

RESP_STATUS = {
    # socksv5 response status
    "SUCCESS": 0x0,
    "GENRAL_FAILURE": 0x01,
    "CONNECTION_NOT_ALLOWED": 0x02,
    "NETWORK_UNREACHABLE": 0x03,
    "HOST_UNREACHABLE": 0x04,
    "CONNECTION_REFUSED": 0x05,
    "TTL_EXPIRED": 0x06,
    "COMMAND_NOT_SUPPORTED": 0x07,
    "ADDRESS_TYPE_NOT_SUPPORTED": 0x08,

    # socksv4/socksv4a response status
    "REQUEST_GRANTED": 0x5a,
    "REQUEST_REJECTED": 0x5b,
    "REQUEST_FAIELD_NO_IDENTD": 0x5c,
    "REQUEST_FAIELD_IDENTD_AUTH_FAIL": 0x5d

}

ADDR_TYPE = {
    "IPV4": 0x01,
    "DOMAINNAME": 0x03,
    "IPV6": 0x04
}
