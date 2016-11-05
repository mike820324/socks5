from __future__ import absolute_import, division, print_function, unicode_literals

from construct import this, If, Switch, OneOf
from construct import Struct, Enum, Array, Embedded
from construct import Byte, BytesInteger, Int8ub, Int16ub, Padding
from construct import PascalString, CString

ReqCommand = Enum(
    Byte,
    CONNECT=0x1,
    BIND=0x02,
    UDP_ASSOCIATE=0x03
)

RespStatus = Enum(
    Byte,
    SUCCESS=0x0,
    GENRAL_FAILURE=0x01,
    CONNECTION_NOT_ALLOWED=0x02,
    NETWORK_UNREACHABLE=0x03,
    HOST_UNREACHABLE=0x04,
    CONNECTION_REFUSED=0x05,
    TTL_EXPIRED=0x06,
    COMMAND_NOT_SUPPORTED=0x07,
    ADDRESS_TYPE_NOT_SUPPORTED=0x08
)

AddrType = Enum(
    Byte,
    IPV4=0x01,
    DOMAINNAME=0x03,
    IPV6=0x04
)

Requestv4 = Struct(
    "cmd" / Byte,
    "port" / Int16ub,
    "addr" / BytesInteger(4),
    "name" / CString(),
    "domainname" / If(this.addr == 1, CString())
)

Responsev4 = Struct(
    "status" / Byte,
    "port" / Int16ub,
    "addr" / BytesInteger(4),
)

GreetingRequest = Struct(
    "version" / OneOf(Int8ub, [4, 5]),
    Embedded(
        Switch(
            this.version,
            {
                0x4: Requestv4,
                0x5: Struct(
                    "nmethod" / Int8ub,
                    "methods" / Array(this.nmethod, Byte)
                )
            }
        )
    )
)

GreetingResponse = Struct(
    "version" / OneOf(Int8ub, [0, 5]),
    Embedded(
        Switch(
            this.version,
            {
                0x0: Responsev4,
                0x5: Struct(
                    "auth_type" / Int8ub
                )
            }
        )
    )
)

Request = Struct(
    "version" / OneOf(Int8ub, [5]),
    "cmd" / Byte,
    Padding(1),
    "atyp" / Byte,
    "addr" / Switch(
        this.atyp,
        {
            0x1: BytesInteger(4),
            0x4: BytesInteger(16),
            0x3: PascalString(Byte)
        }
    ),
    "port" / Int16ub
)

Response = Struct(
    "version" / OneOf(Int8ub, [5]),
    "status" / Byte,
    Padding(1),
    "atyp" / Byte,
    "addr" / Switch(
        this.atyp,
        {
            0x1: BytesInteger(4),
            0x4: BytesInteger(16),
            0x3: PascalString(Byte)
        }
    ),
    "port" / Int16ub
)
