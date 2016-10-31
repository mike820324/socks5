from construct import this
from construct import Struct, Enum, Switch, Array
from construct import Byte, BytesInteger, Int8ub, Int16ub, Padding
from construct import PascalString

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

GreetingRequest = Struct(
    "version" / Int8ub,
    "nmethod" / Int8ub,
    "methods" / Array(this.nmethod, Byte)
)

GreetingResponse = Struct(
    "version" / Int8ub,
    "auth_type" / Int8ub
)

AuthRequest = Struct(
    "version" / Int8ub,
    "username" / PascalString(Byte),
    "password" / PascalString(Byte)
)

AuthResponse = Struct(
    "version" / Int8ub,
    "status" / Byte
)

Request = Struct(
    "version" / Int8ub,
    "cmd" / Byte,
    Padding(1),
    "atyp" / Byte,
    "addr" / Switch(
        this.atyp,
        {
            0x1: BytesInteger(4),
            0x4: BytesInteger(16),
            0x3: PascalString(Byte, encoding="ascii")
        }
    ),
    "port" / Int16ub
)
Response = Struct(
    "version" / Int8ub,
    "status" / Byte,
    Padding(1),
    "atyp" / Byte,
    "addr" / Switch(
        this.atyp,
        {
            0x1: BytesInteger(4),
            0x4: BytesInteger(16),
            0x3: PascalString(Byte, encoding="ascii")
        }
    ),
    "port" / Int16ub
)
