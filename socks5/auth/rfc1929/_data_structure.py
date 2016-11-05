from __future__ import absolute_import, division, print_function, unicode_literals

from construct import this, If, Switch, OneOf
from construct import Struct
from construct import Byte, Int8ub
from construct import PascalString

AuthRequest = Struct(
    "version" / OneOf(Int8ub, [1]),
    "username" / PascalString(Byte),
    "password" / PascalString(Byte)
)

AuthResponse = Struct(
    "version" / OneOf(Int8ub, [1]),
    "status" / Byte
)
