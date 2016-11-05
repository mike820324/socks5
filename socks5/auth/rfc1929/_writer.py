from __future__ import absolute_import, division, print_function, unicode_literals

from ._data_structure import AuthRequest, AuthResponse


def write_auth_request(event):
    event_dict = event.__dict__

    event_dict["version"] = 1
    event_dict["username"] = event.username.encode("ascii")
    event_dict["password"] = event.password.encode("ascii")
    return AuthRequest.build(event_dict)


def write_auth_response(event):
    event_dict = event.__dict__

    event_dict["version"] = 1
    return AuthResponse.build(event_dict)
