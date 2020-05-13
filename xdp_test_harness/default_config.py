from . utils import XDPFlag
from . context import (ContextLocal, ContextRemote, ContextCommunication,
                       ContextClient, ContextServer, ContextClientList)
from . virtual_config import new_virtual_ctx

"""
Context used when running a standalone server.
"""
local_server_ctx = ContextServer(
    ContextLocal("enp0s31f6"),
    ContextCommunication("192.168.0.106", 6555),
)

"""
List of servers to be used while running a client.
"""
remote_server_ctxs = ContextClientList([
    new_virtual_ctx(
        ContextLocal("a_to_b", xdp_mode=XDPFlag.DRV_MODE,
                     inet="192.168.3.1", inet6="fe80::388a:7eff:fe49:1111"),
        ContextCommunication("192.168.1.1"),
        "test_b",
        ContextLocal("b_to_a", xdp_mode=XDPFlag.DRV_MODE,
                     inet="192.168.4.1", inet6="fe80::388a:7eff:fe49:2222"),
        ContextCommunication("192.168.1.2", 6000),
    ),
])
