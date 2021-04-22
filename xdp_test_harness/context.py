import dataclasses
from typing import (Optional, Iterable)

import pyroute2

from . utils import XDPFlag


@dataclasses.dataclass
class ContextRemote:
    """Information about remote interface."""
    ether: Optional[str] = None
    inet: Optional[str] = None
    inet6: Optional[str] = None


@dataclasses.dataclass
class ContextLocal:
    """Information about local interface."""
    iface: str
    xdp_mode: Optional[XDPFlag] = None
    index: int = None
    ether: str = None
    inet: Optional[str] = None
    mask: Optional[int] = 24
    inet6: Optional[str] = None
    mask6: Optional[int] = 64

    def get_remote(self):
        return ContextRemote(self.ether, self.inet, self.inet6)

    def fill_missing(self, ipr: Optional[pyroute2.NetNS] = None):
        if ipr is None:
            ipr = pyroute2.IPRoute()

        if self.index is None:
            res = ipr.link_lookup(ifname=self.iface)
            if len(res) != 1:
                raise RuntimeError("Could not find interface", self.iface)
            self.index = res[0]

        link = ipr.get_links(self.index)[0]
        if self.ether is None:
            for i in link["attrs"]:
                if i[0] == "IFLA_ADDRESS":
                    self.ether = i[1]
                    break

        addr = ipr.get_addr()
        if self.inet is None:
            for i in addr:
                if i["index"] == self.index and i["family"] == socket.AF_INET:
                    self.inet = i.get_attr("IFA_ADDRESS")
        if self.inet6 is None:
            for i in addr:
                if i["index"] == self.index and i["family"] == socket.AF_INET6:
                    self.inet6 = i.get_attr("IFA_ADDRESS")

        ipr.close()


@dataclasses.dataclass
class ContextCommunication:
    """Context of a TCP connection."""
    inet: str
    port: Optional[int] = None
    mask: int = 24


@dataclasses.dataclass
class ContextClient:
    """Context of a connection of a client to a server."""

    def __init__(self, local, comm=None, remote=None):
        self.local = local
        self.remote = remote
        self.comm = comm

    local: ContextLocal
    remote: ContextRemote
    comm: ContextCommunication


class ContextClientList:
    """Collection of all ContextClient used by the harness."""

    def __init__(self, ctx_list: Iterable[ContextClient]):
        self.locals = [c.local for c in ctx_list]
        self.remotes = [c.remote for c in ctx_list]
        self.comms = [c.comm for c in ctx_list]

    def server_count(self) -> int:
        return len(self.locals)

    def iface_index_to_id(self, index: int) -> int:
        for i in range(self.server_count()):
            if self.get_local(i).index == index:
                return i
        return -1

    def get_local(self, i: int) -> ContextLocal:
        return self.locals[i]

    def get_remote(self, i: int) -> ContextRemote:
        return self.remotes[i]

    def get_local_main(self) -> ContextLocal:
        return self.get_local(0)

    def get_remote_main(self) -> ContextRemote:
        return self.get_remote(0)


@dataclasses.dataclass
class ContextServer:
    """Context of a local server."""
    local: ContextLocal
    comm: ContextCommunication
