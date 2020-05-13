from . utils import clean_traffic
from . context import (ContextLocal, ContextCommunication,
                       ContextClient, ContextServer)

import subprocess
import pickle
from typing import Tuple, List, Optional

import pyroute2


def create_virtual_link(ns_a: pyroute2.IPRoute, ctx_a: ContextLocal,
                        ns_b: pyroute2.NetNS, ctx_b: ContextLocal):
    """Create virtual link from specified contexts."""
    peer = {"ifname": ctx_b.iface, "net_ns_fd": ns_b.netns}

    ns_a.link("add", ifname=ctx_a.iface, kind="veth", peer=peer)

    for ns, ctx in ((ns_a, ctx_a),
                    (ns_b, ctx_b)):
        index = ns.link_lookup(ifname=ctx.iface)[0]

        ctx.index = index
        if ctx.ether:
            ns.link("set", index=index, address=ctx.ether)
        else:
            ctx.ether = ns.get_links(index)[0].get_attr("IFLA_ADDRESS")

        if ctx.inet:
            ns.addr("add", index=index, address=ctx.inet, mask=ctx.mask)
        if ctx.inet6:
            ns.addr("add", index=index, address=ctx.inet6, mask=ctx.mask6)

        ns.link("set", index=index, state="up")


def create_virtual_server(
        ns_client, client_ctx_traf, client_ctx_comm,
        ns_server, server_ctx_traf, server_ctx_comm
) -> subprocess.Popen:
    """
    Create a server process in separate network namespace,
    connect it by virtual links and start it.
    Returns the process of the created server.
    """
    server_ctx_comm_ = ContextLocal(server_ctx_traf.iface + "_comm",
                                    inet=server_ctx_comm.inet,
                                    mask=server_ctx_comm.mask)
    client_ctx_comm_ = ContextLocal(client_ctx_traf.iface + "_comm",
                                    inet=client_ctx_comm.inet,
                                    mask=client_ctx_comm.mask)

    create_virtual_link(ns_client, client_ctx_traf,
                        ns_server, server_ctx_traf)
    create_virtual_link(ns_client, client_ctx_comm_,
                        ns_server, server_ctx_comm_)

    to_run = [
        "python3", "-m", "xdp_test_harness.server",
        pickle.dumps(ContextServer(
            server_ctx_traf, server_ctx_comm,
        ), 0).decode()
    ]

    if hasattr(ns_server, "netns"):
        server_process = pyroute2.NSPopen(ns_server.netns, to_run)
    else:
        server_process = subprocess.Popen(to_run)

    return server_process


def create_virtual_servers_from_list(
        to_create: List[Tuple[
            ContextLocal, ContextCommunication,
            str, ContextLocal, ContextCommunication
        ]], client_netns_name: Optional[str]
) -> Tuple[List[subprocess.Popen], List[pyroute2.NetNS]]:
    """
    Create virtual servers from contexts specified in a list.
    Returns a list containing processes of created servers
    and a list containing their network namespaces.
    """
    created_servers = []
    netns = {}

    netns[None] = pyroute2.IPRoute()

    for (cl, cc, sn, sl, sc) in to_create:
        if sn not in netns:
            netns[sn] = pyroute2.NetNS(sn)
            clean_traffic("default", netns[sn])
        new_server = create_virtual_server(netns[client_netns_name], cl, cc,
                                           netns[sn], sl, sc)
        created_servers.append(new_server)

    netns.pop(None)

    return (created_servers, list(netns.values()))
