from . context import ContextLocal, ContextCommunication, ContextClient

from typing import Tuple, List, Optional

"""
List of virtual servers to be created.
Defined as (client_{netns, local, comm}, server_{...}).
"""
virtual_ctxs: List[Tuple[
    ContextLocal, ContextCommunication,
    str, ContextLocal, ContextCommunication
]] = []


def new_virtual_ctx(client_traf: ContextLocal,
                    client_comm: ContextCommunication,
                    server_netns: str,
                    server_traff: ContextLocal,
                    server_comm: ContextCommunication) -> ContextClient:
    new = (
        client_traf, client_comm,
        server_netns, server_traff, server_comm
    )

    virtual_ctxs.append(new)
    return ContextClient(new[0], new[4], new[3].get_remote())
