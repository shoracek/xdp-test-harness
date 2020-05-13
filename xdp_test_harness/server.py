#!/usr/bin/env python3

import sys
import multiprocessing.connection
import pickle
import atexit

from scapy.all import conf, sendp, Ether
import bcc

from . import utils


def send_packets(iface, packets, conn):
    packets = list(map(lambda p: Ether(bytes(p)), packets))
    sniffer = utils.wait_for_async_sniffing(iface=iface)

    sendp(packets, iface=iface)

    conn.send(utils.ServerResponse.FINISHED)

    assert conn.recv() == utils.ServerCommand.STOP
    if sniffer.running:
        sniffer.stop()

    conn.send(sniffer.results)


def watch_traffic(iface, conn):
    sniffer = utils.wait_for_async_sniffing(iface=iface)
    assert conn.recv() == utils.ServerCommand.STOP
    sniffer.stop()
    conn.send(sniffer.results)


def introduce_self(local_ctx, conn):
    conn.send(local_ctx.get_remote())


def start_server(ctx):
    # Load xdp program to fix redirection in veth.
    if ctx.local.xdp_mode:
        prog = bcc.BPF(
            text=b"""int dummy(struct xdp_md *ctx) { return XDP_PASS; }"""
        )
        func = prog.load_func(b"dummy", bcc.BPF.XDP)
        prog.attach_xdp(ctx.local.iface.encode(), func, ctx.local.xdp_mode)

        atexit.register(prog.remove_xdp, ctx.local.iface.encode())

    listener = multiprocessing.connection.Listener(
        (ctx.comm.inet, ctx.comm.port)
    )

    print(f"Server started: {ctx}.")
    while True:
        conn = None
        try:
            conn = listener.accept()
            data = conn.recv()
            if data[0] == utils.ServerCommand.SEND:
                send_packets(ctx.local.iface, data[1], conn)
            elif data[0] == utils.ServerCommand.WATCH:
                watch_traffic(ctx.local.iface, conn)
            elif data[0] == utils.ServerCommand.INTRODUCE:
                introduce_self(ctx.local, conn)
        except Exception as e:
            conn.send(e)
        finally:
            if conn:
                conn.close()


if __name__ == "__main__":
    conf.verb = 0

    start_server(pickle.loads(sys.argv[1].encode()))
