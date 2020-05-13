#!/usr/bin/env python3

import os
import argparse
import sys

from . utils import clean_traffic
from . virtual_config import virtual_ctxs
from . virtual_setup import create_virtual_servers_from_list
from . client import start_client
from . server import start_server
from . xdp_case import (XDPCaseNetwork, XDPCaseBPTR)
try:
    import config
except ImportError:
    print("Using default configuration.")
    import xdp_test_harness.default_config as config


def run_bptr(unittest_args):
    """Start a client in an offline mode."""
    ctxs = config.remote_server_ctxs

    ctxs.get_local_main().xdp_mode = None
    for i in range(ctxs.server_count()):
        if ctxs.get_remote(i) is None:
            print("BPTR mode requires all ContextClient "
                  "to have a predefined remote context.")
            return -1
        ctxs.get_local(i).index = i + 1

    res = start_client(ctxs, XDPCaseBPTR, unittest_args)

    return res


def run_client(unittest_args):
    """Build virtual servers and start a client using network."""
    created_servers_procs = []
    netns = []

    try:
        clean_traffic("default")

        (created_servers_procs, netns) = \
            create_virtual_servers_from_list(virtual_ctxs, None)

        for i in range(config.remote_server_ctxs.server_count()):
            clean_traffic(config.remote_server_ctxs.get_local(i).iface)

        res = start_client(config.remote_server_ctxs,
                           XDPCaseNetwork, unittest_args)
    finally:
        for i in created_servers_procs:
            try:
                i.terminate()
            except KeyboardInterrupt:
                pass
        for i in netns:
            i.close()
            i.remove()

    return res


def run_server():
    """Start a server with configuration from config.py."""
    config.local_server_ctx.local.fill_missing()
    clean_traffic(config.local_server_ctx.local.iface)
    start_server(config.local_server_ctx)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="""
    XDP testsuite

    For configuration, use the config.py file.

    Example usage:

    ./run.py client test_general.ReturnValuesBasic
    """)

    test_names = (
        "tests",
        {
            "help": """A list of patters defining tests to run.
            The patterns are using the unittest format -
            modules, classes and methods separated by dots.""",
            "nargs": argparse.REMAINDER,
            "default": None,
        }
    )

    type_subparser = parser.add_subparsers(dest="type", required=True)

    server_parser = type_subparser.add_parser(
        "server", help="Start a standalone response server."
    )

    client_parser = type_subparser.add_parser(
        "client", help="Start testing using a network."
    )
    client_parser.add_argument(test_names[0], **test_names[1])

    bptr_parser = type_subparser.add_parser(
        "bptr", help="Start testing using BPF_PROG_TEST_RUN command."
    )
    bptr_parser.add_argument(test_names[0], **test_names[1])

    return parser.parse_args()


def main():
    args = parse_args()
    res = 0

    if os.getuid() != 0:
        print("Admin privileges required.")
        sys.exit(-1)

    if args.type == "client":
        unittest_args = {"tests": args.tests}
        res = run_client(unittest_args)
    elif args.type == "server":
        run_server()
    elif args.type == "bptr":
        unittest_args = {"tests": args.tests}
        res = run_bptr(unittest_args)

    sys.exit(res)


if __name__ == "__main__":
    main()
