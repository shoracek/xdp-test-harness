#!/usr/bin/env python3

import sys
import unittest
import pickle

from . import xdp_case


def start_client(ctx, target_xdp_case, unittest_args=None):
    xdp_case.XDPCase = target_xdp_case
    xdp_case.XDPCase.set_context(ctx)
    xdp_case.XDPCase.prepare_class()

    # delayed tests.py -- this prevents having to hack the bases of the XDPCase
    # and postpones the evaluation of decorators (e.g. unittest.skipIf), but
    # this is also kinda hacky...

    if unittest_args["tests"]:
        suite = unittest.defaultTestLoader.loadTestsFromNames(
            unittest_args["tests"]
        )
    else:
        suite = unittest.defaultTestLoader.discover(".")

    runner = unittest.TextTestRunner(verbosity=3)

    res = runner.run(suite)

    return len(res.failures)


if __name__ == "__main__":
    sys.exit(start_client(pickle.loads(sys.argv[1].encode()),
                          pickle.loads(sys.argv[2].encode())))
