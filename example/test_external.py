import subprocess
import time
import os
import signal

import unittest

from xdp_test_harness.xdp_case import XDPCase, usingCustomLoader

"""
An example of running an external program, that attaches an XDP program.
"""


@usingCustomLoader
class SpecialCase(XDPCase):
    def test_first(self):
        proc = subprocess.Popen(["./drop_all_external_program.py",
                                 self.get_contexts().get_local_main().iface],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(1)

        res = self.send_packets(self.generate_default_packets())

        # os.kill(proc.pid, signal.SIGINT)
        proc.send_signal(signal.SIGINT)
        proc.wait()

        self.assertPacketContainerEmpty(res.captured_local)
        for i in res.captured_remote:
            self.assertPacketContainerEmpty(i)
