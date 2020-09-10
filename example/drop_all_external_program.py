#!/usr/bin/env python3

import time
import sys

import bcc

if __name__ == "__main__":
    iface = sys.argv[1].encode()
    prog = bcc.BPF(text="""
	int dropper(struct xdp_md *ctx) {
		return XDP_DROP;
	}
	""")

    try:
        print("attached")
        prog.attach_xdp(iface, prog.load_func("dropper", bcc.BPF.XDP))
        time.sleep(120)
    except:
        print("stopped")
    finally:
        print("removing")
        prog.remove_xdp(iface)
