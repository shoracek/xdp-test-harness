import ctypes
import os

import unittest
import bcc
from scapy.all import Ether

from xdp_test_harness.xdp_case import XDPCase


class ReturnValuesBasic(XDPCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.prog = cls.load_bpf(b"return_values.c")

        cls.to_send = cls.generate_default_packets()

        cls.exception_counter = bcc.BPF(text=b"""
        BPF_ARRAY(counter, int, 1);
        int prog(void *ctx) {
            counter.increment(0);
            return 0;
        }
        """)

    def test_pass(self):
        self.attach_xdp("pass_all")

        result = self.send_packets(self.to_send)

        self.assertPacketsIn(self.to_send, result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)

    def test_drop(self):
        self.attach_xdp("drop_all")

        result = self.send_packets(self.to_send)

        self.assertPacketContainerEmpty(result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)

    def test_aborted(self):
        self.attach_xdp("aborted_all")

        self.exception_counter.attach_tracepoint(
            b"xdp:xdp_exception", fn_name=b"prog")
        counter = self.exception_counter[b"counter"]
        counter[0].value = 0

        result = self.send_packets(self.to_send)

        self.assertGreaterEqual(counter[0].value, len(self.to_send))
        self.assertPacketContainerEmpty(result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)

    def test_tx(self):
        self.attach_xdp("tx_all")

        result = self.send_packets(self.to_send)

        self.assertPacketsIn(self.to_send, result.captured_remote[0])
        self.assertPacketContainerEmpty(result.captured_local)
        for i in result.captured_remote[1:]:
            self.assertPacketContainerEmpty(i)


class HelperFunctionsAdjustSize(XDPCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.prog = cls.load_bpf(b"helper_functions.c",
                                cflags=["-DBYTES_DELTA=5"])

        cls.to_send = cls.generate_default_packets()

    def test_adjust_tail_decrease_size(self):
        self.attach_xdp("remove_bytes_from_tail")

        result = self.send_packets(self.to_send)

        for original in self.to_send:
            shortened = Ether(bytes(original)[:-5])
            self.assertPacketIn(shortened, result.captured_local)
            self.assertPacketNotIn(original, result.captured_local)

    def test_adjust_head_decrease_size(self):
        self.attach_xdp("remove_bytes_from_head")

        result = self.send_packets(self.to_send)

        for original in self.to_send:
            shortened = Ether(bytes(original)[5:])
            self.assertPacketIn(shortened, result.captured_local)
            self.assertPacketNotIn(original, result.captured_local)

    @unittest.expectedFailure
    def test_adjust_tail_increase_size(self):
        self.attach_xdp("add_bytes_to_tail")

        result = self.send_packets(self.to_send)

        for original in self.to_send:
            padded = Ether(bytes(original) + b"\x00" * 5)
            self.assertPacketIn(padded, result.captured_local)
            self.assertPacketNotIn(original, result.captured_local)

    @unittest.expectedFailure
    def test_adjust_head_increase_size(self):
        self.attach_xdp("add_bytes_to_head")

        result = self.send_packets(self.to_send)

        for original in self.to_send:
            padded = Ether(b"\x00" * 5 + bytes(original))
            self.assertPacketIn(padded, result.captured_local)
            self.assertPacketNotIn(original, result.captured_local)


@unittest.skipIf(XDPCase.get_contexts().server_count() < 2,
                 "Requires somewhere to redirect to.")
class HelperFunctionsRedirectToDevice(XDPCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.target = 1
        cls.target_index = cls.get_contexts().get_local(cls.target).index

        cls.prog = cls.load_bpf(b"helper_functions.c",
                                cflags=["-DREDIRECT_TARGET=" +
                                        str(cls.target_index)])

        cls.to_send = cls.generate_default_packets()

    def test_redirect_to_device(self):
        self.attach_xdp("redirect_to_const")

        self.check_result(self.send_packets(self.to_send))

    def test_redirect_map_to_device(self):
        self.attach_xdp("redirect_to_devmap")
        self.prog[b"device_map"][0] = ctypes.c_int(self.target_index)

        self.check_result(self.send_packets(self.to_send))

    def check_result(self, result):
        self.assertPacketsIn(
            self.to_send,
            result.captured_remote[self.target]
        )
        self.assertPacketContainerEmpty(result.captured_local)
        for i in result.captured_remote[:self.target] \
                + result.captured_remote[self.target + 1:]:
            self.assertPacketContainerEmpty(i)


class HelperFunctionsRedirectToCPU(XDPCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.target_cpu = 3

        cls.xdp_prog = cls.load_bpf(b"helper_functions.c",
                                    cflags=["-DREDIRECT_TARGET=" +
                                            str(cls.target_cpu)])

        cls.to_send = cls.generate_default_packets()

        cls.tp_prog = bcc.BPF(text=b"""
        struct format {
            char padding1[16];
            int cpu;
            char padding2[8];
            int to_cpu;
        };
        BPF_ARRAY(counter);
        int prog(struct format *format) {
            int zero = 0;
            u64 *val;

            val = counter.lookup(&zero);
            if (val) {
                *val += 1;
                u64 one = format->cpu;
                counter.update((int *)val, &one);

                *val += 1;
                u64 two = format->to_cpu;
                counter.update((int *)val, &two);
            }

            return 0;
        }
        """)

    @unittest.skipIf(os.cpu_count() < 2, "Requires another CPU.")
    def test_redirect_map_to_cpu(self):
        self.tp_prog.attach_tracepoint(
            b"xdp:xdp_cpumap_enqueue", fn_name=b"prog")
        counter = self.tp_prog[b"counter"]
        counter[0].value = 0

        self.attach_xdp("redirect_to_cpumap")
        self.xdp_prog[b"cpu_map"][self.target_cpu] = ctypes.c_int(16)

        result = self.send_packets(self.to_send)

        for i in range(2, counter[0].value + 1, 2):
            self.assertEqual(counter[i].value, self.target_cpu)

        self.assertPacketsIn(self.to_send, result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)


class ChangeData(XDPCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.xdp_prog = cls.load_bpf(b"change_data.c")

        cls.to_send = cls.generate_default_packets()
        cls.to_receive = [b"x" * len(i) for i in cls.to_send]

    def test_change_data_and_pass(self):
        self.attach_xdp("change_data_and_pass")

        result = self.send_packets(self.to_send)

        self.assertPacketsIn(self.to_receive, result.captured_local)
        self.assertPacketsNotIn(self.to_send, result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)
