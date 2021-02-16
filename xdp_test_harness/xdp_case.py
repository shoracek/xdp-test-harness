import time
import ctypes
import multiprocessing.connection
import errno
from typing import List, Iterable, Optional
import unittest
import os

from scapy.all import Ether, Packet, IP, IPv6, Ether, Raw, UDP, TCP
from bcc import BPF

from . import utils, context


def usingCustomLoader(test):
    """
    Skips test if not using a network.
    """
    if XDPCase.get_contexts().get_local_main().xdp_mode is None:
        return unittest.skip("Custom loader skipped when not using network.")
    return test


class SendResult:
    def __init__(self, captured_local: List[Packet],
                 captured_remote: List[List[Packet]]):
        self.captured_local = captured_local
        self.captured_remote = captured_remote


def _prog_test_run(fd, pkt):
    lib = ctypes.CDLL("libbcc.so.0", use_errno=True)
    lib.bpf_prog_test_run.argtype = [
        ctypes.c_int, ctypes.c_int,
        ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_uint32,
    ]
    lib.bpf_prog_test_run.restype = ctypes.c_int

    """
    LIBBPF_API int bpf_prog_test_run(
        int prog_fd, int repeat,
        void *data, __u32 size,
        void *data_out, __u32 *size_out,
        __u32 *retval, __u32 *duration
    );
    """

    # Maximum size of ether frame size is 1522B.
    out_size = ctypes.c_int(2048)
    out = ctypes.create_string_buffer(out_size.value)
    ret = ctypes.c_int()
    dur = ctypes.c_int()
    pkt = bytes(pkt)

    res = lib.bpf_prog_test_run(
        fd, 1,
        pkt, len(pkt),
        ctypes.byref(out), ctypes.byref(out_size),
        ctypes.byref(ret), ctypes.byref(dur)
    )

    if res != 0:
        raise RuntimeError("bpf_prog_test_run failed, returned", res,
                           "because", errno.errorcode[ctypes.get_errno()])

    out = bytes(out[:out_size.value])
    pkt_out = Ether(out)

    return (ret.value, pkt_out)


def _describe_packet(packet):
    if hasattr(packet, "summary"):
        return f"{packet.summary()} ({bytes(packet)})"

    return f"{bytes(packet)}"


def _describe_packet_container(container):
    if len(container) == 0:
        return "[]"

    if len(container) <= 5:
        descriptions = []
        for i in container:
            descriptions.append(_describe_packet(i))
        return "[\n\t" + ",\n\t".join(descriptions) + "\n]"

    return str(container)


class XDPCase(unittest.TestCase):
    @classmethod
    def set_context(cls, ctxs: context.ContextClientList):
        """Set ContextClientList to be used for testing."""
        cls.contexts = ctxs

    @classmethod
    def get_contexts(cls) -> context.ContextClientList:
        """
        Return ContextClientList,
        containing contexts of testing interfaces.
        """
        return cls.contexts

    @classmethod
    def load_bpf(cls, *args, **kwargs):
        """Set a BPF program to be used for testing."""
        pass

    def attach_xdp(self, section: bytes):
        """
        Set a function to be used for testing.
        Requires load_bpf to be called first.
        """
        raise NotImplementedError

    def send_packets(self, packets: Iterable[Packet]) -> SendResult:
        """Process packets by selected XDP function."""
        raise NotImplementedError

    @classmethod
    def prepare_class(cls):
        """Initialize the static members of XDPCase."""
        pass

    def assertPacketIn(self,
                       packet: Packet,
                       container: Iterable[Packet]):
        """Check that packet is in container."""
        for i in container:
            if bytes(packet) == bytes(i):
                return

        self.fail(f"Packet {_describe_packet(packet)} "
                  f"unexpectedly not found in "
                  f"{_describe_packet_container(container)}.")

    def assertPacketsIn(self,
                        packets: Iterable[Packet],
                        container: Iterable[Packet]):
        """Check that every packet from packets is in container."""
        container = list(map(bytes, container))
        for i in packets:
            self.assertPacketIn(i, container)
            container.remove(bytes(i))

    def assertPacketNotIn(self,
                          packet: Packet,
                          container: Iterable[Packet]):
        """Check that packet is not in container."""
        for i in container:
            if bytes(packet) == bytes(i):
                self.fail(f"Packet {_describe_packet(packet)} "
                          f"unexpectedly found in "
                          f"{_describe_packet_container(container)}.")

    def assertPacketsNotIn(self,
                           packets: Iterable[Packet],
                           container: Iterable[Packet]):
        """Check that no packet from packets is in container."""
        for i in packets:
            self.assertPacketNotIn(i, container)

    def assertPacketContainerEmpty(self, container: Iterable[Packet]):
        """Check that the container is empty."""
        if len(container) == 0:
            return

        self.fail(f"Packet {_describe_packet(container[0])} "
                  f"found in list expected to be empty.")

    @classmethod
    def generate_default_packets(
            cls,
            src_port: int = 50000, dst_port: int = 50000,
            src_inet: Optional[str] = None, dst_inet: Optional[str] = None,
            src_ether: Optional[str] = None, dst_ether: Optional[str] = None,
            layer_4: str = "udp",
            amount: int = 5,
            use_inet6: bool = False,
    ) -> List[Packet]:
        """Generate a list of predefined UDP packets using context."""
        dst_ctx = cls.get_contexts().get_local_main()
        src_ctx = cls.get_contexts().get_remote_main()

        if use_inet6:
            assert(src_inet or src_ctx.inet6 is not None)
            assert(dst_inet or dst_ctx.inet6 is not None)
            ip_layer = IPv6(src=src_inet if src_inet else src_ctx.inet6,
                            dst=dst_inet if dst_inet else dst_ctx.inet6)
        else:
            ip_layer = IP(src=src_inet if src_inet else src_ctx.inet,
                          dst=dst_inet if dst_inet else dst_ctx.inet)

        if layer_4 == "udp":
            transport_layer = UDP(sport=src_port, dport=dst_port)
        elif layer_4 == "tcp":
            transport_layer = TCP(sport=src_port, dport=dst_port)
        else:
            assert(False)

        to_send = [
            Ether(src=src_ether if src_ether else src_ctx.ether,
                  dst=dst_ether if dst_ether else dst_ctx.ether) /
            ip_layer /
            transport_layer /
            Raw(f"This is message number {i}.") for i in range(amount)
        ]
        return [Ether(p.build()) for p in to_send]


class XDPCaseBPTR(XDPCase):
    @classmethod
    def setUpClass(cls):
        cls.__fd = None
        cls.__prog = None

    @classmethod
    def prepare_class(cls):
        cls.probe_counter = BPF(
            src_file=os.path.dirname(__file__) + "/bptr_probe_counter.c"
        )

        # Using kprobes since tracepoints do not get activated with bptr.
        cls.probe_counter.attach_kprobe(event=b"bpf_xdp_redirect_map",
                                        fn_name=b"bpf_xdp_redirect_map")
        cls.probe_counter.attach_kprobe(event=b"bpf_xdp_redirect",
                                        fn_name=b"bpf_xdp_redirect")

    @classmethod
    def load_bpf(cls, *args, **kwargs):
        cls.__prog = BPF(*args, **kwargs)
        return cls.__prog

    def attach_xdp(self, section):
        if self.__prog is None:
            self.fail(
                "A BPF program needs to be loaded before attaching function."
            )

        self.__fd = self.__prog.load_func(section.encode(), BPF.XDP).fd

    def send_packets(self, packets):
        passed = []
        redirected = [[] for i in range(self.get_contexts().server_count())]

        if self.__fd is None:
            self.fail(
                "Sending packets without attaching an XDP program."
            )

        for i in packets:
            (ret_val, pkt) = _prog_test_run(self.__fd, i)

            if ret_val == BPF.XDP_PASS:
                passed.append(pkt)
            elif ret_val == BPF.XDP_TX:
                redirected[0].append(pkt)
            elif ret_val == BPF.XDP_REDIRECT:
                self.__handle_redirect(pkt, passed, redirected)
            elif ret_val == BPF.XDP_ABORTED:
                pass
            elif ret_val == BPF.XDP_DROP:
                pass

        return SendResult(passed, redirected)

    def __handle_redirect(self, pkt, passed, redirected):
        redirect_activated = self.probe_counter[b"redirect_activated"][0]
        redirect_map_activated = self.probe_counter[b"redirect_map_activated"][0]
        if redirect_activated == redirect_map_activated:
            self.fail("Unexpectedly, both or neither map "
                      "or regular redirect got activated.")

        if redirect_activated:
            redirect_info = self.probe_counter[b"redirect_info"][0]

            ifindex = redirect_info.ifindex
            ifindex = self.get_contexts().iface_index_to_id(ifindex)

            redirected[ifindex].append(pkt)
        elif redirect_map_activated:
            redirect_map_info = self.probe_counter[b"redirect_map_info"][0]

            map_type = utils.BPFMapType(redirect_map_info.map_type)
            if map_type == utils.BPFMapType.BPF_MAP_TYPE_DEVMAP:
                ifindex = redirect_map_info.ifindex
                map_name = redirect_map_info.map_name
                ifindex = self.__prog[map_name][ifindex].value
                ifindex = self.get_contexts().iface_index_to_id(ifindex)

                redirected[ifindex].append(pkt)
            elif map_type == utils.BPFMapType.BPF_MAP_TYPE_CPUMAP:
                passed.append(pkt)
            elif map_type == utils.BPFMapType.BPF_MAP_TYPE_SOCKMAP:
                pass
            elif map_type == utils.BPFMapType.BPF_MAP_TYPE_XSKMAP:
                pass
            else:
                self.fail("used something else than devmap/cpumap redirect")


class XDPCaseNetwork(XDPCase):
    @classmethod
    def setUpClass(cls):
        cls.__prog = None

        cls.__pass_prog = BPF(text=b"""
        int pass_all(struct xdp_md *ctx) { return XDP_PASS; }
        """)
        cls.__pass_fn = cls.__pass_prog.load_func(b"pass_all", BPF.XDP)

        main_ctx = cls.get_contexts().get_local_main()
        for i in range(cls.get_contexts().server_count()):
            ctx = cls.get_contexts().get_local(i)
            if ctx == main_ctx or ctx.xdp_mode is None:
                continue

            cls.__pass_prog.attach_xdp(ctx.iface.encode(),
                                       cls.__pass_fn,
                                       ctx.xdp_mode)

        return super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        if cls.__prog is None:
            return

        for i in range(cls.get_contexts().server_count()):
            ctx = cls.get_contexts().get_local(i)
            cls.__prog.remove_xdp(ctx.iface.encode())

    @classmethod
    def prepare_class(cls):
        ctx = cls.get_contexts()
        for i in range(ctx.server_count()):
            try:
                conn = cls.__connect(ctx.comms[i], 100)
                conn.send((utils.ServerCommand.INTRODUCE, ))
                remote = conn.recv()
                # Custom context is prefered.
                # if ctx.remotes[i] is None:
                ctx.remotes[i] = remote
                conn.close()
            except Exception as exception:
                raise RuntimeError("Could not contact server.",
                                   ctx.comms[i]) from exception

            ctx.get_local(i).fill_missing()

    @classmethod
    def load_bpf(cls, *args, **kwargs):
        cls.__prog = BPF(*args, **kwargs)
        return cls.__prog

    def attach_xdp(self, section):
        if self.__prog is None:
            self.fail(
                "A BPF program needs to be loaded before attaching function."
            )

        self.__prog.attach_xdp(
            self.get_contexts().get_local_main().iface.encode(),
            self.__prog.load_func(section.encode(), BPF.XDP),
            self.get_contexts().get_local_main().xdp_mode
        )

    def send_packets(self, packets):
        sniffer = utils.wait_for_async_sniffing(
            iface=self.get_contexts().get_local_main().iface
        )

        conn_list = []
        for comm in self.get_contexts().comms:
            conn_list.append(self.__connect(comm))
        main_conn = conn_list[0]

        for conn in conn_list[1:]:
            conn.send((utils.ServerCommand.WATCH, ))
        main_conn.send((utils.ServerCommand.SEND, packets))

        # Packets are being send here.

        response = main_conn.recv()
        if response != utils.ServerResponse.FINISHED:
            self.fail(
                "Unexpected situation while sending packets: " + str(response))

        server_results = []
        for conn in conn_list:
            conn.send(utils.ServerCommand.STOP)
            server_results.append(conn.recv())
            conn.close()

        if sniffer.running:
            sniffer.stop()

        return SendResult(sniffer.results, server_results)

    @classmethod
    def __connect(cls, comm, retry=10):
        for i in range(retry):
            try:
                return multiprocessing.connection.Client(
                    (comm.inet, comm.port), "AF_INET"
                )
            except ConnectionRefusedError as exception:
                if i == retry - 1:
                    raise exception
                time.sleep(0.2)
