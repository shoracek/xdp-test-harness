import enum
import subprocess
import atexit
import threading

from scapy.all import AsyncSniffer
from scapy.arch.linux import L2ListenSocket
import pyroute2


class XDPFlag(enum.IntFlag):
    """
    elixir.bootlin.com/linux/v5.4/source/include/uapi/linux/if_link.h#L949
    """
    UPDATE_IF_NOEXIST = (1 << 0)
    SKB_MODE = (1 << 1)
    DRV_MODE = (1 << 2)
    HW_MODE = (1 << 3)


class BPFMapType(enum.IntEnum):
    """
    elixir.bootlin.com/linux/v5.4/source/include/uapi/linux/bpf.h#L112
    """
    BPF_MAP_TYPE_DEVMAP = 14
    BPF_MAP_TYPE_SOCKMAP = 15
    BPF_MAP_TYPE_CPUMAP = 16
    BPF_MAP_TYPE_XSKMAP = 17


class ServerCommand(enum.Enum):
    INTRODUCE = enum.auto()

    SEND = enum.auto()
    WATCH = enum.auto()

    STOP = enum.auto()


class ServerResponse(enum.Enum):
    FINISHED = enum.auto()
    TIMEOUT = enum.auto()


def restore_traffic(sysctl_state):
    for i in sysctl_state:
        # NOTE: for some reason string with spaces is returned when querying
        # but string without spaces is required for writing
        i = i.replace(b" ", b"")
        subprocess.run(["sysctl", "-w", i], capture_output=True)


def clean_traffic(iface: str,
                  netns: pyroute2.NetNS = None,
                  restore_on_exit: bool = True):
    sysctl_state = []
    MILLISECONDS_IN_HOUR = 1000 * 60 * 60

    for (folder, setting, value) in [
        ("conf", "autoconf", 0),
        ("conf", "accept_ra", 0),
        ("conf", "accept_dad", 0),
        ("conf", "mldv1_unsolicited_report_interval", MILLISECONDS_IN_HOUR),
        ("conf", "mldv2_unsolicited_report_interval", MILLISECONDS_IN_HOUR),
        ("neigh", "mcast_solicit", 0),
    ]:
        if netns:
            # No need to remember previous setting of network namespace,
            # since it is going to be destroyed anyway.
            pyroute2.NSPopen(netns.netns, [
                "sysctl", "-w", "net.ipv6." + folder + "." +
                iface + "." + setting + "=" + str(value)
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()
        else:
            try:
                previous = subprocess.check_output([
                    "sysctl", "net.ipv6." + folder + "." +
                    iface + "." + setting
                ])
                sysctl_state.append(previous)
            except:
                pass

            subprocess.run([
                "sysctl", "-w", "net.ipv6." + folder + "." +
                iface + "." + setting + "=" + str(value)
            ], capture_output=True)

    atexit.register(restore_traffic, sysctl_state)


class L2ListenSocketOutgoing(L2ListenSocket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Defined in if_packet.h
        PACKET_IGNORE_OUTGOING = 23
        SOL_PACKET = 263

        self.ins.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)


def wait_for_async_sniffing(*args, **kwargs):
    """Starts AsyncSniffer and waits until it starts sniffing."""

    lock = threading.Lock()

    if "started_callback" in kwargs:
        original_started_callback = kwargs["started_callback"]

        def combined_started_callback():
            lock.release()
            original_started_callback()
    else:
        combined_started_callback = lock.release

    kwargs["started_callback"] = combined_started_callback
    kwargs["L2socket"] = L2ListenSocketOutgoing
    lock.acquire()
    asniff = AsyncSniffer(*args, **kwargs)
    asniff.start()
    lock.acquire()

    return asniff
