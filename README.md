# XDP test harness

A test harness that can be used to test the implementation of XDP and XDP
programs.


## Requirements

Python 3.5, bcc, Pyroute2, Scapy


## Usage


### Running

To start the test harness, run `python3 -m xdp_test_harness.runner` in a folder
containing tests as a superuser. There are three commands that can be used:

####  `client`

Start a client, running tests using network interfaces to process packets by XDP
program. One can further specify which tests to run, using `unittest`'s format.
That is modules, classes and methods separated by dots, for example `python3 -m
xdp_test_harness.runner client test_general.ReturnValuesBasic`.

####  `bptr`

Similar to the `client` command, but uses the `BPF_PROG_TEST_RUN` syscall
command instead of a server to process packets by an XDP program.

####  `server`

Starts a server, used by `client` command to send packets.


### Configuration

Configuration of interfaces to be used for testing is done in the `config.py`
file. In the configuration file there are two variables:

####  `local_server_ctx`

A variable specifying the interface of the server, used for testing, and
the interface of the server used for communication with a client.

```python
local_server_ctx = ContextServer(
    ContextLocal("enp0s31f6"),
    ContextCommunication("192.168.0.106", 6555),
)
```

####  `remote_server_ctxs`

List of contexts specifying one physical testing interface and one virtual
testing interface. Elements of the list are either `ContextClient` objects,
for physical interfaces, or objects created by `new_virtual_ctx` function,
for virtual interfaces.
    
```python
remote_server_ctxs = ContextClientList([
    ContextClient(
        ContextLocal("enp0s31f6", xdp_mode=XDPFlag.SKB_MODE),
        ContextCommunication("192.168.0.107", 6555)
    ),
    new_virtual_ctx(
        ContextLocal("a_to_b", xdp_mode=XDPFlag.DRV_MODE),
        ContextCommunication("192.168.1.1"),
        "test_b",
        ContextLocal("b_to_a", xdp_mode=XDPFlag.DRV_MODE),
        ContextCommunication("192.168.1.2", 6000),
    ),
])
```


## Creating new tests

To create a new test, create a class inheriting from `XDPCase`. This class
should be located in a file named with a `test_` prefix and placed in the
`tests` folder. Each method of this class, that should be run while testing,
has to be named with a `test_` prefix.

Each test should either call both `load_bpf` and `attach_xdp` methods in this
order, before calling `send_packets`, or be decorated with
`usingCustomLoader` and attach own XDP program to the interface. After
attaching attaching an XDP program, calling `send_packets`, returns a
`SendResult` object, containing lists of packets that arrived to each
interface engaged in testing.

