#!/bin/bash

ip netns add test_a
ip netns exec test_a bash -c "mount bpffs /sys/fs/bpf -t bpf && ./run.py $@"
res=$?
ip netns delete test_a
exit $res
