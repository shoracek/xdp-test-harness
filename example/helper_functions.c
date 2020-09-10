#ifndef BYTES_DELTA
#define BYTES_DELTA 0
#endif
int remove_bytes_from_tail(struct xdp_md *ctx) {
	int err;

	err = bpf_xdp_adjust_tail(ctx, -BYTES_DELTA);
	if (err) {
		return XDP_ABORTED;
	}

	return XDP_PASS;
}

int remove_bytes_from_head(struct xdp_md *ctx) {
	int err;

	err = bpf_xdp_adjust_head(ctx, BYTES_DELTA);
	if (err) {
		return XDP_ABORTED;
	}

	return XDP_PASS;
}

int add_bytes_to_tail(struct xdp_md *ctx) {
	int err;

	err = bpf_xdp_adjust_tail(ctx, BYTES_DELTA);
	if (err) {
		return XDP_ABORTED;
	}

	return XDP_PASS;
}

int add_bytes_to_head(struct xdp_md *ctx) {
	int err;

	err = bpf_xdp_adjust_tail(ctx, BYTES_DELTA);
	if (err) {
		return XDP_ABORTED;
	}

	return XDP_PASS;
}

#ifndef REDIRECT_TARGET
#define REDIRECT_TARGET 0
#endif
int redirect_to_const(struct xdp_md *ctx) {
	return bpf_redirect(REDIRECT_TARGET, 0);
}

BPF_DEVMAP(device_map, 1);
int redirect_to_devmap(struct xdp_md *ctx) {
	return device_map.redirect_map(0, 0);
}

BPF_CPUMAP(cpu_map, 4);
int redirect_to_cpumap(struct xdp_md *ctx) {
	return cpu_map.redirect_map(REDIRECT_TARGET, 0);
}