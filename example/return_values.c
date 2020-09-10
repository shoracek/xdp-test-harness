int pass_all(struct xdp_md *ctx) {
	return XDP_PASS;
}

int drop_all(struct xdp_md *ctx) {
	return XDP_DROP;
}

int aborted_all(struct xdp_md *ctx) {
	return XDP_ABORTED;
}

int tx_all(struct xdp_md *ctx) {
	return XDP_TX;
}