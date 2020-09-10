static void set_bytes_to_x(void *data, void *data_end)
{
	for (int i = 0; i < 1500; ++i)
	{
		char *p = (char *)data + i;
		if (p + sizeof(*p) > (char *)data_end)
		{
			break;
		}

		*p = 'x';
	}
}

int change_data_and_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	set_bytes_to_x(data, data_end);

	return XDP_PASS;
}