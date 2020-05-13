#include <linux/bpf.h>


struct redirect_map_info {
	u64 ifindex;
	u64 map_type;
	char map_name[BPF_OBJ_NAME_LEN];
};
BPF_ARRAY(redirect_map_info, struct redirect_map_info, 1);
BPF_ARRAY(redirect_map_activated, bool, 1);

int bpf_xdp_redirect_map(struct pt_regs *ctx,
			 struct bpf_map *map,
			 u32 ifindex, u64 flags)
{
	int zero_value = 0;
	bool true_value = 1;

	redirect_map_activated.update(&zero_value, &true_value);

	struct redirect_map_info info;
	info.ifindex = ifindex;
	info.map_type = map->map_type;
	bpf_probe_read_str(info.map_name, BPF_OBJ_NAME_LEN, map->name);

	redirect_map_info.update(&zero_value, &info);

	return 0;
}

struct redirect_info {
	u64 ifindex;
};
BPF_ARRAY(redirect_info, struct redirect_info, 1);
BPF_ARRAY(redirect_activated, bool, 1);

int bpf_xdp_redirect(struct pt_regs *ctx,
		     u32 ifindex, u64 flags)
{
	int zero_value = 0;
	bool true_value = 1;

	redirect_activated.update(&zero_value, &true_value);

	struct redirect_info info;
	info.ifindex = ifindex;

	redirect_info.update(&zero_value, &info);

	return 0;
}
