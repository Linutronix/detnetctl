#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "socket_token.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u8);
	__type(value, u64);
} allowed_tokens SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
	int priority = ctx->priority;
	if (priority <= 0) {
		return TC_ACT_OK;
	}

	u64 allowed_token = 0;
	u64 *allowed_token_ptr =
		bpf_map_lookup_elem(&allowed_tokens, &priority);
	if (!allowed_token_ptr) {
		// no token stored for this priority -> priority not reserved
		return TC_ACT_OK;
	}

	allowed_token = *allowed_token_ptr;
	u64 token = bpf_get_socket_token(ctx);
	bpf_printk(
		"TX packet with priority %i and token %lu. Allowed token is %lu -> ",
		priority, token, allowed_token);

	if (allowed_token == token) {
		bpf_printk("OK\n");
		return TC_ACT_OK;
	} else {
		bpf_printk("DROP\n");
		return TC_ACT_SHOT;
	}
}

char __license[] SEC("license") = "GPL";
