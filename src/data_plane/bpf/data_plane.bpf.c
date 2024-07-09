// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Identifies incoming stream and replicates it by broadcast redirection.

#include "../../bpf/vmlinux.h"
#include "../../bpf/stream_identification.bpf.h"

#define MAX_REPLICATIONS 6

struct stream {
	u16 handle;
} __attribute__((__packed__));

// Map of stream identification to stream handles
// default stream handle 0 is also in the map for all zeros in the key
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STREAMS);
	__type(key, struct null_stream_identification);
	__type(value, struct stream);
} streams SEC(".maps");

// Number of streams (including default stream handle 0)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u16);
	__uint(max_entries, 1);
} num_streams SEC(".maps");

struct redirect_interfaces {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, MAX_REPLICATIONS);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_devmap_val));
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_STREAMS);
	__uint(key_size, sizeof(u16));
	__array(values, struct redirect_interfaces);
} redirect_map SEC(".maps");

SEC("xdp")
int xdp_bridge(struct xdp_md *ctx)
{
	/*************************
	 * STREAM IDENTIFICATION *
	 *************************/
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct null_stream_identification stream_id = {};
	struct stream *stream = 0;
	if (stream_identification((struct bpf_map *)&streams, data, data_end, 0,
				  &stream_id, &stream) < 0) {
		return XDP_DROP;
	}

	if (stream->handle == 0) {
		// no matching stream was found, this is the fallback stream
		// so process as local traffic and pass on into the stack
		if (debug_output) {
			bpf_printk("Pass into stack");
		}
		return XDP_PASS;
	}

	/********************************
	 * REDIRECTION WITH REPLICATION *
	 ********************************/
	struct redirect_interfaces *interfaces =
		bpf_map_lookup_elem(&redirect_map, &stream->handle);
	if (!interfaces) {
		if (debug_output) {
			bpf_printk(
				"Dropping packet due to internal error. Entry not found in redirect map.");
		}
		return XDP_DROP;
	}

	return bpf_redirect_map(interfaces, 0, BPF_F_BROADCAST);
}

SEC("xdp")
int pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
