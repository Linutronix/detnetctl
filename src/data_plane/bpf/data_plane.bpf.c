// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../bpf/vmlinux.h"
#include "../../bpf/stream_identification.bpf.h"

struct stream {
	u16 handle;
	u32 outgoing_interface;
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

	/*********************
	 *    REDIRECTION    *
	 *********************/
	if (debug_output) {
		bpf_printk("Redirect to %i", stream->outgoing_interface);
	}

	return bpf_redirect(stream->outgoing_interface, 0);
}

char __license[] SEC("license") = "GPL";
