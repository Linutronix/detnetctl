// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../bpf/vmlinux.h"
#include "../../bpf/helpers.bpf.h"

struct stream {
	u16 handle;
	u32 outgoing_interface;
} __attribute__((__packed__));

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
	if (stream_identification(data, data_end, 0, &stream_id, &stream) < 0) {
		return XDP_DROP;
	}

	if (stream->handle == 0) {
		// no matching stream was found, this is the fallback stream
		// so process as local traffic and pass on into the stack
		return XDP_PASS;
	}


	/*********************
	 *    REDIRECTION    *
	 *********************/

	return bpf_redirect(stream->outgoing_interface, 0);
}

char __license[] SEC("license") = "GPL";
