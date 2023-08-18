// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "socket_token.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define MAX_STREAMS 100

struct null_stream_identification {
	u8 destination_address[6];
	u16 vlan_identifier;
} __attribute__((__packed__));

struct stream {
	u8 restrictions;
	u64 socket_token; // only read if indicated by restrictions
	u16 shifted_pcp;
	u32 egress_priority;
} __attribute__((__packed__));

// Map of stream identification to stream handles
// stream_handle 0 is not in the map and corresponds to best effort traffic
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STREAMS);
	__type(key, struct null_stream_identification);
	__type(value, u16); // stream handle
} stream_handles SEC(".maps");

// Number of streams (including best effort)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u16);
	__uint(max_entries, 1);
} num_streams SEC(".maps");

// Array of streams
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_STREAMS);
	__type(key, u32); // stream handle
	__type(value, struct stream);
} streams SEC(".maps");

const volatile bool debug_output = false;

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
	/*************************
	 * STREAM IDENTIFICATION *
	 *************************/
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	u64 nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		if (debug_output) {
			bpf_printk("Dropping invalid Ethernet packet");
		}
		return TC_ACT_SHOT;
	}

	// Only search for stream if VLAN header is provided, otherwise fall back to 0 (best-effort)
	u32 stream_handle = 0;
	struct null_stream_identification stream_id;

	__builtin_memcpy(stream_id.destination_address, eth->h_dest,
			 sizeof(stream_id.destination_address));
	stream_id.vlan_identifier = ctx->vlan_tci & 0xFFF;

	u16 *stream_handle_ptr =
		bpf_map_lookup_elem(&stream_handles, &stream_id);
	if (stream_handle_ptr) {
		// only set if found, otherwise fall back to 0 (best-effort)
		stream_handle = *stream_handle_ptr;
	} else if (debug_output) {
		bpf_printk(
			"No matching TSN stream found, processing as best effort...");
	}

	struct stream *stream = bpf_map_lookup_elem(&streams, &stream_handle);
	if (!stream) {
		if (debug_output) {
			// should never happen, if no explicit stream is available,
			// the stream_handle should be 0
			bpf_printk(
				"Dropping packet due to internal error: Stream %i not found",
				stream_handle);
		}
		return TC_ACT_SHOT;
	}

	/*************************
	 *   ADMISSION CONTROL   *
	 *************************/
	if (stream->restrictions) {
		// this is a restricted stream
		if (ctx->sk == NULL) {
			// If there is no socket attached to the skb,
			// this packet is generated by the kernel
			// (e.g. ARP packets), so we just let it pass.
			// TODO we might want to make this configurable
			//      per TSN stream in the future
			if (debug_output) {
				bpf_printk(
					"Admitting packet to stream %i since no socket is attached",
					stream_handle);
			}
		} else {
			u64 token = bpf_get_socket_token(ctx);
			if (stream->socket_token != token) {
				if (debug_output) {
					bpf_printk(
						"Dropping packet to restricted stream (required token %lu, provided token %lu)",
						stream->socket_token, token);
				}
				return TC_ACT_SHOT;
			}
		}
	}

	/*************************
	 *   PRIORITY MAPPING    *
	 *************************/
	if (debug_output) {
		bpf_printk("TX packet with priority %i",
			   stream->egress_priority);
	}

	ctx->priority = stream->egress_priority;

	// egress-qos-map was already applied for the initial
	// priority, so set the PCP here according to the
	// TSN configuration and ignore the egress-qos-map
	// for the interface itself, but only if the packet
	// is targeted to a VLAN (i.e. bpf_skb_vlan_pop is successful)
	u16 vlan_proto = ctx->vlan_proto;
	if (bpf_skb_vlan_pop(ctx) == 0) {
		bpf_skb_vlan_push(ctx, vlan_proto,
				  stream_id.vlan_identifier |
					  stream->shifted_pcp);
	}

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
