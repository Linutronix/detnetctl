// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../bpf/vmlinux.h"
#include "../../bpf/stream_identification.bpf.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define DROP_ALL_MASK 0x01
#define DROP_WITHOUT_SK_MASK 0x02
#define DROP_WITH_WRONG_CGROUP_MASK 0x03

struct stream_or_flow {
	u16 handle;
	u8 flags;
	u16 shifted_pcp;
	u32 egress_priority;
} __attribute__((__packed__));

// Map of stream identification to stream handles
// default stream handle 0 is also in the map for all zeros in the key
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STREAMS_OR_FLOWS);
	__type(key, struct null_stream_identification);
	__type(value, struct stream_or_flow);
} streams SEC(".maps");

// Number of streams (including default stream handle 0)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u16);
	__uint(max_entries, 1);
} num_streams_or_flows SEC(".maps");

// Array of cgroups for each stream
// Only accessed and checked if indicated
// by stream.restrictions
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, MAX_STREAMS_OR_FLOWS);
	__type(key, u32); // stream handle
	__type(value, u32);
} stream_cgroups SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
	/**************************
	 * STREAM IDENTIFICATION *
	 *************************/
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct null_stream_identification stream_id = {};
	struct stream_or_flow *stream = 0;
	if (stream_identification((struct bpf_map *)&streams, data, data_end,
				  ctx->vlan_tci, &stream_id, &stream) < 0) {
		return TC_ACT_SHOT;
	}

	/*************************
	 *   ADMISSION CONTROL   *
	 *************************/
	if (stream->flags & DROP_ALL_MASK) {
		if (debug_output) {
			bpf_printk(
				"Shot packet to stream %i due to DROP_ALL flag",
				stream->handle);
		}
		return TC_ACT_SHOT;
	}

	if (ctx->sk == NULL) {
		// If there is no socket attached to the skb,
		// this packet is generated by the kernel
		// (e.g. ARP packets). Handle according to
		// DROP_WITHOUT_SK flag
		if (stream->flags & DROP_WITHOUT_SK_MASK) {
			if (debug_output) {
				bpf_printk(
					"Shot packet to stream %i since no socket is attached",
					stream->handle);
			}

			return TC_ACT_SHOT;
		} else {
			if (debug_output) {
				bpf_printk(
					"Admitting packet to stream %i since no socket is attached",
					stream->handle);
			}
		}
	} else if (stream->flags & DROP_WITH_WRONG_CGROUP_MASK) {
		long cgroup_check = bpf_skb_under_cgroup(ctx, &stream_cgroups,
							 stream->handle);
		if (cgroup_check != 1) {
			if (debug_output) {
				if (cgroup_check == 0) {
					bpf_printk(
						"Dropping packet to restricted stream");
				} else {
					bpf_printk(
						"Dropping packet due to internal error: Checking cgroup for stream %i failed: %i",
						stream->handle, cgroup_check);
				}
			}

			return TC_ACT_SHOT;
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
