// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
	u16 handle;
	u8 restrictions;
	u16 shifted_pcp;
	u32 egress_priority;
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

// Array of cgroups for each stream
// Only accessed and checked if indicated
// by stream.restrictions
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, MAX_STREAMS);
	__type(key, u32); // stream handle
	__type(value, u32);
} stream_cgroups SEC(".maps");

const volatile bool debug_output = false;

static inline int
stream_identification(void *data, void *data_end, u16 vlan_tci_override,
		      struct null_stream_identification *stream_id,
		      struct stream **stream)
{
	struct vlan_ethhdr *eth = data;

	u64 nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		if (debug_output) {
			bpf_printk("Dropping invalid Ethernet packet");
		}
		return -1;
	}

	// Only search for stream if VLAN header is provided, otherwise fall back to 0 (best-effort)

	__builtin_memcpy(stream_id->destination_address, eth->h_dest,
			 sizeof(stream_id->destination_address));

	if (vlan_tci_override) {
		stream_id->vlan_identifier = vlan_tci_override & 0xFFF;
	} else {
		u16 vlan_proto = bpf_ntohs(eth->h_vlan_proto);
		if (vlan_proto != ETH_P_8021Q && vlan_proto != ETH_P_8021AD) {
			if (debug_output) {
				bpf_printk(
					"No VLAN header in packet. Consider disabling VLAN offload. Assuming VLAN ID 0");
			}

			stream_id->vlan_identifier = 0;
		} else {
			stream_id->vlan_identifier =
				bpf_ntohs(eth->h_vlan_TCI) & 0xFFF;
		}
	}

	*stream = bpf_map_lookup_elem(&streams, &stream_id);
	if (!*stream) {
		bpf_printk(
			"No matching TSN stream found dst: %x:%x:%x:%x:%x:%x vlan %i, processing as default traffic",
			stream_id->destination_address[0],
			stream_id->destination_address[1],
			stream_id->destination_address[2],
			stream_id->destination_address[3],
			stream_id->destination_address[4],
			stream_id->destination_address[5],
			stream_id->vlan_identifier);

		struct null_stream_identification default_stream_id = {};
		struct stream *stream =
			bpf_map_lookup_elem(&streams, &default_stream_id);

		if (!stream) {
			if (debug_output) {
				// should never happen, if no explicit stream is available,
				// the default stream should be available
				bpf_printk(
					"Dropping packet due to internal error when loading default stream");
			}
			return -1;
		}
	}

	return 0;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
	/**************************
	 * STREAM IDENTIFICATION *
	 *************************/
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct null_stream_identification stream_id = {};
	struct stream *stream = 0;
	if (stream_identification(data, data_end, ctx->vlan_tci, &stream_id,
				  &stream) < 0) {
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
					stream->handle);
			}
		} else {
			long cgroup_check = bpf_skb_under_cgroup(
				ctx, &stream_cgroups, stream->handle);
			if (cgroup_check != 1) {
				if (debug_output) {
					if (cgroup_check == 0) {
						bpf_printk(
							"Dropping packet to restricted stream");
					} else {
						bpf_printk(
							"Dropping packet due to internal error: Checking cgroup for stream %i failed: %i",
							stream->handle,
							cgroup_check);
					}
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
