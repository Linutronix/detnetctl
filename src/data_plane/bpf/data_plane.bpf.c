// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Identifies incoming stream and replicates it by broadcast redirection.
// Decapsulates incoming flows and performs sequence recovery.
// Further frame modifications will be performed by the postprocessing.bpf.c

#include "../../bpf/vmlinux.h"
#include "../../bpf/stream_identification.bpf.h"
#include "frer.bpf.h"

#define MAX_REPLICATIONS 6

#define L2_SEQUENCE_GENERATION_MASK 0x01
#define L3_SEQUENCE_GENERATION_MASK 0x02

struct stream_or_flow {
	u16 handle;
	u8 flags;
} __attribute__((__packed__));

// Map of stream identification to stream handles
// default stream handle 0 is also in the map for all zeros in the key
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STREAMS_OR_FLOWS);
	__type(key, struct null_stream_identification);
	__type(value, struct stream_or_flow);
} streams SEC(".maps");

// Map of flow identification to stream handles
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STREAMS_OR_FLOWS);
	__type(key, struct detnet_flow_identification);
	__type(value, struct stream_or_flow);
} flows SEC(".maps");

// Number of streams or flows (including default stream handle 0)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u16);
	__uint(max_entries, 1);
} num_streams_or_flows SEC(".maps");

struct redirect_interfaces {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, MAX_REPLICATIONS);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_devmap_val));
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_STREAMS_OR_FLOWS);
	__uint(key_size, sizeof(u16));
	__array(values, struct redirect_interfaces);
} redirect_map SEC(".maps");

SEC("xdp")
int xdp_bridge(struct xdp_md *ctx)
{
	/*********************************
	 * STREAM OR FLOW IDENTIFICATION *
	 *********************************/
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct null_stream_identification stream_id = {};
	struct stream_or_flow *stream_or_flow = 0;
	if (stream_identification((struct bpf_map *)&streams, data, data_end, 0,
				  &stream_id, &stream_or_flow) < 0) {
		return XDP_DROP;
	}

	bool detnet_decapsulation = false;
	if (stream_or_flow->handle == 0) {
		// if flow is found, overwrite stream, otherwise it will be kept intact
		detnet_stream_identification((struct bpf_map *)&flows, data,
					     data_end, &stream_or_flow);

		if (stream_or_flow->handle != 0) {
			detnet_decapsulation = true;
		}
	}

	if (stream_or_flow->handle == 0) {
		// no matching stream was found, this is the fallback stream
		// so process as local traffic and pass on into the stack
		if (debug_output) {
			bpf_printk("Pass into stack");
		}
		return XDP_PASS;
	}

	/******************************************
	 *   SEQUENCE RECOVERY AND DECAPSULATION  *
	 ******************************************/
	// reset history window if needed
	u64 now = bpf_ktime_get_coarse_ns();
	sequence_recovery_timer_cb(&now);

	struct vlan_ethhdr *eth = data;
	u16 vlan_proto = bpf_ntohs(eth->h_vlan_proto);
	u16 vlan_encaps_proto = bpf_ntohs(eth->h_vlan_encapsulated_proto);
	if (detnet_decapsulation ||
	    ((vlan_proto == ETH_P_8021Q || vlan_proto == ETH_P_8021AD) &&
	     vlan_encaps_proto == ETH_P_RTAG)) {
		struct seq_rcvy_and_hist *rec = bpf_map_lookup_elem(
			&seqrcvy_map, &stream_or_flow->handle);
		if (!rec) {
			if (debug_output) {
				bpf_printk("Sequence recovery map not found");
			}
			return XDP_DROP;
		}

		ushort seq;
		if (!detnet_decapsulation) {
			int ret = rm_rtag(ctx, &seq);
			if (ret < 0) {
				if (debug_output) {
					bpf_printk("Failed to remove R-TAG");
				}
				return XDP_DROP;
			}
		} else {
			// The check for a packet with full IP/UDP/MPLS was
			// already made in detnet_stream_identification.
			// Just grab CW then move the head accordingly.
			u8 total_encapsulation_size =
				sizeof(struct vlan_ethhdr) +
				sizeof(struct ipv6hdr) + sizeof(struct udphdr) +
				8;

			if (data + sizeof(struct vlan_ethhdr) +
				    sizeof(struct ipv6hdr) +
				    sizeof(struct udphdr) + 8 >
			    data_end) {
				if (debug_output) {
					bpf_printk(
						"Cannot decapsulate DetNet packet, too small");
				}
				return XDP_DROP;
			}

			seq = bpf_ntohl(*(u32 *)(data +
						 total_encapsulation_size -
						 4)) &
			      0xFFFF;

			if (bpf_xdp_adjust_head(ctx,
						total_encapsulation_size)) {
				if (debug_output) {
					bpf_printk(
						"Changing packet size for decapsulation failed");
				}
				return XDP_DROP;
			}
		}

		bpf_spin_lock(&(rec->lock));
		bool pass = recover(rec, seq);
		bpf_spin_unlock(&(rec->lock));
		if (!pass) {
			if (debug_output) {
				bpf_printk("Dropped as intended due to FRER");
			}
			return XDP_DROP;
		}

		rec->last_packet_ns = now;
	}

	/*************************
	 *  SEQUENCE GENERATION  *
	 *************************/
	if (stream_or_flow->flags &
	    (L2_SEQUENCE_GENERATION_MASK | L3_SEQUENCE_GENERATION_MASK)) {
		struct seq_gen *gen = bpf_map_lookup_elem(
			&seqgen_map, &stream_or_flow->handle);
		if (!gen) {
			if (debug_output) {
				bpf_printk("Sequence generator not found");
			}
			return XDP_DROP;
		}

		uint16_t seq = genseq(gen);

		if (stream_or_flow->flags & L2_SEQUENCE_GENERATION_MASK) {
			int ret = add_rtag(ctx, &seq);
			if (ret < 0) {
				if (debug_output) {
					bpf_printk("Adding RTAG failed");
				}
				return XDP_DROP;
			}
		} else {
			int ret = add_detnet_cw(ctx, &seq);
			if (ret < 0) {
				if (debug_output) {
					bpf_printk("Adding DetNet CW failed");
				}
				return XDP_DROP;
			}
		}
	}

	/********************************
	 * REDIRECTION WITH REPLICATION *
	 ********************************/
	struct redirect_interfaces *interfaces =
		bpf_map_lookup_elem(&redirect_map, &stream_or_flow->handle);
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
