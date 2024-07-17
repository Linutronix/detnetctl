// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Identifies incoming stream and replicates it by broadcast redirection.
// Further frame modifications will be performed by the postprocessing.bpf.c

#include "../../bpf/vmlinux.h"
#include "../../bpf/stream_identification.bpf.h"
#include "frer.bpf.h"

#define MAX_REPLICATIONS 6

#define L2_SEQUENCE_GENERATION_MASK 0x01
#define L3_SEQUENCE_GENERATION_MASK 0x02

struct stream {
	u16 handle;
	u8 flags;
} __attribute__((__packed__));

// Map of stream identification to stream handles
// default stream handle 0 is also in the map for all zeros in the key
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STREAMS);
	__type(key, struct null_stream_identification);
	__type(value, struct stream);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} detnetctl_data_plane_streams SEC(".maps");

// Number of streams (including default stream handle 0)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u16);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} detnetctl_data_plane_num_streams SEC(".maps");

struct redirect_interfaces {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, MAX_REPLICATIONS);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_devmap_val));
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_STREAMS);
	__uint(key_size, sizeof(int));
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
	if (stream_identification(
		    (struct bpf_map *)&detnetctl_data_plane_streams, data,
		    data_end, 0, &stream_id, &stream) < 0) {
		return XDP_DROP;
	}

	if (stream->handle == 0) {
		// no matching stream was found, this is the fallback stream
		// so process as local traffic and pass on into the stack
		return XDP_PASS;
	}

	/*************************
	 *   SEQUENCE RECOVERY   *
	 *************************/
	sequence_recovery_timer_cb(); // reset history window if needed

	struct vlan_ethhdr *eth = data;
	u16 vlan_proto = bpf_ntohs(eth->h_vlan_proto);
	u16 vlan_encaps_proto = bpf_ntohs(eth->h_vlan_proto);
	if ((vlan_proto == ETH_P_8021Q || vlan_proto == ETH_P_8021AD) &&
	    vlan_encaps_proto == ETH_P_RTAG) {
		struct seq_rcvy_and_hist *rec = bpf_map_lookup_elem(
			&detnetctl_data_plane_seqrcvy, &stream->handle);
		if (!rec) {
			if (debug_output) {
				bpf_printk("Sequence generator not found");
			}
			return XDP_DROP;
		}

		ushort seq;
		int ret = rm_rtag(ctx, &seq);
		if (ret < 0) {
			if (debug_output) {
				bpf_printk("Failed to remove R-TAG");
			}
			return XDP_DROP;
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

		rec->last_packet_ns = bpf_ktime_get_ns();
	}

	/*************************
	 *  SEQUENCE GENERATION  *
	 *************************/
	if (stream->flags & (L2_SEQUENCE_GENERATION_MASK | L3_SEQUENCE_GENERATION_MASK)) {
		struct seq_gen *gen = bpf_map_lookup_elem(
			&detnetctl_data_plane_seqgen, &stream->handle);
		if (!gen) {
			if (debug_output) {
				bpf_printk("Sequence generator not found");
			}
			return XDP_DROP;
		}

		uint16_t seq = genseq(gen);

		if (stream->flags & L2_SEQUENCE_GENERATION_MASK) {
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

char __license[] SEC("license") = "GPL";
