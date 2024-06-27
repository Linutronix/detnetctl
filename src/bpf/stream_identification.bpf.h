// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define MAX_STREAMS 100

struct null_stream_identification {
	u8 destination_address[6];
	u16 vlan_identifier;
} __attribute__((__packed__));

struct stream;

const volatile bool debug_output = false;

static inline int
stream_identification(struct bpf_map *streams, void *data, void *data_end,
		      u16 vlan_tci_override,
		      struct null_stream_identification *stream_id,
		      struct stream **stream)
{
	if (!stream_id) {
		if (debug_output) {
			bpf_printk("Dropping due to NULL stream ID");
		}
		return -1;
	}

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

	*stream = bpf_map_lookup_elem(streams, stream_id);
	if (!*stream) {
		if (debug_output) {
			bpf_printk(
				"No matching TSN stream found dst: %x:%x:%x:%x:%x:%x vlan %i, processing as default traffic",
				stream_id->destination_address[0],
				stream_id->destination_address[1],
				stream_id->destination_address[2],
				stream_id->destination_address[3],
				stream_id->destination_address[4],
				stream_id->destination_address[5],
				stream_id->vlan_identifier);
		}

		struct null_stream_identification default_stream_id = {};
		*stream = bpf_map_lookup_elem(streams, &default_stream_id);

		if (!*stream) {
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
