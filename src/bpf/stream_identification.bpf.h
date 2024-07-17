// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IPV6 0x86DD
#define UDP_PROTOCOL_NUMBER 17
#define MPLS_OVER_UDP_PORT_NUMBER 6635
#define MPLS_LABEL_SHIFT 12
#define MPLS_LABEL_MASK 0xFFFFF

#define MAX_STREAMS_OR_FLOWS 100

struct null_stream_identification {
	u8 destination_address[6];
	u16 vlan_identifier;
} __attribute__((__packed__));

struct detnet_flow_identification {
	u32 mpls_label;
	u16 udp_source_port;
} __attribute__((__packed__));

struct stream_or_flow;

const volatile bool debug_output = false;

static inline int
stream_identification(struct bpf_map *streams, void *data, void *data_end,
		      u16 vlan_tci_override,
		      struct null_stream_identification *stream_id,
		      struct stream_or_flow **stream)
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

static inline void detnet_stream_identification(struct bpf_map *flows,
						void *data, void *data_end,
						struct stream_or_flow **flow)
{
	if (data + sizeof(struct vlan_ethhdr) + sizeof(struct ipv6hdr) +
		    sizeof(struct udphdr) + 8 >
	    data_end) {
		if (debug_output) {
			bpf_printk("Cannot identify DetNet packet, too small");
		}
		return;
	}

	struct vlan_ethhdr *eth = data;

	u16 vlan_proto = bpf_ntohs(eth->h_vlan_proto);
	if (vlan_proto != ETH_P_8021Q && vlan_proto != ETH_P_8021AD) {
		if (debug_output) {
			bpf_printk(
				"Cannot identify DetNet packet, no VLAN tag");
		}
		return;
	}

	if (bpf_ntohs(eth->h_vlan_encapsulated_proto) != ETH_P_IPV6) {
		if (debug_output) {
			bpf_printk("Cannot identify DetNet packet, not IPv6");
		}
		return;
	}

	struct ipv6hdr *ip6h = data + sizeof(struct vlan_ethhdr);
	if (ip6h->nexthdr != UDP_PROTOCOL_NUMBER) {
		if (debug_output) {
			bpf_printk("Cannot identify DetNet packet, not UDP");
		}
		return;
	}

	struct udphdr *udph =
		data + sizeof(struct vlan_ethhdr) + sizeof(struct ipv6hdr);
	if (bpf_ntohs(udph->dest) != MPLS_OVER_UDP_PORT_NUMBER) {
		if (debug_output) {
			bpf_printk("Cannot identify DetNet packet, not MPLS");
		}
		return;
	}

	struct mplshdr *mplsh = data + sizeof(struct vlan_ethhdr) +
				sizeof(struct ipv6hdr) + sizeof(struct udphdr);

	struct detnet_flow_identification flow_id;
	flow_id.mpls_label = (bpf_ntohl(*(u32 *)mplsh) >> MPLS_LABEL_SHIFT) &
			     MPLS_LABEL_MASK;
	flow_id.udp_source_port = bpf_ntohs(udph->source);

	struct stream_or_flow *new_flow = bpf_map_lookup_elem(flows, &flow_id);
	if (new_flow) {
		*flow = new_flow;
	}
}
