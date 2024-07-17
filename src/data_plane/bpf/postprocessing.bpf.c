// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Postprocesses the frame after replication by broadcast redirection.

#include "../../bpf/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

volatile const bool debug_output = false;
volatile const struct vlan_ethhdr target_outer_hdr;
volatile const bool overwrite_dest_addr = false;
volatile const bool overwrite_source_addr = false;
volatile const bool overwrite_vlan_proto_and_tci = false;
volatile const bool overwrite_ether_type = false;
volatile const bool fixed_egress_cpu = false;
volatile const u32 outgoing_cpu = 0;
volatile const bool mpls_encapsulation = false;
volatile const u32 mpls_stack_entry;
volatile const bool udp_ip_encapsulation = false;
volatile const u8 udp_header[sizeof(struct udphdr)];
volatile const u8 ip_header[sizeof(struct ipv6hdr)];

#define TSN_MAX_FRAME_SIZE 1400 // TODO investigate, should be 1518 but does not work with survilliance camera...

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
	__uint(max_entries, 12);
} cpu_map SEC(".maps");

SEC("xdp/devmap")
int xdp_bridge_postprocessing(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/*************************
	 *     ENCAPSULATION     *
	 *************************/
	if (mpls_encapsulation || udp_ip_encapsulation) {
		u8 total_encapsulation_size = sizeof(struct vlan_ethhdr);
		if (udp_ip_encapsulation) {
			total_encapsulation_size += sizeof(struct ipv6hdr) + sizeof(struct udphdr);
		}
		if (mpls_encapsulation) { // without control word that was added before redirect
			total_encapsulation_size += sizeof(mpls_stack_entry);
		}

		u16 payload_len = data_end - data;

		if (payload_len + total_encapsulation_size > TSN_MAX_FRAME_SIZE) {
			if (debug_output) {
				bpf_printk("Packet with encapsulation header does not fit into MTU");
			}
			return XDP_DROP;
		}

		if (bpf_xdp_adjust_head(ctx, -total_encapsulation_size)) {
			if (debug_output) {
				bpf_printk("Changing packet size for encapsulation failed");
			}
			return XDP_DROP;
		}

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		// make space for outer Ethernet header but write to it
		// under "SET L2 HEADER" that is also used to overwrite
		// the existing Ethernet header if no encapsulation takes place

		struct mplshdr* mplsh = data + sizeof(struct vlan_ethhdr);

		if (udp_ip_encapsulation) {
			struct ipv6hdr *ip6h = data + sizeof(struct vlan_ethhdr);
			struct udphdr* udph = (void*)ip6h + sizeof(struct ipv6hdr);
			mplsh = ((void*)mplsh) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);

			if ((void*)udph + sizeof(struct udphdr) > data_end ||
			    (void*)ip6h + sizeof(struct ipv6hdr) > data_end) {
				if (debug_output) {
					bpf_printk("UDP IP encapsulation failed");
				}

				return XDP_DROP;
			}

			__builtin_memcpy(udph, (const void*)&udp_header, sizeof(struct udphdr));
			__builtin_memcpy(ip6h, (const void*)&ip_header, sizeof(struct ipv6hdr));

			// Keep at 0 for the moment
			// Also aligns with RFC 6935 (IPv6 and UDP Checksums for Tunneled Packets)
			// to allow 0 for tunneling purposes.
			udph->check = 0;

			if (mpls_encapsulation) {
				payload_len += sizeof(mpls_stack_entry);
			}
			udph->len = bpf_htons(payload_len);
			payload_len += sizeof(struct udphdr);
			ip6h->payload_len = bpf_htons(payload_len);
		}

		if (mpls_encapsulation) {
			if ((void*)mplsh + mpls_stack_entry > data_end) {
				if (debug_output) {
					bpf_printk("MPLS encapsulation failed");
				}

				return XDP_DROP;
			}

			__builtin_memcpy(mplsh, (const void*)&mpls_stack_entry, sizeof(mpls_stack_entry));
		}
	}

	/*********************
	 *   SET L2 HEADER   *
	 *********************/
	struct vlan_ethhdr *outer_vlan_eth = data;
	u16 *ether_type = &outer_vlan_eth->h_vlan_encapsulated_proto;

	u16 vlan_proto = bpf_ntohs(outer_vlan_eth->h_vlan_proto);
	if (vlan_proto != ETH_P_8021Q && vlan_proto != ETH_P_8021AD) {
		// There is no VLAN tag yet
		if (overwrite_vlan_proto_and_tci) {
			// The VLAN tag needs to be pushed and not just changed
			int offset = sizeof(struct vlan_ethhdr) -
				     sizeof(struct ethhdr);
			if (bpf_xdp_adjust_head(ctx, -offset)) {
				if (debug_output) {
					bpf_printk(
						"Changing packet size for encapsulation failed");
				}
				return XDP_DROP;
			}

			// Move addresses to front
			__builtin_memmove(data, data + offset,
					  2 * sizeof(outer_vlan_eth->h_dest));

			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			outer_vlan_eth = data;
		} else if (overwrite_ether_type) {
			// This shall be a Ethernet header without VLAN tag,
			// so find the correct position for the type
			struct ethhdr *outer_eth = data;
			ether_type = &outer_eth->h_proto;
		}
	}

	if (overwrite_ether_type) {
		__builtin_memcpy(&ether_type,
				 (const void *)&target_outer_hdr
					 .h_vlan_encapsulated_proto,
				 sizeof(ether_type));
	}

	if (overwrite_vlan_proto_and_tci) {
		__builtin_memcpy(&outer_vlan_eth->h_vlan_proto,
				 (const void *)&target_outer_hdr.h_vlan_proto,
				 sizeof(outer_vlan_eth->h_vlan_proto) +
					 sizeof(outer_vlan_eth->h_vlan_TCI));
	}

	if (overwrite_dest_addr) {
		// position is the same, regardless of existence of VLAN tag
		__builtin_memcpy(outer_vlan_eth->h_dest,
				 (const void *)target_outer_hdr.h_dest,
				 sizeof(outer_vlan_eth->h_dest));
	}

	if (overwrite_source_addr) {
		// position is the same, regardless of existence of VLAN tag
		__builtin_memcpy(outer_vlan_eth->h_source,
				 (const void *)target_outer_hdr.h_source,
				 sizeof(outer_vlan_eth->h_source));
	}

	/*********************
	 *   QUEUE MAPPING   *
	 *********************/
	/* There is currently no way to specify the egress queue for packets
	 * processed by XDP and even if it were, that would be prone to CPUs
	 * fighting for access to queues
	 * (see https://lore.kernel.org/xdp-newbies/c8072891-6d5c-42c3-8b13-e8ca9ab6c43c@linutronix.de/T/#u )
	 * However, most network card drivers, in particular the igc driver
	 * for Intels i225/i226 use a mapping of CPU to queue
	 * (see https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/ethernet/intel/igc/igc_main.c?h=v6.8-rc4#n2453 )
	 * Therefore, for the moment, going over to the associated CPU will
	 * feed the packet into the correct queue, until there is a better
	 * way to configure this in the kernel.
	 */
	if (!fixed_egress_cpu) {
		// We don't care about the CPU, just pass
		return XDP_PASS;
	}

	u32 cpu = bpf_get_smp_processor_id();
	if (cpu == outgoing_cpu) {
		// We are already on the correct CPU, just pass
		return XDP_PASS;
	}

	// We are not on the correct CPU, go over CPUMAP.
	// Since this is a per-stream loaded XDP, the
	// first entry in the CPUMAP is always configured
	// for the correct queue.
	return bpf_redirect_map(&cpu_map, 0, 0);
}

char __license[] SEC("license") = "GPL";
