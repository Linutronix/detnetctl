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

// memcpy does not work with volatile src array,
// so provide an alternative
void *memcpy_v(void *dst, const volatile void *src, size_t n)
{
	const volatile unsigned char *src_c = src;
	unsigned char *dst_c = dst;

	while (n > 0) {
		n--;
		dst_c[n] = src_c[n];
	}

	return dst;
}

SEC("xdp/devmap")
int xdp_bridge_postprocessing(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_ethhdr *outer_vlan_eth = data;
	u16 *ether_type = &outer_vlan_eth->h_vlan_encapsulated_proto;

	if (data + sizeof(struct vlan_ethhdr) > data_end) {
		if (debug_output) {
			bpf_printk("Dropping invalid Ethernet packet");
		}
		return -1;
	}

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

			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			outer_vlan_eth = data;

			if (data + sizeof(struct vlan_ethhdr) > data_end) {
				if (debug_output) {
					bpf_printk(
						"Dropping invalid Ethernet packet after head adjustment");
				}
				return -1;
			}

			// Move addresses to front
			__builtin_memmove(data, data + offset,
					  2 * sizeof(outer_vlan_eth->h_dest));
		} else if (overwrite_ether_type) {
			// This shall be a Ethernet header without VLAN tag,
			// so find the correct position for the type
			struct ethhdr *outer_eth = data;
			ether_type = &outer_eth->h_proto;
		}
	}

	if (overwrite_ether_type) {
		*ether_type =
			bpf_ntohs(target_outer_hdr.h_vlan_encapsulated_proto);
	}

	if (overwrite_vlan_proto_and_tci) {
		outer_vlan_eth->h_vlan_proto =
			bpf_ntohs(target_outer_hdr.h_vlan_proto);
		outer_vlan_eth->h_vlan_TCI =
			bpf_ntohs(target_outer_hdr.h_vlan_TCI);
	}

	if (overwrite_dest_addr) {
		// position is the same, regardless of existence of VLAN tag
		memcpy_v(outer_vlan_eth->h_dest, target_outer_hdr.h_dest,
			 sizeof(outer_vlan_eth->h_dest));
	}

	if (overwrite_source_addr) {
		// position is the same, regardless of existence of VLAN tag
		memcpy_v(outer_vlan_eth->h_source, target_outer_hdr.h_source,
			 sizeof(outer_vlan_eth->h_source));
	}

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
