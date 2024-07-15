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

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
	__uint(max_entries, 12);
} cpu_map SEC(".maps");

SEC("xdp/devmap")
int xdp_bridge_postprocessing(struct xdp_md *ctx)
{
	/*********************
	 *   SET L2 HEADER   *
	 *********************/
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
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
