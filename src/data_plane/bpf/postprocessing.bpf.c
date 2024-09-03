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
#define ETH_P_IP 0x0800
#define ETHER_ADDR_LEN 6
#define ICMP_DEST_UNREACH 3
#define ICMP_FRAG_NEEDED 4

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

#define MAX_ENCAPSULATED_FRAME_SIZE 1400

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
	__uint(max_entries, 12);
} cpu_map SEC(".maps");

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

int respond_to_large_packet(struct xdp_md *ctx, u16 total_encapsulation_size);

SEC("xdp/devmap")
int xdp_bridge_postprocessing(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/*************************
	 *     ENCAPSULATION     *
	 *************************/
	if (mpls_encapsulation || udp_ip_encapsulation) {
		u16 total_encapsulation_size = sizeof(struct vlan_ethhdr);
		if (udp_ip_encapsulation) {
			total_encapsulation_size +=
				sizeof(struct ipv6hdr) + sizeof(struct udphdr);
		}
		if (mpls_encapsulation) { // without control word that was added before redirect
			total_encapsulation_size += sizeof(mpls_stack_entry);
		}

		u16 payload_len = data_end - data;

		bpf_printk("encapsulated frame size %i", payload_len + total_encapsulation_size);

		if (payload_len + total_encapsulation_size >
		    MAX_ENCAPSULATED_FRAME_SIZE) {
			if (debug_output) {
				bpf_printk(
					"Packet with encapsulation header does not fit into MTU");
			}

			return respond_to_large_packet(
				ctx, total_encapsulation_size);
		}

		if (bpf_xdp_adjust_head(ctx, -total_encapsulation_size)) {
			if (debug_output) {
				bpf_printk(
					"Changing packet size for encapsulation failed");
			}
			return XDP_DROP;
		}

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		// make space for outer Ethernet header but write to it
		// under "SET L2 HEADER" that is also used to overwrite
		// the existing Ethernet header if no encapsulation takes place

		void *mplsh = data + sizeof(struct vlan_ethhdr);

		if (udp_ip_encapsulation) {
			struct ipv6hdr *ip6h =
				data + sizeof(struct vlan_ethhdr);
			struct udphdr *udph =
				(void *)ip6h + sizeof(struct ipv6hdr);
			mplsh = ((void *)mplsh) + sizeof(struct ipv6hdr) +
				sizeof(struct udphdr);

			if ((void *)udph + sizeof(struct udphdr) > data_end ||
			    (void *)ip6h + sizeof(struct ipv6hdr) > data_end) {
				if (debug_output) {
					bpf_printk(
						"UDP IP encapsulation failed");
				}

				return XDP_DROP;
			}

			memcpy_v(udph, udp_header, sizeof(struct udphdr));
			memcpy_v(ip6h, ip_header, sizeof(struct ipv6hdr));

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
			if ((void *)mplsh + sizeof(mpls_stack_entry) >
			    data_end) {
				if (debug_output) {
					bpf_printk("MPLS encapsulation failed");
				}

				return XDP_DROP;
			}

			*(u32 *)mplsh = mpls_stack_entry;
		}
	}

	/*********************
	 *   SET L2 HEADER   *
	 *********************/
	struct vlan_ethhdr *outer_vlan_eth = data;
	u16 *ether_type = &outer_vlan_eth->h_vlan_encapsulated_proto;

	if (data + sizeof(struct vlan_ethhdr) > data_end) {
		if (debug_output) {
			bpf_printk("Dropping invalid Ethernet packet");
		}
		return -1;
	}

	u16 vlan_proto = bpf_ntohs(outer_vlan_eth->h_vlan_proto);
	if (!mpls_encapsulation && !udp_ip_encapsulation &&
	    vlan_proto != ETH_P_8021Q && vlan_proto != ETH_P_8021AD) {
		// There is no VLAN tag yet and no encapsulation shall take place
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

static __always_inline void swap_src_dst_mac(struct vlan_ethhdr *eth)
{
	__u8 h_tmp[ETHER_ADDR_LEN];

	__builtin_memcpy(h_tmp, eth->h_source, ETHER_ADDR_LEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETHER_ADDR_LEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETHER_ADDR_LEN);
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;

	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

static __always_inline u16 calculate_checksum(unsigned short *data,
					      unsigned int count)
{
	unsigned long sum = 0;

	for (int i = 0; i < count; i++) {
		sum += *data;
		data++;
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

// Respond to too large packet with ICMP_DEST_UNREACH/ICMP_FRAG_NEEDED.
// This is particularly important for TCP transmitters to adapt the frame size.
// Currently only implemented for IPv4
int respond_to_large_packet(struct xdp_md *ctx, u16 total_encapsulation_size)
{
	// DetNet CW was already prepended, so remove again
	if (bpf_xdp_adjust_head(ctx, 4)) {
		if (debug_output) {
			bpf_printk(
				"Internal error: Cannot remove CW for sending ICMP");
		}
		return XDP_DROP;
	}

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_ethhdr *ethhdr = data;

	if (data + sizeof(struct vlan_ethhdr) > data_end) {
		if (debug_output) {
			bpf_printk(
				"Internal error: Packet too large for encapsulation, but too small for Ethernet header");
		}
		return XDP_DROP;
	}

	u16 vlan_proto = bpf_ntohs(ethhdr->h_vlan_proto);
	u16 ether_type;
	struct iphdr *ip;
	u16 ethsize;
	if (vlan_proto != ETH_P_8021Q && vlan_proto != ETH_P_8021AD) {
		ether_type = vlan_proto;
		ethsize = sizeof(struct ethhdr);
	} else {
		ether_type = bpf_ntohs(ethhdr->h_vlan_encapsulated_proto);
		ethsize = sizeof(struct vlan_ethhdr);
	}

	ip = data + ethsize;

	if (ether_type != ETH_P_IP) {
		if (debug_output) {
			bpf_printk(
				"Responding to too large packets currently only implemented for IPv4");
		}
		return XDP_DROP;
	}

	struct icmphdr *icmp = (void *)ip + sizeof(struct iphdr);
	void *orig_hdr =
		(void *)icmp +
		sizeof(struct icmphdr); // ICMP response contains original IP header

	if ((void *)ip + sizeof(struct iphdr) > data_end ||
	    (void *)icmp + sizeof(struct icmphdr) > data_end ||
	    (void *)orig_hdr + sizeof(struct iphdr) + 8 > data_end) {
		if (debug_output) {
			bpf_printk(
				"Internal error: Packet too large for encapsulation, but too small to fit ICMP response");
		}
		return XDP_DROP;
	}

	__builtin_memcpy(orig_hdr, ip, sizeof(struct iphdr) + 8);

	swap_src_dst_ipv4(ip);
	swap_src_dst_mac(ethhdr);

	u16 ip_tot_len =
		(void *)orig_hdr + sizeof(struct iphdr) + 8 - (void *)ip;
	ip->tot_len = bpf_htons(ip_tot_len);

	ip->protocol = IPPROTO_ICMP;

	icmp->type = ICMP_DEST_UNREACH;
	icmp->code = ICMP_FRAG_NEEDED;
	icmp->un.frag.__unused = 0;
	int max_forwarded_frame_size =
		MAX_ENCAPSULATED_FRAME_SIZE - total_encapsulation_size;
	icmp->un.frag.mtu = bpf_htons(max_forwarded_frame_size -
				      ethsize); // MTU excludes L2 header

	ip->check = 0;
	ip->check = calculate_checksum((unsigned short *)ip,
				       sizeof(struct iphdr) / 2);

	icmp->checksum = 0;
	icmp->checksum = calculate_checksum(
		(unsigned short *)icmp,
		(sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) / 2);

	if (bpf_xdp_adjust_tail(ctx, ((void *)ip + ip_tot_len) - data_end)) {
		if (debug_output) {
			bpf_printk(
				"Changing packet size for ICMP response failed");
		}
		return XDP_DROP;
	}

	return bpf_redirect(ctx->ingress_ifindex, 0); // send back
}

char __license[] SEC("license") = "GPL";
