// SPDX-FileCopyrightText: Copyright (c) 2024, Ericsson Research
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Originally developed as part of xdpfrer
// https://github.com/EricssonResearch/xdpfrer
// and modified for integration.
//
// For details see
// @misc{fejes2023lightweight,
//    title={Lightweight Implementation of Per-packet Service Protection in eBPF/XDP},
//    author={Ferenc Fejes and Ferenc Orosi and Balázs Varga and János Farkas},
//    booktitle={Netdev 0x17, THE Technical Conference on Linux Networking},
//    year={2023},
//    eprint={2312.07152},
//    archivePrefix={arXiv},
//    primaryClass={cs.NI},
//    url={https://netdevconf.info/0x17/25}
// }

#ifndef __FRER_BPF_H__
#define __FRER_BPF_H__

#include "../../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <stdbool.h>
#include <string.h>

// HST = history window, sequence number, take any
// 0th-46th bit means the history window
// 47th-62nd bit means the sequence number
// 63rd means the take any
typedef uint64_t HST;
#define TAKE_ANY 63
#define SEQ_START_BIT 47
#define FRER_DEFAULT_HIST_LEN 47
#define FRER_RCVY_SEQ_SPACE (1 << 16)
#define FRER_RCVY_TIMEOUT_NS ((1000 * 1000 * 1000) * 2)
#define FRER_TIMEOUT_CHECK_PERIOD_NS ((1000 * 1000 * 1000) / 100) //every 10ms

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

// Per-ifindex ingress VLAN translation table
struct vlan_translation_entry {
	int from;
	int to;
};

struct seq_rcvy_and_hist {
	unsigned reset_msec;
	bool individual_recovery;

	HST hist_recvseq_takeany;

	int lost_packets;
	int out_of_order_packets;
	int passed_packets;
	int rogue_packets;
	int discarded_packets;
	int remaining_ticks;
	int seq_recovery_resets;
	int latent_errors;
	int latent_reset_counter;
	int latent_error_counter;
	int latent_error_resets;

	unsigned long last_packet_ns;
	struct bpf_spin_lock lock;
};

struct seq_gen {
	int gen_seq_num;

	int resets;
};

static inline int calc_delta(ushort seq1, ushort seq2)
{
	int delta = (seq1 - seq2) & (FRER_RCVY_SEQ_SPACE - 1);
	if ((delta & (FRER_RCVY_SEQ_SPACE / 2)) != 0)
		delta = delta - FRER_RCVY_SEQ_SPACE;
	return delta;
}

static inline void reset_ticks(struct seq_rcvy_and_hist *rec)
{
	(void)rec;
}

#undef bpf_printk
#define bpf_printk(fmt, ...)                                               \
	({                                                                 \
		static const char ____fmt[] = fmt;                         \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})

static inline int genseq(struct seq_gen *gen)
{
	int seq = gen->gen_seq_num;
	if (gen->gen_seq_num >= FRER_RCVY_SEQ_SPACE - 1)
		gen->gen_seq_num = 0;
	else
		gen->gen_seq_num += 1;
	return seq;
}

struct rtaghdr {
	uint16_t reserved;
	uint16_t seq;
	uint16_t nexthdr;
} __attribute__((packed));

const size_t ethhdr_sz = sizeof(struct ethhdr);
const size_t vlanhdr_sz = sizeof(struct vlan_hdr);
const size_t rtaghdr_sz = sizeof(struct rtaghdr);
const size_t iphdr_sz = sizeof(struct iphdr);

// UNI VLAN ---> Seq generator
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct seq_gen));
} seqgen_map SEC(".maps");

// Stream handle ---> Seq recovery
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, u16);
	__type(value, struct seq_rcvy_and_hist);
} seqrcvy_map SEC(".maps");

volatile int packets_seen = 0;
volatile int dropped = 0;
volatile int passed = 0;

static inline long reset_recovery_cb(struct bpf_map *map, const void *key,
				     void *value, void *ctx)
{
	struct seq_rcvy_and_hist *rec = value;
	if (rec && ((rec->hist_recvseq_takeany >> TAKE_ANY) & 1LU) == true)
		goto end;

	if (bpf_ktime_get_ns() - rec->last_packet_ns < FRER_RCVY_TIMEOUT_NS)
		goto end;

	// Reset history window
	rec->hist_recvseq_takeany = 0;

	rec->hist_recvseq_takeany ^= (-(true) ^ rec->hist_recvseq_takeany) &
				     (1UL << TAKE_ANY); // set take any true
	rec->latent_error_resets += 1;
	//bpf_printk("Seq recovery reset for VLAN %d", *((int *) key));
end:
	return 0;
}

static void timer_cb()
{
	bpf_for_each_map_elem(&seqrcvy_map, reset_recovery_cb, NULL, 0);
}

static inline ulong bit_range(HST value, int from, int to)
{
	HST waste = sizeof(HST) * 8 - to - 1;
	return (value << waste) >> (waste + from);
}

static inline bool recover(struct seq_rcvy_and_hist *rec, ushort seq)
{
	HST hst = rec->hist_recvseq_takeany;
	uint64_t history_window = bit_range(hst, 0, SEQ_START_BIT - 1);
	bool take_any = (hst >> TAKE_ANY) & 1LU;
	ushort recv_seq = bit_range(hst, SEQ_START_BIT, TAKE_ANY - 1);

	int delta = calc_delta(seq, recv_seq);
	if (take_any) {
		history_window |= (1UL << (FRER_DEFAULT_HIST_LEN -
					   1)); // set first bit to 1
		take_any = false;
		recv_seq = seq;
		rec->passed_packets += 1;
		reset_ticks(rec);
		goto pass;
	} else if (delta >= FRER_DEFAULT_HIST_LEN ||
		   delta <= -FRER_DEFAULT_HIST_LEN) {
		rec->rogue_packets += 1;
		rec->discarded_packets += 1;

		if (rec->individual_recovery)
			reset_ticks(rec);
	} else if (delta <= 0) {
		if (-delta !=
		    FRER_DEFAULT_HIST_LEN) { // error check for verifier
			goto drop;
		}

		if (((history_window >> -delta) & 1LU) ==
		    0) { // checking -deltath bit
			history_window |=
				(1UL << -delta); // set deltath bit to 1
			rec->out_of_order_packets += 1;
			rec->passed_packets += 1;
			reset_ticks(rec);
			goto pass;
		} else {
			rec->discarded_packets += 1;
			if (rec->individual_recovery)
				reset_ticks(rec);
		}
	} else {
		if (delta != 1) {
			rec->out_of_order_packets += 1;
		}
		history_window =
			(history_window >> delta); // shift every bit to right
		history_window |= (1UL << (FRER_DEFAULT_HIST_LEN -
					   1)); // set first bit to 1
		recv_seq = seq;
		rec->passed_packets += 1;
		reset_ticks(rec);
		goto pass;
	}
	goto drop;
drop:
	// Copy history window to hst.
	for (int i = 0; i < SEQ_START_BIT; i++)
		hst ^= (-((history_window >> i) & 1LU) ^ hst) & (1UL << i);

	// Copy seqence number to hst.
	for (int i = SEQ_START_BIT; i < TAKE_ANY; i++)
		hst ^= ((-((recv_seq >> (i - SEQ_START_BIT)) & 1LU)) ^ hst) &
		       (1UL << i);

	// Set take any.
	hst ^= (-(take_any) ^ hst) & (1UL << TAKE_ANY);

	rec->hist_recvseq_takeany = hst;
	return false;
pass:
	// Copy history window to hst.
	for (int i = 0; i < SEQ_START_BIT; i++)
		hst ^= (-((history_window >> i) & 1LU) ^ hst) & (1UL << i);

	// Copy seqence number to hst.
	for (int i = SEQ_START_BIT; i < TAKE_ANY; i++)
		hst ^= ((-((recv_seq >> (i - SEQ_START_BIT)) & 1LU)) ^ hst) &
		       (1UL << i);

	// Set take any.
	hst ^= (-(take_any) ^ hst) & (1UL << TAKE_ANY);

	rec->hist_recvseq_takeany = hst;
	return true;
}

static inline int add_rtag(struct xdp_md *pkt, ushort *seq)
{
	// Make room for R-tag
	if (bpf_xdp_adjust_head(pkt, 0 - (int)rtaghdr_sz))
		return -1;

	void *data = (void *)(long)pkt->data;
	void *data_end = (void *)(long)pkt->data_end;
	if (data + rtaghdr_sz + ethhdr_sz + vlanhdr_sz >
	    data_end) // bound check for verifier
		return -1;

	// Move Ethernet+VLAN headers to the front of the buffer
	__builtin_memmove(data, data + rtaghdr_sz, ethhdr_sz + vlanhdr_sz);
	struct vlan_hdr *vhdr = data + ethhdr_sz;
	struct rtaghdr *rtag = data + ethhdr_sz + vlanhdr_sz;

	// Prepare the R-tag
	__builtin_memset(rtag, 0, rtaghdr_sz);
	rtag->nexthdr = vhdr->h_vlan_encapsulated_proto;
	vhdr->h_vlan_encapsulated_proto = bpf_htons(0xf1c1);
	rtag->seq = bpf_htons(*seq);

	return 0;
}

static inline int rm_rtag(struct xdp_md *pkt, ushort *seq)
{
	// Find the R-tag in the header
	void *data = (void *)(long)pkt->data;
	void *data_end = (void *)(long)pkt->data_end;
	if (data + ethhdr_sz + vlanhdr_sz + rtaghdr_sz > data_end)
		return -1;

	struct vlan_hdr *vhdr = data + ethhdr_sz;
	struct rtaghdr *rtag = data + ethhdr_sz + vlanhdr_sz;

	//TODO: restore next proto header after R-tag
	vhdr->h_vlan_encapsulated_proto = rtag->nexthdr;

	// Get the seq number from R-tag
	*seq = bpf_ntohs(rtag->seq);

	// Remove the R-tag
	__builtin_memmove(data + rtaghdr_sz, data, ethhdr_sz + vlanhdr_sz);
	if (bpf_xdp_adjust_head(pkt, (int)rtaghdr_sz))
		return -1;

	return 0;
}

SEC("xdp")
int check_reset(void)
{
	timer_cb();
	return 1;
}

char LICENSE[] SEC("license") = "GPL";

#endif /* __FRER_BPF_H__ */
