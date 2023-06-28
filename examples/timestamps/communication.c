// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#include "communication.h"

#include <string.h>
#include <stdio.h>
#include <linux/errqueue.h>
#include <errno.h>
#include <linux/net_tstamp.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

enum SockTypes parse_sock_type(const char *str)
{
	if (strcmp(str, "INET_DGRAM") == 0) {
		return SOCK_TYPE_INET_DGRAM;
	} else if (strcmp(str, "INET_RAW") == 0) {
		return SOCK_TYPE_INET_RAW;
	} else if (strcmp(str, "INET_RAW_IP_HDRINCL") == 0) {
		return SOCK_TYPE_INET_RAW_IP_HDRINCL;
	} else if (strcmp(str, "PACKET_DGRAM") == 0) {
		return SOCK_TYPE_PACKET_DGRAM;
	} else if (strcmp(str, "PACKET_RAW") == 0) {
		return SOCK_TYPE_PACKET_RAW;
	} else if (strcmp(str, "XDP") == 0) {
		return SOCK_TYPE_XDP;
	} else {
		return SOCK_TYPE_INVALID;
	}
}

int setup_socket(const char *interface, int priority, int port,
		 struct Addresses *src_addr, enum SockTypes sock_type)
{
	int sockfd = -1;

	switch (sock_type) {
	case SOCK_TYPE_INET_DGRAM:
		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		break;

	case SOCK_TYPE_INET_RAW:
	case SOCK_TYPE_INET_RAW_IP_HDRINCL:
		sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

		if (sock_type == SOCK_TYPE_INET_RAW_IP_HDRINCL) {
			int enable = 1;
			if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable,
				       sizeof(int)) < 0) {
				fprintf(stderr,
					"Could not set IP_HDRINCL for socket\n");
				close(sockfd);
				return -1;
			}
		}
		break;

	case SOCK_TYPE_PACKET_DGRAM:
		sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
		break;

	case SOCK_TYPE_PACKET_RAW:
		sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
		break;

	case SOCK_TYPE_XDP:
		fprintf(stderr, "sock_type not yet implemented!\n");
		return -1;

	case SOCK_TYPE_INVALID:
	default:
		fprintf(stderr, "Invalid sock_type!\n");
		return -1;
	}

	if (sockfd == -1) {
		fprintf(stderr, "Could not create socket\n");
		if (sock_type != SOCK_TYPE_INET_DGRAM) {
			fprintf(stderr,
				"Maybe CAP_NET_RAW / sudo is missing?\n");
		}
		return -1;
	}

	// Set socket timeout
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "Could not set timeout for socket\n");
		close(sockfd);
		return -1;
	}

	// Setup timestamping (all timestamps available for UDP)
	int enable =
		SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_TX_SCHED | SOF_TIMESTAMPING_OPT_TX_SWHW |
		SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE |
		SOF_TIMESTAMPING_OPT_ID | SOF_TIMESTAMPING_OPT_TSONLY;
	if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &enable,
		       sizeof(int)) < 0) {
		fprintf(stderr, "Could not set timestamping for socket\n");
		close(sockfd);
		return -1;
	}

	// Setup IP_RECVERR to get sendto() errors on tc egress drops also for INET_* socket types.
	// This is apparently undocumented behavior (also see the referenced commit),
	// but it leads to a nicer output without impacting functionality (direct error instead of waiting for timeout).
	//
	//     commit 6ce9e7b5fe3195d1ae6e3a0753d4ddcac5cd699e
	//     Author: Eric Dumazet <eric.dumazet@gmail.com>
	//     Date:   Wed Sep 2 18:05:33 2009 -0700
	//
	//     ip: Report qdisc packet drops
	//
	if (sock_type == SOCK_TYPE_INET_DGRAM ||
	    sock_type == SOCK_TYPE_INET_RAW ||
	    sock_type == SOCK_TYPE_INET_RAW_IP_HDRINCL) {
		int enable = 1;
		if (setsockopt(sockfd, IPPROTO_IP, IP_RECVERR, &enable,
			       sizeof(int)) < 0) {
			fprintf(stderr,
				"Could not set IP_RECVERR for socket\n");
			close(sockfd);
			return -1;
		}
	}

	// Setup socket priority
	if (priority >= 0) {
		if (setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &priority,
			       sizeof(priority)) < 0) {
			fprintf(stderr, "Setting SO_PRIORITY failed\n");
			close(sockfd);
			return -1;
		}
	}

	// Prepare source address
	src_addr->in.sin_addr.s_addr = htonl(
		INADDR_ANY); // will be overwritten if interface is provided
	src_addr->in.sin_family = AF_INET;
	src_addr->in.sin_port = htons(port);

	// If interface is provided, setup accordingly
	struct ifreq ifr;
	if (interface != NULL) {
		size_t interface_len = strlen(interface);
		if (interface_len > 0) {
			if (interface_len >= sizeof(ifr.ifr_name)) {
				fprintf(stderr, "Interface name too long\n");
				close(sockfd);
				return -1;
			}

			memcpy(ifr.ifr_name, interface, interface_len);
			ifr.ifr_name[interface_len] = '\0';

			// Set socket option to bind to interface
			if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
				       (void *)&ifr, sizeof(ifr)) < 0) {
				fprintf(stderr,
					"Setting SO_BINDTODEVICE failed\n");
				close(sockfd);
				return -1;
			}

			// Fill source IP address
			if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
				fprintf(stderr,
					"Can not get source IP address\n");
				close(sockfd);
				return -1;
			}
			memcpy(&src_addr->in.sin_addr,
			       &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr,
			       sizeof(struct in_addr));

			if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
				fprintf(stderr,
					"Can not convert interface name to interface index\n");
				close(sockfd);
				return -1;
			}
			int ifindex = ifr.ifr_ifindex;

			if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
				fprintf(stderr,
					"Can not get source MAC address\n");
				close(sockfd);
				return -1;
			}

			// Fill source LL address
			src_addr->ll.sll_family = AF_PACKET;
			src_addr->ll.sll_ifindex = ifindex;
			src_addr->ll.sll_halen = ETHER_ADDR_LEN;
			src_addr->ll.sll_protocol = htons(ETH_P_IP);
			memcpy(src_addr->ll.sll_addr, ifr.ifr_hwaddr.sa_data,
			       ETHER_ADDR_LEN);
		}
	}

	// Bind
	struct sockaddr *bind_addr;
	size_t bind_addr_len;
	if (sock_type == SOCK_TYPE_INET_DGRAM ||
	    sock_type == SOCK_TYPE_INET_RAW ||
	    sock_type == SOCK_TYPE_INET_RAW_IP_HDRINCL) {
		bind_addr = (struct sockaddr *)&src_addr->in;
		bind_addr_len = sizeof(src_addr->in);
	} else {
		bind_addr = (struct sockaddr *)&src_addr->ll;
		bind_addr_len = sizeof(src_addr->ll);
	}

	if (bind(sockfd, bind_addr, bind_addr_len) != 0) {
		fprintf(stderr, "bind error\n");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

void prepare_udp_header(struct sockaddr_in src_addr,
			struct sockaddr_in dest_addr, struct Headers *hdr,
			size_t payload_size)
{
	hdr->udp.source = src_addr.sin_port;
	hdr->udp.dest = dest_addr.sin_port;
	hdr->udp.len = htons(sizeof(hdr->udp) + payload_size);
	hdr->udp.check = 0;
}

uint16_t ip_checksum(uint8_t *header, size_t size)
{
	unsigned long checksum = 0;
	uint16_t *buffer = (uint16_t *)header;
	while (size > 1) {
		checksum += *buffer++;
		size -= 2;
	}

	if (size) {
		checksum += *(uint8_t *)buffer;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	return ~checksum;
}

void prepare_ip_header(struct sockaddr_in src_addr,
		       struct sockaddr_in dest_addr, struct Headers *hdr,
		       size_t payload_size)
{
	memset(&(hdr->ip), 0, sizeof(struct iphdr));

	hdr->ip.ihl = 5;
	hdr->ip.version = 4;
	hdr->ip.ttl = 2;
	hdr->ip.saddr = src_addr.sin_addr.s_addr;
	hdr->ip.daddr = dest_addr.sin_addr.s_addr;
	hdr->ip.protocol = IPPROTO_UDP;
	hdr->ip.tot_len =
		htons(sizeof(hdr->ip) + sizeof(hdr->udp) + payload_size);
	hdr->ip.check = ip_checksum((uint8_t *)&(hdr->ip), sizeof(hdr->ip));
}

void prepare_ethernet_header(struct sockaddr_ll src_ll_addr,
			     struct sockaddr_ll dest_ll_addr,
			     struct Headers *hdr)
{
	memset(&(hdr->eth), 0, sizeof(struct ethhdr));

	memcpy(hdr->eth.h_source, src_ll_addr.sll_addr, ETHER_ADDR_LEN);
	memcpy(hdr->eth.h_dest, dest_ll_addr.sll_addr, ETHER_ADDR_LEN);
	hdr->eth.h_proto = htons(ETH_P_IP);
}

int prepare_headers(const struct Addresses *src_addr,
		    const struct Addresses *dest_addr, struct Headers *hdr,
		    size_t payload_size, enum SockTypes sock_type)
{
	if (sock_type == SOCK_TYPE_INET_DGRAM) {
		return 0;
	}

	prepare_udp_header(src_addr->in, dest_addr->in, hdr, payload_size);

	if (sock_type == SOCK_TYPE_INET_RAW) {
		// Remaining headers are added by kernel
		return 0;
	}

	prepare_ip_header(src_addr->in, dest_addr->in, hdr, payload_size);

	if (sock_type == SOCK_TYPE_INET_RAW_IP_HDRINCL ||
	    sock_type == SOCK_TYPE_PACKET_DGRAM) {
		// Remaining header is added by kernel
		return 0;
	}

	prepare_ethernet_header(src_addr->ll, dest_addr->ll, hdr);

	return 0;
}

int send_message(int sockfd, const struct Addresses *dest_addr, uint8_t *msg,
		 size_t total_msg_size, enum SockTypes sock_type)
{
	size_t offset = 0;
	struct sockaddr *addr = { 0 };
	size_t addrlen = 0;

	switch (sock_type) {
	case SOCK_TYPE_INET_DGRAM:
		// Only send payload. The UDP and IP headers are added by kernel.
		offset = sizeof(struct ethhdr) + sizeof(struct iphdr) +
			 sizeof(struct udphdr);
		addr = (struct sockaddr *)&dest_addr->in;
		addrlen = sizeof(struct sockaddr_in);
		break;
	case SOCK_TYPE_INET_RAW:
		// Since IP_HDRINCL is not set, only send UDP header and payload.
		offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
		addr = (struct sockaddr *)&dest_addr->in;
		addrlen = sizeof(struct sockaddr_in);
		break;
	case SOCK_TYPE_INET_RAW_IP_HDRINCL:
		offset = sizeof(struct ethhdr);
		addr = (struct sockaddr *)&dest_addr->in;
		addrlen = sizeof(struct sockaddr_in);
		break;
	case SOCK_TYPE_PACKET_DGRAM:
		offset = sizeof(struct ethhdr);
		addr = (struct sockaddr *)&dest_addr->ll;
		addrlen = sizeof(struct sockaddr_ll);
		break;
	case SOCK_TYPE_PACKET_RAW:
		offset = 0;
		addr = (struct sockaddr *)&dest_addr->ll;
		addrlen = sizeof(struct sockaddr_ll);
		break;
	case SOCK_TYPE_XDP:
		fprintf(stderr, "sock_type not yet implemented!\n");
		return -1;
	case SOCK_TYPE_INVALID:
	default:
		fprintf(stderr, "Invalid sock_type!\n");
		return -1;
	}

	if (offset > total_msg_size) {
		fprintf(stderr, "Message too short! %zu > %zu\n", offset,
			total_msg_size);
		return -1;
	}

	return sendto(sockfd, msg + offset, total_msg_size - offset, 0, addr,
		      addrlen);
}

int receive_offset(enum SockTypes sock_type)
{
	switch (sock_type) {
	case SOCK_TYPE_INET_DGRAM:
		// Only receive payload. UDP and IP headers are stripped by kernel.
		return sizeof(struct ethhdr) + sizeof(struct iphdr) +
		       sizeof(struct udphdr);
	case SOCK_TYPE_INET_RAW: // even if IP_HDRINCL is not set, IP header is received
	case SOCK_TYPE_INET_RAW_IP_HDRINCL:
	case SOCK_TYPE_PACKET_DGRAM:
		return sizeof(struct ethhdr);
	case SOCK_TYPE_PACKET_RAW:
		return 0;
	case SOCK_TYPE_XDP:
		fprintf(stderr, "sock_type not yet implemented!\n");
		return -1;
	case SOCK_TYPE_INVALID:
	default:
		fprintf(stderr, "Invalid sock_type!\n");
		return -1;
	}
}

int receive_message(int sockfd, uint8_t *data, size_t total_data_size,
		    enum SockTypes sock_type)
{
	int offset = receive_offset(sock_type);
	if (offset < 0) {
		return -1;
	}

	if ((size_t)offset > total_data_size) {
		fprintf(stderr, "Message too short! %i > %zu\n", offset,
			total_data_size);
		return -1;
	}

	return recv(sockfd, data + offset, total_data_size - offset, 0);
}

int receive_timestamped_message(int sockfd, uint8_t *message, size_t max_size,
				int flags, struct timespec *ts_sw,
				struct timespec *ts_hw,
				struct timespec *ts_user, int *tstype,
				int *tskey, struct Addresses *addresses,
				enum SockTypes sock_type)
{
	struct iovec iov[1];
	struct msghdr msg;
	char control[CMSG_SPACE(
		sizeof(struct scm_timestamping) +
		CMSG_SPACE(sizeof(struct sock_extended_err)))] = {};

	memset(iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));

	int offset = receive_offset(sock_type);
	if (offset < 0) {
		return -1;
	}

	if ((size_t)offset > max_size) {
		fprintf(stderr, "Message too short! %i > %zi\n", offset,
			max_size);
		return -1;
	}

	iov[0].iov_base = message + offset;
	iov[0].iov_len = max_size - offset;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	switch (sock_type) {
	case SOCK_TYPE_INET_DGRAM:
	case SOCK_TYPE_INET_RAW:
	case SOCK_TYPE_INET_RAW_IP_HDRINCL:
		msg.msg_name = &addresses->in;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;
	case SOCK_TYPE_PACKET_DGRAM:
	case SOCK_TYPE_PACKET_RAW:
	case SOCK_TYPE_XDP:
		msg.msg_name = &addresses->ll;
		msg.msg_namelen = sizeof(struct sockaddr_ll);
		break;
	case SOCK_TYPE_INVALID:
	default:
		fprintf(stderr, "Invalid sock_type!\n");
		return -1;
	}

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	msg.msg_flags = 0;

	int n = recvmsg(sockfd, &msg, flags);
	if (ts_user) {
		// get RX time after reception from kernel as early as possible
		clock_gettime(CLOCK_REALTIME, ts_user);
	}

	if (n < 0) {
		return n;
	}

	if (msg.msg_controllen < sizeof(struct cmsghdr)) {
		fprintf(stderr,
			"received truncated control message with length %ld\n",
			(long)msg.msg_controllen);
		return -1;
	}

	// Parse control messages
	struct scm_timestamping *tss = NULL;
	struct sock_extended_err *serr = NULL;
	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMPING) {
			tss = (void *)CMSG_DATA(cmsg);
		} else if ((cmsg->cmsg_level == SOL_IP &&
			    cmsg->cmsg_type == IP_RECVERR) ||
			   (cmsg->cmsg_level == SOL_IPV6 &&
			    cmsg->cmsg_type == IPV6_RECVERR) ||
			   (cmsg->cmsg_level == SOL_PACKET &&
			    cmsg->cmsg_type == PACKET_TX_TIMESTAMP)) {
			serr = (void *)CMSG_DATA(cmsg);
			if (serr->ee_errno != ENOMSG ||
			    serr->ee_origin != SO_EE_ORIGIN_TIMESTAMPING) {
				if (serr->ee_errno == ECONNREFUSED) {
					fprintf(stderr,
						"Connection refused!\n");
				} else {
					fprintf(stderr,
						"Unknown IP error %d %d\n",
						serr->ee_errno,
						serr->ee_origin);
				}

				serr = NULL;
				return -1;
			}
		}
	}

	if (tss == NULL) {
		fprintf(stderr, "no timestamp found\n");
		return -1;
	}

	// Fill available timestamps
	if (ts_sw && (tss->ts[0].tv_sec != 0 || tss->ts[0].tv_nsec != 0)) {
		memcpy(ts_sw, &(tss->ts[0]), sizeof(struct timespec));
	}

	if (ts_hw && (tss->ts[2].tv_sec != 0 || tss->ts[2].tv_nsec != 0)) {
		memcpy(ts_hw, &(tss->ts[2]), sizeof(struct timespec));
	}

	if (tstype && tskey) {
		if (serr == NULL) {
			fprintf(stderr, "no timestamp ID found\n");
			return -1;
		}

		*tstype = serr->ee_info;
		*tskey = serr->ee_data;
	}

	return n;
}
