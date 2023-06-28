// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#include "communication.h"
#include "realtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <getopt.h>

#define DEFAULT_PORT 4321
#define STR_(x) #x
#define STR(x) STR_(x)

static volatile sig_atomic_t exiting = 0;

void sig_int(__attribute__((unused)) int signo)
{
	exiting = 1;
}

static void print_usage(const char *filepath)
{
	fprintf(stderr,
		"\nUsage: %s [options]\n"
		"\nwith the following options:\n"
		"  -s, --socktype  [socktype]   One of\n"
		"                                 INET_DGRAM           For socket(AF_INET, SOCK_DGRAM, 0) (default)\n"
		"\n"
		"                                 INET_RAW             For socket(AF_INET, SOCK_RAW, IPPROTO_UDP)\n"
		"                                 INET_RAW_IP_HDRINCL  Like INET_RAW, but also set IP_HDRINCL\n"
		"                                                      For both INET_RAW* options, the packet is still additionally passed to the UDP layer\n"
		"                                                      and generates ICMP port unreachable messages. They can be dropped with e.g.\n"
		"                                                        iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP\n"
		"\n"
		"                                 PACKET_DGRAM         For socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))\n"
		"                                 PACKET_RAW           For socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))\n"
		"                                                      For both PACKET_* options, the packet is still additionally passed to the IP layer\n"
		"                                                      and generates ICMP port unreachable messages. This can be prevented with e.g.\n"
		"                                                        iptables -t raw -A PREROUTING -p udp --dport 4321 -j DROP -i eth0\n"
		"\n"
		"  -i, --interface [interface]  Interface to bind to (default: do not explictly bind)\n"
		"                               Do not explicitly bind to interface if not provided as CLI and not via detnetctl registration.\n"
		"  -p, --port      [port]       Destination port (default: " STR(
			DEFAULT_PORT) ")\n"
				      "  -r, --realtime  [priority]   Enable SCHED_FIFO with the given priority (if not provided, default scheduling is used)\n"
				      "  -c, --cpu       [cpu]        Run on provided CPU (if not provided, no CPU affinity is set up)\n",
		filepath);
}

int main(int argc, char *argv[])
{
	char interface[IF_NAMESIZE] = { 0 };
	uint16_t port = DEFAULT_PORT;
	enum SockTypes sock_type = SOCK_TYPE_INET_DGRAM;

	// Parse command line options
	while (1) {
		static struct option long_options[] = {
			{ "socktype", required_argument, 0, 's' },
			{ "interface", required_argument, 0, 'i' },
			{ "port", required_argument, 0, 'p' },
			{ "realtime", required_argument, 0, 'r' },
			{ "cpu", required_argument, 0, 'c' },
			{ 0, 0, 0, 0 }
		};

		int option_index = 0;
		int c = getopt_long(argc, argv, "s:i:p:r:c:h", long_options,
				    &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 's':
			sock_type = parse_sock_type(optarg);
			if (sock_type == SOCK_TYPE_INVALID) {
				fprintf(stderr,
					"Invalid socktype %s provided!\n",
					optarg);
				print_usage(argv[0]);
				return 1;
			}
			break;
		case 'i':
			if (strlen(optarg) > sizeof(interface) - 1) {
				fprintf(stderr,
					"Interface %s shall not be longer than %zu characters!\n",
					optarg, sizeof(interface) - 1);
				print_usage(argv[0]);
				return 1;
			}
			strncpy(interface, optarg, sizeof(interface));
			break;
		case 'p': {
			long int l = strtol(optarg, NULL, 10);
			if (l < 0 || l > UINT16_MAX) {
				fprintf(stderr, "Invalid port %s provided!\n",
					optarg);
				print_usage(argv[0]);
				return 1;
			}
			port = (uint16_t)l;
			break;
		}
		case 'r': {
			long int l = strtol(optarg, NULL, 10);
			if (l < 0 || l > UINT8_MAX) {
				fprintf(stderr,
					"Invalid realtime priority %s provided!\n",
					optarg);
				print_usage(argv[0]);
				return 1;
			}
			if (activate_sched_fifo((uint8_t)l) != 0) {
				return 1;
			}
			break;
		}
		case 'c': {
			long int l = strtol(optarg, NULL, 10);
			if (l < 0 || l > UINT8_MAX) {
				fprintf(stderr, "Invalid CPU %s provided!\n",
					optarg);
				print_usage(argv[0]);
				return 1;
			}
			if (set_cpu_affinity((uint8_t)l) != 0) {
				return 1;
			}
			break;
		}
		case 'h':
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (sock_type == SOCK_TYPE_PACKET_DGRAM ||
	    sock_type == SOCK_TYPE_PACKET_RAW || sock_type == SOCK_TYPE_XDP) {
		if (strlen(interface) == 0) {
			fprintf(stderr,
				"Interface required for this socktype!\n");
			print_usage(argv[0]);
			return 1;
		}
	}

	struct Addresses src_addr = { 0 };

	// Setup and bind to socket
	int sockfd = setup_socket(interface, 0, port, &src_addr, sock_type);
	if (sockfd == -1) {
		return 1;
	}

	// Enter main server loop
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "Can't set signal handler: %s\n",
			strerror(errno));
		return 1;
	}

	while (!exiting) {
		struct timespec ts_sw = {};
		struct timespec ts_hw = {};
		struct timespec ts_user = {};
		struct Addresses dest_addr = {};
		struct RequestMessage hi_msg;
		//int n = receive_timestamped_message(sockfd, (uint8_t *)&hi_msg, sizeof(hi_msg), 0, &ts_sw, &ts_hw, &ts_user, NULL, NULL, &addresses.dest_ip, sock_type);
		int n = receive_timestamped_message(
			sockfd, (uint8_t *)&hi_msg, sizeof(hi_msg), 0, &ts_sw,
			&ts_hw, &ts_user, NULL, NULL, &dest_addr, sock_type);
		if (n < (int)sizeof(struct RequestPayload) ||
		    hi_msg.payload.type != HI_TYPE) {
			continue;
		}

		if (ts_hw.tv_sec == 0) {
			fprintf(stderr, "Can not request HW RX timestamp.\n");
			fprintf(stderr,
				"Please make sure hardware timestamps are enabled (e.g. see \"enable_hw_timestamps\" in examples/utils).\n");
			continue;
		}

		if (sock_type != SOCK_TYPE_INET_DGRAM) {
			// Copy client port from UDP header since it is not filled by recvmsg in this case
			dest_addr.in.sin_port = hi_msg.hdr.udp.source;
		}

		if (sock_type == SOCK_TYPE_PACKET_DGRAM ||
		    sock_type == SOCK_TYPE_PACKET_RAW ||
		    sock_type == SOCK_TYPE_XDP) {
			// Copy client IP address from IP header since it is not filled by recvmsg in this case
			memcpy(&dest_addr.in.sin_addr.s_addr,
			       &hi_msg.hdr.ip.saddr,
			       sizeof(hi_msg.hdr.ip.saddr));
		}

		if (sock_type == SOCK_TYPE_PACKET_RAW ||
		    sock_type == SOCK_TYPE_XDP) {
			// Fill client LL address since it is not filled by recvmsg in this case
			dest_addr.ll.sll_family = AF_PACKET;
			dest_addr.ll.sll_ifindex = src_addr.ll.sll_ifindex;
			dest_addr.ll.sll_halen = ETHER_ADDR_LEN;
			dest_addr.ll.sll_protocol = htons(ETH_P_IP);
			memcpy(dest_addr.ll.sll_addr, hi_msg.hdr.eth.h_source,
			       ETHER_ADDR_LEN);
		}

		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(dest_addr.in.sin_addr), str,
			  INET_ADDRSTRLEN);
		printf("Received %" PRIu32 " from %s %i\n", hi_msg.payload.seq,
		       str, ntohs(dest_addr.in.sin_port));

		struct ResponseMessage time_msg;
		time_msg.payload.type = TIME_TYPE;
		time_msg.payload.seq = hi_msg.payload.seq;
		time_msg.payload.user.seconds = ts_user.tv_sec;
		time_msg.payload.user.nanoseconds = ts_user.tv_nsec;
		time_msg.payload.sw.seconds = ts_sw.tv_sec;
		time_msg.payload.sw.nanoseconds = ts_sw.tv_nsec;
		time_msg.payload.hw.seconds = ts_hw.tv_sec;
		time_msg.payload.hw.nanoseconds = ts_hw.tv_nsec;

		if (prepare_headers(&src_addr, &dest_addr, &time_msg.hdr,
				    sizeof(time_msg.payload), sock_type) != 0) {
			fprintf(stderr, "Can not prepare message\n");
			continue;
		}

		if (send_message(sockfd, &dest_addr, (uint8_t *)&time_msg,
				 sizeof(struct ResponseMessage),
				 sock_type) < 0) {
			fprintf(stderr, "Can not send message\n");
			continue;
		}

		fflush(stdout);
	}

	printf("\n");

	return 0;
}
