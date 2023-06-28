// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#include "communication.h"
#include "client_loop.h"
#include "../common/registration.h"
#include "realtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

#define MAX_APPNAME_SIZE 100
#define DEFAULT_PORT 4321
#define STR_(x) #x
#define STR(x) STR_(x)

static void print_usage(const char *filepath)
{
	fprintf(stderr,
		"\nUsage: %s [options] server_ip\n"
		"\nwith the following options:\n"
		"  -a, --app  [app_name]        Register at the node controller with the provided app_name.\n"
		"                               Can not be combined with --interface and --priority, because they will be\n"
		"                               provided automatically during registration!\n"
		"                               If not provided, no registration at the node controller takes place!\n"
		"  -s, --socktype  [socktype]   One of\n"
		"                                 INET_DGRAM           For socket(AF_INET, SOCK_DGRAM, 0)\n"
		"                                 (default)            Send only application payload to kernel\n"
		"\n"
		"                                 INET_RAW             For socket(AF_INET, SOCK_RAW, IPPROTO_UDP)\n"
		"                                                      Send application payload and UDP header to kernel\n"
		"\n"
		"                                 INET_RAW_IP_HDRINCL  Like INET_RAW, but also set IP_HDRINCL\n"
		"                                                      Send application payload, UDP and IP header to kernel\n"
		"\n"
		"                                 PACKET_DGRAM         For socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))\n"
		"                                                      Send application payload, UDP and IP header to kernel\n"
		"                                                      and provide MAC address (set via --mac) in sockaddr_ll.\n"
		"\n"
		"                                 PACKET_RAW           For socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))\n"
		"                                                      Send application payload, UDP, IP and Ethernet header to kernel\n"
		"                                                      MAC address needs to be provided via --mac!\n"
		"  -i, --interface [interface]  Interface to bind to / to use.\n"
		"                               Do not explicitly bind to interface if not provided as CLI and not via detnetctl registration.\n"
		"  -P, --priority  [priority]   SO_PRIORITY to use (default: do not set SO_PRIORITY)\n"
		"  -p, --port      [port]       Source and destination port (default: " STR(
			DEFAULT_PORT) ")\n"
				      "  -m, --mac       [macaddress] Destination MAC address (required for PACKET_DGRAM, PACKET_RAW and XDP, ignored for all others).\n"
				      "                               Format as 01:23:45:67:89:AB\n"
				      "  -r, --realtime  [priority]   Enable SCHED_FIFO with the given priority (if not provided, default scheduling is used)\n"
				      "  -c, --cpu       [cpu]        Run on provided CPU (if not provided, no CPU affinity is set up)\n"
				      "  -n, --number    [n]          Send n packets then exit (if not provided or n < 0, continue until SIGINT)\n",
		filepath);
}

int main(int argc, char *argv[])
{
	bool do_registration = false;
	char app_name[MAX_APPNAME_SIZE + 1] = { 0 };
	char interface[IF_NAMESIZE] = { 0 };
	int8_t priority = -1;
	uint16_t port = DEFAULT_PORT;
	enum SockTypes sock_type = SOCK_TYPE_INET_DGRAM;
	uint8_t dest_mac_addr[ETHER_ADDR_LEN] = { 0 };
	bool dest_mac_addr_provided = false;
	int32_t max_packets = -1;

	// Parse command line options
	if (argc <= 1) {
		print_usage(argv[0]);
		return 1;
	}

	while (1) {
		static struct option long_options[] = {
			{ "app", required_argument, 0, 'a' },
			{ "interface", required_argument, 0, 'i' },
			{ "priority", required_argument, 0, 'P' },
			{ "port", required_argument, 0, 'p' },
			{ "mac", required_argument, 0, 'm' },
			{ "socktype", required_argument, 0, 's' },
			{ "realtime", required_argument, 0, 'r' },
			{ "cpu", required_argument, 0, 'c' },
			{ "number", required_argument, 0, 'n' },
			{ 0, 0, 0, 0 }
		};

		int option_index = 0;
		int c = getopt_long(argc, argv, "a:i:P:p:m:s:r:c:n:h",
				    long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'a':
			do_registration = true;
			if (strlen(optarg) > sizeof(app_name) - 1) {
				fprintf(stderr,
					"App name %s shall not be longer than %zu characters!\n",
					optarg, sizeof(app_name) - 1);
				print_usage(argv[0]);
				return 1;
			}
			strncpy(app_name, optarg, sizeof(app_name));
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
		case 'P': {
			long int l = strtol(optarg, NULL, 10);
			if (l < 0 || l > INT8_MAX) {
				fprintf(stderr,
					"Invalid priority %s provided!\n",
					optarg);
				print_usage(argv[0]);
				return 1;
			}
			priority = (int8_t)l;
			break;
		}
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
		case 'm': {
			int values[6];
			if (6 != sscanf(optarg, "%x:%x:%x:%x:%x:%x%*c",
					&values[0], &values[1], &values[2],
					&values[3], &values[4], &values[5])) {
				fprintf(stderr,
					"Invalid MAC address %s provided!\n",
					optarg);
				print_usage(argv[0]);
				return 1;
			}

			for (int i = 0; i < 6; i++) {
				if (values[i] < 0 || values[i] > UINT8_MAX) {
					fprintf(stderr,
						"Invalid MAC address %s provided!\n",
						optarg);
					print_usage(argv[0]);
					return 1;
				}
				dest_mac_addr[i] = (uint8_t)values[i];
			}
			dest_mac_addr_provided = true;
			break;
		}
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
		case 'n': {
			long int l = strtol(optarg, NULL, 10);
			if (l > INT32_MAX) {
				fprintf(stderr, "Invalid number %s provided!\n",
					optarg);
				print_usage(argv[0]);
				return 1;
			}

			max_packets = (int32_t)l;
		} break;
		case 'h':
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (sock_type == SOCK_TYPE_PACKET_DGRAM ||
	    sock_type == SOCK_TYPE_PACKET_RAW || sock_type == SOCK_TYPE_XDP) {
		if (!dest_mac_addr_provided) {
			fprintf(stderr,
				"Destination MAC address required for this socktype!\n");
			print_usage(argv[0]);
			return 1;
		}

		if (strlen(interface) == 0) {
			fprintf(stderr,
				"Interface required for this socktype!\n");
			print_usage(argv[0]);
			return 1;
		}
	} else {
		if (dest_mac_addr_provided) {
			fprintf(stderr,
				"Warning: Provided MAC address is ignored for this socktype!\n");
		}
	}

	if (optind != argc - 1) {
		fprintf(stderr, "Missing destination IP!\n");
		print_usage(argv[0]);
		return 1;
	}

	const char *destination_ip = argv[argc - 1];

	// Perform registration (if requested)
	uint64_t token = 0;
	if (do_registration) {
		int result = register_app(app_name, interface,
					  sizeof(interface), &priority, &token);
		if (result != 0) {
			return result;
		}
	}

	// Setup socket
	struct Addresses src_addr = {};
	struct Addresses dest_addr = {};
	int sockfd =
		setup_socket(interface, priority, port, &src_addr, sock_type);
	if (sockfd == -1) {
		return 1;
	}

	if (do_registration) {
#ifdef SO_TOKEN
		if (setsockopt(sockfd, SOL_SOCKET, SO_TOKEN, &token,
			       sizeof(token)) < 0) {
			fprintf(stderr, "Setting SO_TOKEN failed\n");
			close(sockfd);
			return -1;
		}
#else
		fprintf(stderr,
			"WARNING: SO_TOKEN not available, so token is not set!\n");

#endif
	}

	// Fill destination address
	dest_addr.in.sin_addr.s_addr = inet_addr(destination_ip);
	dest_addr.in.sin_family = AF_INET;
	dest_addr.in.sin_port = htons(port);

	// Fill destination LL address
	if (src_addr.ll.sll_halen > 0) {
		dest_addr.ll.sll_family = AF_PACKET;
		dest_addr.ll.sll_ifindex = src_addr.ll.sll_ifindex;
		dest_addr.ll.sll_halen = ETHER_ADDR_LEN;
		dest_addr.ll.sll_protocol = htons(ETH_P_IP);
		memcpy(dest_addr.ll.sll_addr, dest_mac_addr, ETHER_ADDR_LEN);
	}

	// Main loop
	return client_loop(sockfd, &src_addr, &dest_addr, max_packets,
			   sock_type);
}
