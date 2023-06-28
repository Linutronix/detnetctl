// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/net_tstamp.h>
#include <net/if.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr,
			"Call as \"./enable_hw_timestamps <interface>\"\n");
		return 1;
	}

	const char *interface = argv[1];

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		fprintf(stderr, "Could not create socket\n");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);

	struct hwtstamp_config hwts_config;
	memset(&hwts_config, 0, sizeof(hwts_config));
	hwts_config.tx_type = HWTSTAMP_TX_ON;
	hwts_config.rx_filter = HWTSTAMP_FILTER_ALL;
	ifr.ifr_data = (void *)&hwts_config;
	if (ioctl(sockfd, SIOCSHWTSTAMP, &ifr) == -1) {
		fprintf(stderr, "Enabling hardware timestamps failed\n");
		close(sockfd);
		return -1;
	}
}
