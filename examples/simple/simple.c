// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <netdb.h>

#include "../common/ptp_status.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(__attribute__((unused)) int signo)
{
	exiting = 1;
}

int print_usage(char *name)
{
	fprintf(stderr, "Call as\n");
	fprintf(stderr, "%s <hostname> [<interface>]\n", name);
	fprintf(stderr,
		"If interface is provided, SO_BINDTODEVICE will be set and the PTP status for this interface will be requested regularly.\n");
	return 1;
}

int main(int argc, char *argv[])
{
	char interface[IF_NAMESIZE] = { 0 };

	/* Parse command line arguments */
	if (argc == 3) {
		strncpy(interface, argv[2], IF_NAMESIZE - 1);
	} else if (argc != 2) {
		return print_usage(argv[0]);
	}

	/* Resolve hostname */
	struct hostent *he;
	if ((he = gethostbyname(argv[1])) == NULL) {
		return 1;
	}

	/* Register signal handler for SIGINT
	 * and ignore SIGPIPE to handle closed sockets properly */
	if (signal(SIGINT, sig_int) == SIG_ERR ||
	    signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "Can't set signal handler: %s\n",
			strerror(errno));
		return 1;
	}

	int i = 0;
	while (!exiting) {
		/* Setup socket */
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd == -1) {
			fprintf(stderr, "Could not create socket\n");
			return 1;
		}

		/* Set socket option to bind to interface */
		size_t interface_len = strlen(interface);
		if (interface_len > 0) {
			struct ifreq ifr;
			memcpy(ifr.ifr_name, interface, interface_len);
			ifr.ifr_name[interface_len] = '\0';
			if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
				       (void *)&ifr, sizeof(ifr)) < 0) {
				fprintf(stderr,
					"Setting SO_BINDTODEVICE failed\n");
				close(sockfd);
				return 1;
			}
		}

		/* Connect to server */
		struct sockaddr_in server;
		memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
		server.sin_family = AF_INET;
		server.sin_port = htons(80);

		if (connect(sockfd, (struct sockaddr *)&server,
			    sizeof(server)) < 0) {
			fprintf(stderr, "Connect error\n");
			return 1;
		}

		printf("Connected successfully\n");

		char request[100];
		snprintf(request, sizeof(request),
			 "HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n\r\n", he->h_name);
		char response[1000];

		while (!exiting) {
			if (write(sockfd, request, strlen(request)) < 0) {
				break;
			}

			int n = read(sockfd, response, sizeof(response));
			if (n <= 0) {
				break;
			}
			response[n] = '\0';

			/* Not interested in the output for the demo
			 * if(fputs(response, stdout) == EOF) {
			 * 	printf("fputs() error\n");
			 * }
			 */

			printf(".");
			fflush(stdout);
			sleep(1);

			/* Request and print PTP Status
			 * Will print nothing if ptp feature is not enabled
			 */
			if (interface_len > 0 && i++ % 10 == 9) {
				print_ptp_status(interface);
			}
		}

		printf("\nConnection closed\n");
	}

	return 0;
}
