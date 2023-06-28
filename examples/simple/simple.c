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

#include "../common/registration.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(__attribute__((unused)) int signo)
{
	exiting = 1;
}

int print_usage(char *name)
{
	fprintf(stderr, "In order to register via D-Bus call as\n");
	fprintf(stderr, "%s <hostname> <app_name>\n\n", name);
	fprintf(stderr, "Otherwise, call as\n");
	fprintf(stderr,
		"%s <hostname> --skip-registration <interface> <priority>\n\n",
		name);
	return 1;
}

int main(int argc, char *argv[])
{
	char interface[IF_NAMESIZE] = { 0 };
	int priority = 0;
	uint64_t token = 0;

	/* Parse command line arguments */
	if (argc != 3 && argc != 5) {
		return print_usage(argv[0]);
	}

	if (strcmp(argv[2], "--skip-registration") == 0) {
		if (argc != 5) {
			return print_usage(argv[0]);
		}

		strncpy(interface, argv[3], IF_NAMESIZE - 1);
		priority = atoi(argv[4]);
	} else {
		if (argc != 3) {
			return print_usage(argv[0]);
		}

		/* Register via D-Bus */
		int8_t reg_priority = 0;
		int result = register_app(argv[2], interface, sizeof(interface),
					  &reg_priority, &token);
		if (result != 0) {
			return result;
		}
		priority = reg_priority;
	}

	/* Resolve hostname */
	struct hostent *he;
	if ((he = gethostbyname(argv[1])) == NULL) {
		return 1;
	}

	/* Setup socket */
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		fprintf(stderr, "Could not create socket\n");
		return 1;
	}

	/* Setup socket priority */
	if (setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &priority,
		       sizeof(priority)) < 0) {
		fprintf(stderr, "Setting SO_PRIORITY failed\n");
		close(sockfd);
		return 1;
	}

	/* Set socket option to bind to interface */
	size_t interface_len = strlen(interface);
	struct ifreq ifr;
	memcpy(ifr.ifr_name, interface, interface_len);
	ifr.ifr_name[interface_len] = '\0';
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr,
		       sizeof(ifr)) < 0) {
		fprintf(stderr, "Setting SO_BINDTODEVICE failed\n");
		close(sockfd);
		return 1;
	}

	if (token != 0) {
#ifdef SO_TOKEN
		// Setup token
		if (setsockopt(sockfd, SOL_SOCKET, SO_TOKEN, &token,
			       sizeof(token)) < 0) {
			fprintf(stderr, "Setting SO_TOKEN failed\n");
			close(sockfd);
			return 1;
		}
#else
#warning "Kernel does not support, SO_TOKEN, so it will not be set!\n"
		fprintf(stderr,
			"WARNING: SO_TOKEN not available, SO_TOKEN is not set!\n");
#endif
	}

	/* Connect to server */
	struct sockaddr_in server;
	memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
	server.sin_family = AF_INET;
	server.sin_port = htons(80);

	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		fprintf(stderr, "Connect error\n");
		return 1;
	}

	printf("Connected successfully\n");

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "Can't set signal handler: %s\n",
			strerror(errno));
		return 1;
	}

	char request[100];
	snprintf(request, sizeof(request),
		 "HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n\r\n", he->h_name);
	char response[1000];

	while (!exiting) {
		if (write(sockfd, request, strlen(request)) >= 0) {
			int n = read(sockfd, response, sizeof(response));
			response[n] = '\0';

			/* Not interested in the output for the demo
			 * if(fputs(response, stdout) == EOF) {
			 * 	printf("fputs() error\n");
			 * }
			 */
		}

		printf(".");
		fflush(stdout);
		sleep(1);
	}

	printf("\n");

	return 0;
}
