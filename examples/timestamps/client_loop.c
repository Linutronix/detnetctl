// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#include "client_loop.h"
#include "communication.h"

#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <linux/errqueue.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>

#define TX_TIMESTAMP_REQUEST_SLOWDOWN_USEC 500 * 1000
#define SEND_INTERVAL_USEC 100 * 1000
#define FNTIME "%" PRIu64 ".%.9" PRIu32
#define FLTIME "%lld.%.9ld"

static volatile sig_atomic_t exiting = 0;

static void sig_int(__attribute__((unused)) int signo)
{
	exiting = 1;
}

int process_local_timestamps(int sockfd, int *expected_tskey,
			     struct timespec *ts_sched,
			     struct timespec *ts_snd_sw,
			     struct timespec *ts_snd_hw,
			     enum SockTypes sock_type)
{
	memset(ts_sched, 0, sizeof(struct timespec));
	memset(ts_snd_sw, 0, sizeof(struct timespec));
	memset(ts_snd_hw, 0, sizeof(struct timespec));

	int i = 0;
	do {
		// Abort loop after too many iterations
		if (i++ > 50) {
			fprintf(stderr,
				"Transmission with full timestamp recording not successful.\n");
			fprintf(stderr,
				"Please make sure hardware timestamps are enabled (e.g. see \"enable_hw_timestamps\" in examples/utils).\n");
			return -1;
		}

		// Receive timestamps from ERRQUEUE
		struct timespec ts_sw = {};
		struct timespec ts_hw = {};
		int tstype, tskey;
		struct Addresses addr_buffer;
		struct RequestMessage errqueue_request;
		int n = receive_timestamped_message(
			sockfd, (uint8_t *)&errqueue_request,
			sizeof(struct RequestMessage), MSG_ERRQUEUE, &ts_sw,
			&ts_hw, NULL, &tstype, &tskey, &addr_buffer, sock_type);
		if (n < 0) {
			if (errno != EAGAIN) {
				return n;
			}

			usleep(TX_TIMESTAMP_REQUEST_SLOWDOWN_USEC);
			continue;
		}

		// Check for the correct SOF_TIMESTAMPING_OPT_ID
		if (*expected_tskey > tskey) {
			fprintf(stderr,
				"Flushing error queue. tskey %i expected %i\n",
				tskey, *expected_tskey);
			continue;
		}

		if (*expected_tskey < tskey) {
			fprintf(stderr, "tskey %i != expected %i\n", tskey,
				*expected_tskey);
			*expected_tskey = tskey + 1;
			return -1;
		}

		// Process timestamps according to type
		if (tstype == SCM_TSTAMP_SCHED && ts_sw.tv_sec > 0) {
			ts_sched->tv_sec = ts_sw.tv_sec;
			ts_sched->tv_nsec = ts_sw.tv_nsec;
		} else if (tstype == SCM_TSTAMP_SND) {
			if (ts_hw.tv_sec > 0) {
				ts_snd_hw->tv_sec = ts_hw.tv_sec;
				ts_snd_hw->tv_nsec = ts_hw.tv_nsec;
			} else if (ts_sw.tv_sec > 0) {
				ts_snd_sw->tv_sec = ts_sw.tv_sec;
				ts_snd_sw->tv_nsec = ts_sw.tv_nsec;
			}
		}
	} while (ts_sched->tv_sec == 0 || ts_snd_sw->tv_sec == 0 ||
		 ts_snd_hw->tv_sec ==
			 0); // repeat until all timestamps are found

	return 0;
}

int process_remote_timestamps(int sockfd, uint32_t expected_seq,
			      struct ResponseMessage *msg,
			      enum SockTypes sock_type)
{
	int i = 0;
	do {
		// Abort loop after too many iterations
		if (i++ > 50) {
			fprintf(stderr,
				"Can not receive response from server. Please make sure it is running!\n");
			return -1;
		}

		// Receive message from server
		int n = receive_message(sockfd, (uint8_t *)msg,
					sizeof(struct ResponseMessage),
					sock_type);
		if (n <= 0 || msg->payload.type != TIME_TYPE) {
			continue;
		}

		// Check if sequence number matches
		if (msg->payload.seq < expected_seq) {
			fprintf(stderr,
				"Flushing RX queue. seq %i expected %i\n",
				msg->payload.seq, expected_seq);
			continue;
		}

		if (msg->payload.seq > expected_seq) {
			fprintf(stderr, "seq %i != expected %i\n",
				msg->payload.seq, expected_seq);
			return -1;
		}

		break; // we have a proper message now
	} while (1);

	return 0;
}

int client_loop(int sockfd, const struct Addresses *src_addr,
		const struct Addresses *dest_addr, int32_t max_packets,
		enum SockTypes sock_type)
{
	// Setup message handler to permit Strg+C
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "Can't set signal handler: %s\n",
			strerror(errno));
		return 1;
	}

	// Print header for CSV output
	printf("seq,txUser,txSched,txSw,txHw,rxHw,rxSw,rxUser\n");

	struct RequestMessage request;
	request.payload.type = HI_TYPE;
	int expected_tskey = -1;
	int i = 0;
	while (!exiting && (max_packets < 0 || i < max_packets)) {
		usleep(SEND_INTERVAL_USEC);
		request.payload.seq = i++;
		expected_tskey++;

		if (prepare_headers(src_addr, dest_addr, &request.hdr,
				    sizeof(request.payload), sock_type) != 0) {
			continue;
		}

		// Get timestamp before sending message to kernel
		struct timespec ts_user, ts_sched, ts_snd, ts_hw;
		clock_gettime(CLOCK_REALTIME, &ts_user);

		// Send message to kernel to deliver to destination
		if (send_message(sockfd, dest_addr, (uint8_t *)&request,
				 sizeof(struct RequestMessage),
				 sock_type) < 0) {
			fprintf(stderr, "Can not send message. %s",
				strerror(errno));
			if (errno == ENOBUFS) {
				fprintf(stderr,
					" Packet was dropped and not queued!");
			}
			fprintf(stderr, "\n");
			continue;
		}

		// Request TX timestamps from local ERRQUEUE
		if (process_local_timestamps(sockfd, &expected_tskey, &ts_sched,
					     &ts_snd, &ts_hw, sock_type) != 0) {
			continue;
		}

		// Receive RX timestamps from server
		struct ResponseMessage time_msg;
		if (process_remote_timestamps(sockfd, request.payload.seq,
					      &time_msg, sock_type) != 0) {
			continue;
		}

		// Print timestamps for CSV output
		printf("%" PRIu32 "," FLTIME "," FLTIME "," FLTIME "," FLTIME
		       "," FNTIME "," FNTIME "," FNTIME "\n",
		       time_msg.payload.seq, (long long)ts_user.tv_sec,
		       ts_user.tv_nsec, (long long)ts_sched.tv_sec,
		       ts_sched.tv_nsec, (long long)ts_snd.tv_sec,
		       ts_snd.tv_nsec, (long long)ts_hw.tv_sec, ts_hw.tv_nsec,
		       time_msg.payload.hw.seconds,
		       time_msg.payload.hw.nanoseconds,
		       time_msg.payload.sw.seconds,
		       time_msg.payload.sw.nanoseconds,
		       time_msg.payload.user.seconds,
		       time_msg.payload.user.nanoseconds);

		fflush(stdout);
	}

	printf("\n");

	return 0;
}
