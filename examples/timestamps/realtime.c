// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#define _GNU_SOURCE /*for CPU_SET*/

#include "realtime.h"

#include <sched.h>
#include <pthread.h>
#include <stdio.h>

int activate_sched_fifo(uint8_t priority)
{
	pthread_t thread = pthread_self();
	struct sched_param params;
	int policy;
	if (pthread_getschedparam(thread, &policy, &params)) {
		fprintf(stderr, "Failed to get scheduler parameters\n");
		return -1;
	}

	params.sched_priority = priority;

	if (pthread_setschedparam(thread, SCHED_FIFO, &params)) {
		fprintf(stderr, "Failed to set scheduler parameters\n");
		return -1;
	}

	return 0;
}

int set_cpu_affinity(uint8_t cpu)
{
	pthread_t thread = pthread_self();
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
		fprintf(stderr, "Failed to set CPU affinity\n");
		return -1;
	}

	return 0;
}
