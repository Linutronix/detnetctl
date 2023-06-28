// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#ifndef REALTIME_H
#define REALTIME_H

#include <inttypes.h>

int activate_sched_fifo(uint8_t priority);
int set_cpu_affinity(uint8_t cpu);

#endif
