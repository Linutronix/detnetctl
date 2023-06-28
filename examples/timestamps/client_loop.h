// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#ifndef CLIENT_LOOP_H
#define CLIENT_LOOP_H

#include "communication.h"
#include <net/ethernet.h>

int client_loop(int sockfd, const struct Addresses *src_addr,
		const struct Addresses *dest_addr, int32_t max_packets,
		enum SockTypes sock_type);

#endif
