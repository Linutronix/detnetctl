// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: 0BSD

#ifndef REGISTRATION_H
#define REGISTRATION_H

#include <inttypes.h>

int register_app(const char *app_name, char *interface,
		 int max_interface_length, int8_t *priority, uint64_t *token);

#endif
