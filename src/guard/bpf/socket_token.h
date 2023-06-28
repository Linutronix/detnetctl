// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SOCKET_TOKEN_H
#define SOCKET_TOKEN_H

#ifndef LIBBPF_WITH_SOTOKEN
// This assumes a kernel with bpf_get_socket_token at the given position.
// TODO This should be removed ASAP after it is available upstream
//      to prevent inconsistencies and redefinitions!
static __u64 (*bpf_get_socket_token)(void *ctx) = (void *)212;
#endif

#endif
