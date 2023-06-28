# SPDX-FileCopyrightText: 2023 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CPPFLAGS += -MMD -MP -Wall -Wfatal-errors

all: enable_hw_timestamps

enable_hw_timestamps: enable_hw_timestamps.c
-include enable_hw_timestamps.d

