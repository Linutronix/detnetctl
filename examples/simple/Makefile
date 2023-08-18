# SPDX-FileCopyrightText: 2023 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CPPFLAGS += -MMD -MP -Wall -Wextra -Wfatal-errors

all: simple

simple: simple.o ../common/registration.o ../common/ptp_status.o
simple: LDLIBS += `pkg-config --libs dbus-1` -lpthread
../common/registration.o: CPPFLAGS += `pkg-config --cflags dbus-1`
../common/ptp_status.o: CPPFLAGS += `pkg-config --cflags dbus-1`
-include simple.d
-include ../common/registration.d
-include ../common/ptp_status.d

