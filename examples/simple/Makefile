# SPDX-FileCopyrightText: 2023 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CPPFLAGS += -MMD -MP -Wall -Wextra -Wfatal-errors

ifdef SETCAPS
all: simple setcaps
else
all: simple
endif

simple: simple.o ../common/registration.o
simple: LDLIBS += `pkg-config --libs dbus-1` -lpthread
../common/registration.o: CPPFLAGS += `pkg-config --cflags dbus-1`
-include simple.d
-include ../common/registration.d

setcaps:
	# cap_net_raw required for setting SO_PRIORITY outside [0,6]
	# Currently, only cap_net_admin is documented for this, but it was introduced with
	# However, this ability was introduced with 
	#
	#    commit a1b519b745489a54189e05ee934ada1b6bc595a3
	#    Author: Maciej Żenczykowski <maze@google.com>
	#    Date:   Tue Nov 23 12:37:02 2021 -0800
	#
	#    net: allow CAP_NET_RAW to setsockopt SO_PRIORITY
	#
	# TODO upstream man page change
	#
	# We also might think about if we should use priorities within [0,6]
	# (requires detd change), since we anyway filter the traffic.
	#
	# Also we should take into consideration not setting the
	# SO_PRIORITY by the user-space application itself, and rather
	# use an approach like using network priority cgroups
	# https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/net_prio.html
	# Maybe this lets us skip the whole filtering altogether...
	sudo setcap cap_net_raw+ep ./simple

