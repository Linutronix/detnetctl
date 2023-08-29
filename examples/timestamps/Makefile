# SPDX-FileCopyrightText: 2023 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CPPFLAGS += -MMD -MP -Wall -Wextra -Wfatal-errors

ifdef SETCAPS
all: server client setcaps
else
all: server client
endif

-include communication.d
-include realtime.d

server: server.o communication.o realtime.o
server: -lpthread
-include server.d

client: client.o client_loop.o communication.o realtime.o
client: LDLIBS += `pkg-config --libs dbus-1` -lpthread
-include client.d
-include client_loop.d

setcaps:
	# cap_net_raw required for RAW and PACKET support
	# cap_sys_nice required for RT scheduling
	sudo setcap cap_net_raw,cap_sys_nice+ep ./client
	sudo setcap cap_net_raw,cap_sys_nice+ep ./server
