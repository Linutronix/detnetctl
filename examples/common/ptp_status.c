// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: 0BSD

#include "ptp_status.h"

#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#define MAX_CLOCK_DELTA_NS 50000
#define MAX_MASTER_OFFSET_NS 100

#define NUM_PORT_STATES 10
const char *PORT_STATES[NUM_PORT_STATES] = {
	"Initializing", "Faulty",  "Disabled",	   "Listening", "PreMaster",
	"Master",	"Passive", "Uncalibrated", "Slave",	"GrandMaster"
};

int print_ptp_status(const char *interface)
{
	/* setup DBus connection */
	DBusConnection *connection = NULL;
	DBusError error;
	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set(&error)) {
		fprintf(stderr, "Error connecting to DBus: %s\n",
			error.message);
		dbus_error_free(&error);
		return 1;
	}

	/* assemble method call */
	DBusMessage *msgQuery = dbus_message_new_method_call(
		"org.detnet.detnetctl1", "/org/detnet/detnetctl1",
		"org.detnet.detnetctl1", "PtpStatus");

	uint64_t max_clock_delta_ns = MAX_CLOCK_DELTA_NS;
	uint64_t max_master_offset_ns = MAX_MASTER_OFFSET_NS;
	dbus_message_append_args(msgQuery, DBUS_TYPE_STRING, &interface,
				 DBUS_TYPE_UINT64, &max_clock_delta_ns,
				 DBUS_TYPE_UINT64, &max_master_offset_ns,
				 DBUS_TYPE_INVALID);

	/* send message */
	DBusMessage *msgReply = dbus_connection_send_with_reply_and_block(
		connection, msgQuery, 10000, &error);
	if (dbus_error_is_set(&error)) {
		if (strcmp(error.name,
			   "org.freedesktop.DBus.Error.UnknownMethod") == 0) {
			/* no PTP support provided by detnetctl (i.e. feature not enabled) */
			return 2;
		}

		fprintf(stderr, "Error requesting PTP status: %s %s\n",
			error.name, error.message);
		dbus_error_free(&error);
		return 1;
	}

	dbus_message_unref(msgQuery);

	/* get result */
	uint8_t issues;
	int64_t phc_rt;
	int64_t phc_tai;
	int32_t kernel_tai_offset;
	uint8_t port_state;
	int64_t master_offset;
	if (!dbus_message_get_args(
		    msgReply, &error, DBUS_TYPE_BYTE, &issues, DBUS_TYPE_INT64,
		    &phc_rt, DBUS_TYPE_INT64, &phc_tai, DBUS_TYPE_INT32,
		    &kernel_tai_offset, DBUS_TYPE_BYTE, &port_state,
		    DBUS_TYPE_INT64, &master_offset, DBUS_TYPE_INVALID) ||
	    dbus_error_is_set(&error)) {
		fprintf(stderr, "Error parsing DBus response: %s\n",
			error.message);
		dbus_message_unref(msgReply);
		dbus_error_free(&error);
		return 1;
	}

	dbus_message_unref(msgReply);

	printf("\nPTP STATUS: %s\n", issues ? "NOT OK" : "OK");
	printf("  PHC RT DELTA: %" PRIi64 " ns (%s)\n", phc_rt,
	       issues & 1 ? "NOT OK" : "OK");
	printf("  PHC TAI DELTA: %" PRIi64 " ns (%s)\n", phc_tai,
	       issues & 2 ? "NOT OK" : "OK");
	printf("  KERNEL TAI OFFSET: %" PRIi32 " s (%s)\n", kernel_tai_offset,
	       issues & 4 ? "NOT OK" : "OK");
	if (port_state - 1 < NUM_PORT_STATES) {
		printf("  PORT STATE: %s (%s)\n", PORT_STATES[port_state - 1],
		       issues & 8 ? "NOT OK" : "OK");
	} else {
		printf("  PORT STATE: INVALID (NOT OK)\n");
	}
	printf("  MASTER OFFSET: %" PRIi64 " ns (%s)\n", master_offset,
	       issues & 16 ? "NOT OK" : "OK");

	return 0;
}
