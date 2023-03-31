#include "registration.h"

#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>

#define DBUS_NAME_PREFIX "org.detnet.apps."
#define MAX_TOTAL_NAME_LENGTH 100

int register_app(const char *app_name, char *interface,
		 int max_interface_length, int8_t *priority, uint64_t *token)
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

	/* register name */
	char name[MAX_TOTAL_NAME_LENGTH + 1];
	strcpy(name, DBUS_NAME_PREFIX);
	strncat(name, app_name,
		MAX_TOTAL_NAME_LENGTH - strlen(DBUS_NAME_PREFIX));

	int ret = dbus_bus_request_name(
		connection, name, DBUS_NAME_FLAG_REPLACE_EXISTING, &error);
	if (dbus_error_is_set(&error)) {
		fprintf(stderr,
			"Can not register name (%s). Is the process run under the correct user according to the D-Bus policy?\n",
			error.message);
		dbus_error_free(&error);
		return 1;
	}

	if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {
		fprintf(stderr,
			"Not the primary owner of the D-Bus name! Is the process run under the correct user according to the D-Bus policy?\n");
		return 1;
	}

	/* assemble method call */
	DBusMessage *msgQuery = dbus_message_new_method_call(
		"org.detnet.detnetctl", "/org/detnet/detnetctl",
		"org.detnet.detnetctl", "Register");

	dbus_message_append_args(msgQuery, DBUS_TYPE_STRING, &app_name,
				 DBUS_TYPE_INVALID);

	/* send message */
	fprintf(stderr, "Registering app %s\n", app_name);
	DBusMessage *msgReply = dbus_connection_send_with_reply_and_block(
		connection, msgQuery, 10000, &error);
	if (dbus_error_is_set(&error)) {
		fprintf(stderr, "Error during registration: %s\n",
			error.message);
		dbus_error_free(&error);
		return 1;
	}

	dbus_message_unref(msgQuery);

	/* get result */
	const char *interface_response = NULL;
	if (!dbus_message_get_args(msgReply, &error, DBUS_TYPE_STRING,
				   &interface_response, DBUS_TYPE_BYTE,
				   priority, DBUS_TYPE_UINT64, token,
				   DBUS_TYPE_INVALID) ||
	    dbus_error_is_set(&error)) {
		fprintf(stderr, "Error parsing DBus response: %s\n",
			error.message);
		dbus_message_unref(msgReply);
		dbus_error_free(&error);
		return 1;
	}

	strncpy(interface, interface_response, max_interface_length - 1);
	interface[max_interface_length - 1] = '\0';

	dbus_message_unref(msgReply);

	fprintf(stderr,
		"Registration successful with interface %s, priority %i and token %" PRIu64
		"\n",
		interface, *priority, *token);

	return 0;
}
