#!/bin/bash

# SPDX-FileCopyrightText: 2023 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

# Generate traffic to fill up the network queue
# Run as root (or adequate priviliges to run trafgen)

if ! command -v trafgen &> /dev/null
then
	echo "trafgen could not be found! Is trafgen installed and is the script run as root?"
	exit 1
fi

if [ -z $1 ]; then
	echo "Provide network interface as first parameter!"
	exit 1
fi
INTERFACE=$1

if [ -z $2 ]; then
	echo "Provide send interval as second parameter (e.g. 1000ns)!"
	exit 1
fi
SEND_INTERVAL=$2
SCRIPT_DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}" )" )" >/dev/null 2>&1 && pwd )"

trafgen -i ${SCRIPT_DIR}/traffic.cfg -o $INTERFACE --cpp -n0 -q -t$SEND_INTERVAL

