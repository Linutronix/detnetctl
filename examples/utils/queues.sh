#!/bin/bash

# SPDX-FileCopyrightText: 2023 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

# Watch the status of the qdiscs (queue lengths etc.)
# Run as root (or adequate priviliges to run tc)

if ! command -v watch &> /dev/null
then
	echo "watch could not be found! Please install!"
	exit 1
fi

if ! command -v tc &> /dev/null
then
	echo "tc could not be found! Is tc installed and is the script run as root?"
	exit 1
fi

if [ -z $1 ]; then
	echo "Provide network interface as parameter!"
	exit 1
fi
INTERFACE=$1

watch -n1 tc -s -d qdisc ls dev $INTERFACE
