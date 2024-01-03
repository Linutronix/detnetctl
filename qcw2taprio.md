<!--
SPDX-FileCopyrightText: 2023 Linutronix GmbH
SPDX-License-Identifier: 0BSD
-->

# qcw2taprio - Sets up TAPRIO qdiscs from current sysrepo state

## Command Line Interface

```console
Sets up TAPRIO qdiscs from current sysrepo state

Usage: qcw2taprio [OPTIONS] [QUEUES]...

Arguments:
  [QUEUES]...  Maps traffic classes to queues
               Format: count1@offset1 count2@offset2 ...
               The default performs a one-to-one mapping of traffic classes and queues (1@0 1@1 ... 1@<num_tc-1>)

Options:
  -m, --mode <MODE>                  Offload mode [default: FULL_OFFLOAD] [possible values: SOFTWARE, TX_TIME_ASSIST, FULL_OFFLOAD]
  -i, --interface <INTERFACE>        Interface (if not provided, use all that have a schedule in the sysrepo)
  -c, --clock-id <CLOCK_ID>          Set Clock ID. Not allowed for FULL_OFFLOAD mode, mandatory for the other modes [possible values: TAI, REALTIME, MONOTONIC, BOOTTIME]
  -d, --txtime-delay <TXTIME_DELAY>  TX time delay for TX_TIME_ASSIST mode
  -t, --tc-fallback <TC_FALLBACK>    For priorities not provided in the priority to tc map, use this tc [default: 0]
  -h, --help                         Print help (see more with '--help')
  -V, --version                      Print version
```

## Getting started

Build with
```console
cargo build
```

Load all relevant YANG models into sysrepo with
```console
sudo sysrepoctl -i config/yang/schemas/standard/ietf/RFC/ietf-interfaces@2018-02-20.yang
sudo sysrepoctl -i config/yang/schemas/standard/ieee/draft/802.1/Qcw/ieee802-types.yang
sudo sysrepoctl -i config/yang/schemas/standard/ieee/draft/802.1/Qcw/ieee802-dot1q-types.yang 
sudo sysrepoctl -i config/yang/schemas/standard/ieee/draft/802.1/Qcw/ieee802-dot1q-bridge.yang 
sudo sysrepoctl -i config/yang/schemas/standard/ieee/draft/802.1/Qcw/ieee802-dot1q-sched.yang 
sudo sysrepoctl -i config/yang/schemas/standard/ieee/draft/802.1/Qcw/ieee802-dot1q-sched-bridge.yang 
```

Load configuration (see below) into sysrepo with
```console
sudo sysrepocfg -Iconfig/yang/qcw.json
```

Start `qcw2taprio` with
```console
sudo ./target/debug/qcw2taprio
```

Inspect the results with
```console
tc qdisc show
```

## Example configuration

```json
{
  "ietf-interfaces:interfaces": {
    "interface": [
      {
        "name": "enp86s0",
        "type": "iana-if-type:ethernetCsmacd",
        "ieee802-dot1q-bridge:bridge-port": {
          "traffic-class": {
            "traffic-class-table": {
              "number-of-traffic-classes": 3,
              "priority0": 2,
              "priority1": 2,
              "priority2": 1,
              "priority3": 0,
              "priority4": 2,
              "priority5": 2,
              "priority6": 2,
              "priority7": 2
            }
          },
          "ieee802-dot1q-sched-bridge:gate-parameter-table": {
            "gate-enabled": true,
            "config-change": true,
            "supported-list-max": 3,
            "supported-interval-max": 1000000,
            "supported-cycle-max": {
              "numerator": 1,
              "denominator": 1
            },
            "admin-cycle-time": {
              "numerator": 1,
              "denominator": 1000
            },
            "admin-base-time": {
              "seconds": "1",
              "nanoseconds": 0
            },
            "admin-control-list": {
              "gate-control-entry": [
                {
                  "index": 0,
                  "operation-name": "ieee802-dot1q-sched:set-gate-states",
                  "time-interval-value": 300000,
                  "gate-states-value": 1
                },
                {
                  "index": 1,
                  "operation-name": "ieee802-dot1q-sched:set-gate-states",
                  "time-interval-value": 300000,
                  "gate-states-value": 3
                },
                {
                  "index": 2,
                  "operation-name": "ieee802-dot1q-sched:set-gate-states",
                  "time-interval-value": 400000,
                  "gate-states-value": 4
                }
              ]
	    }
          }
        }
      }
    ]
  }
}
```
