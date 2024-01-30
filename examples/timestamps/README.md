<!--
SPDX-FileCopyrightText: 2023 Linutronix GmbH

SPDX-License-Identifier: 0BSD
-->

# Latency Demonstrator (C Example)

This demonstrator can be used to analyze the effects of different techniques, such as RT scheduling, TAPRIO Qdiscs, socket types etc. on the latencies of a UDP packet transmission.

- [Client Command Line Interface](#client-command-line-interface)
- [Server Command Line Interface](#server-command-line-interface)
- [Step for Step Example](#step-for-step-example)

## Client Command Line Interface

```console
Usage: ./client [options] server_ip

with the following options:
  -s, --socktype  [socktype]   One of
                                 INET_DGRAM           For socket(AF_INET, SOCK_DGRAM, 0)
                                 (default)            Send only application payload to kernel

                                 INET_RAW             For socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
                                                      Send application payload and UDP header to kernel

                                 INET_RAW_IP_HDRINCL  Like INET_RAW, but also set IP_HDRINCL
                                                      Send application payload, UDP and IP header to kernel

                                 PACKET_DGRAM         For socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))
                                                      Send application payload, UDP and IP header to kernel
                                                      and provide MAC address (set via --mac) in sockaddr_ll.

                                 PACKET_RAW           For socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))
                                                      Send application payload, UDP, IP and Ethernet header to kernel
                                                      MAC address needs to be provided via --mac!
  -i, --interface [interface]  Interface to bind to / to use.
  -p, --port      [port]       Source and destination port (default: 4321)
  -m, --mac       [macaddress] Destination MAC address (required for PACKET_DGRAM, PACKET_RAW and XDP, ignored for all others).
                               Format as 01:23:45:67:89:AB
  -r, --realtime  [priority]   Enable SCHED_FIFO with the given priority (if not provided, default scheduling is used)
  -c, --cpu       [cpu]        Run on provided CPU (if not provided, no CPU affinity is set up)
  -n, --number    [n]          Send n packets then exit (if not provided or n < 0, continue until SIGINT)
```

## Server Command Line Interface

```console
Usage: ./server [options]

with the following options:
  -s, --socktype  [socktype]   One of
                                 INET_DGRAM           For socket(AF_INET, SOCK_DGRAM, 0) (default)

                                 INET_RAW             For socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
                                 INET_RAW_IP_HDRINCL  Like INET_RAW, but also set IP_HDRINCL
                                                      For both INET_RAW* options, the packet is still additionally passed to the UDP layer
                                                      and generates ICMP port unreachable messages. They can be dropped with e.g.
                                                        iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

                                 PACKET_DGRAM         For socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))
                                 PACKET_RAW           For socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))
                                                      For both PACKET_* options, the packet is still additionally passed to the IP layer
                                                      and generates ICMP port unreachable messages. This can be prevented with e.g.
                                                        iptables -t raw -A PREROUTING -p udp --dport 4321 -j DROP -i eth0

  -i, --interface [interface]  Interface to bind to (default: do not explictly bind)
                               Do not explicitly bind to interface if not provided as CLI and not via detnetctl registration.
  -p, --port      [port]       Destination port (default: 4321)
  -r, --realtime  [priority]   Enable SCHED_FIFO with the given priority (if not provided, default scheduling is used)
  -c, --cpu       [cpu]        Run on provided CPU (if not provided, no CPU affinity is set up)
```

## Step for Step Example

1. Build the examples:

```console
SETCAPS=1 make -C examples
```

2. Connect two computer with NICs supporting hardware timestamping together.
3. Setup PTP (e.g. see <https://tsn.readthedocs.io/timesync.html>) to ensure the clocks are synchronized on both computers.
4. Start the server on one computer, e.g.

```console
./examples/timestamps/server
```

5. Start the client on the other computer, e.g.

```console
./examples/timestamps/client -n 30 10.0.1.2 > timestamps_low_traffic.csv
```

6. Analyze the results with

```console
./examples/timestamps/analyze.py timestamps_low_traffic.csv
```

7. Generate a lot of traffic. You can e.g. use the provided `traffic.sh` using `trafgen`, but make sure to adapt the configuration `examples/utils/traffic.cfg`, especially the MAC and IP addresses.

```console
sudo ./examples/utils/traffic.sh enp86s0 3Gbit
```

   You can experiment a little bit with the send rate. You can use e.g. the provided `queues.sh` to see the effect on the packet backlog:

```console
./examples/utils/queues.sh enp86s0
```

8. Repeat step 5 and 6 and compare the results. The latencies should be significantly higher. You might also see strange effects like negative values for the transmission times. In that case the traffic is too high to even allow for proper time synchronization.

9. In the next step we use detnetctl to both reduce the latency for our test application as well as ensure a proper time synchronization even with high parallel traffic. For that, we setup a configuration like

```yaml
version: 0.3.0
apps:
  measurement:
    logical_interface: enp86s0.5
    physical_interface: enp86s0
    period_ns: 100000
    offset_ns: 0
    size_bytes: 300
    stream:
      destination_address: 48:21:0b:56:db:da
      vid: 5
    pcp: 3
    addresses: [[10.5.1.1, 24]]
  ptp4l:
    logical_interface: enp86s0.7
    physical_interface: enp86s0
    period_ns: 100000
    offset_ns: 99040
    size_bytes: 300
    stream:
      destination_address: 01:80:c2:00:00:0e
      vid: 7
    pcp: 4
ptp:
  active_instance: 1
  instances:
    1:
      clock_class: 248
      clock_accuracy: 0x31
      offset_scaled_log_variance: 65535
      current_utc_offset: 37
      current_utc_offset_valid: true
      leap59: false
      leap61: false
      time_traceable: true
      frequency_traceable: false
      ptp_timescale: true
      time_source: 0xA0
      gptp_profile: true
```

and then apply it with

```console
sudo ./target/debug/detnetctl --oneshot myconfig.yml 
```

Configure `ptp4l` to use the respective VLAN interface, e.g.

```console
ptp4l -i enp86s0.7 -f /etc/linuxptp/gPTP.cfg --step_threshold=1
```

For this demonstration, it is not essential to install interference protection, so we can just start the application as before, but make sure to use the correct destination IP address matching the VLAN and to also setup the server side accordingly.

```console
./examples/timestamps/client -n 30 10.5.1.2 > timestamps_high_traffic_detnetctl.csv
```

This should significantly reduce in particular the queuing latencies and ensure proper operation of ptp4l. Still you will likely see further room for improvement, especially on receiver side that will be addressed in future improvements of detnetctl.

