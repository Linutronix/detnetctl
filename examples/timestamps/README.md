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
  -a, --app  [app_name]        Register at the node controller with the provided app_name.
                               Can not be combined with --interface, because that will be
                               provided automatically during registration!
                               If not provided, no registration at the node controller takes place!
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
                               Do not explicitly bind to interface if not provided as CLI and not via detnetctl registration.
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
./examples/timestamp/client -n 30 10.0.48.10 > timestamps_low_traffic.csv
```

6. Analyze the results with

```console
./examples/timestamp/analyze.py timestamps_low_traffic.csv
```

7. Generate a lot of traffic. You can e.g. use the provided `traffic.sh` using `trafgen`, e.g.

```console
./examples/utils/traffic.sh enp1s0 1400ns
```

   You can experiment a little bit with the send interval. You can use e.g. the provided `queues.sh` to see the effect on the packet backlog:

```console
./examples/utils/queues.sh enp1s0
```

8. Repeat step 5 and 6 and compare the results. The latencies should be significantly higher.

9. Now use RT scheduling and compare the results with high traffic. Especially the *Kernel to Userspace* latency should be much shorter now.

```console
./examples/timestamps/server --realtime 10 --cpu 1   # on server side

./examples/timestamp/client -n 30 --realtime 10 --cpu 1 10.0.48.10 > timestamps_high_traffic_rt.csv  # on client side
```
    
10. Finally, use a TAPRIO Qdisc. Either setup the Qdisc manually (e.g. see <https://tsn.readthedocs.io/qdiscs.html>) or simply use on a running `detnetctl`:

```console
sudo -u app0 ./examples/timestamps/client --app app0 -n 30 --realtime 10 --cpu 1 10.0.52.10 > timestamps_high_traffic_rt_taprio.csv
```

Please bear in mind that `detnetctl` (or more specifically `detd`) will setup a VLAN and lets the `client` bind to the VLAN interface. So make sure to configure the VLAN correctly on server and client side and to use the correct IP addresses.

This should significantly reduce queueing delay on client side. The major latency left should be *NIC to kernel* and this could be optimized using XDP (not implemented for this example yet).

