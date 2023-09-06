<!--
SPDX-FileCopyrightText: 2023 Linutronix GmbH

SPDX-License-Identifier: 0BSD
-->

# detnetctl - A TSN/DetNet Node Controller with Interference Protection

The purpose of detnetctl is to coordinate different applications requiring real-time communication (in the sense of TSN or DetNet) running on the same Linux system.
The main focus is to avoid interference between different networking applications, even if they can not be fully trusted to be cooperative.
For example, this prevents the situation that two applications send to the same TSN stream due to misconfiguration, bugs or security issues
and thus might sent their traffic in the same time slot leading to missed deadlines.

In its current status, this software should be classified as demonstrator or research prototype intended for collecting experience with the requirements.
For feedback or if you have a related productive use case, please contact [Linutronix](https://linutronix.de/).

## Features

The detnetctl software is split up into features that can be individually enabled to make it possible to try it out without the full set of dependencies.
The features are introduced one by one below, but you should be able to mix and match by adapting the respective `cargo build` commands.

- [Oneshot Dry-Run Registration (Minimal Feature Set)](#oneshot-dry-run-registration-minimal-feature-set) - using `--app-name` and `--cgroup`
- [Registration via D-Bus Interface](#registration-via-d-bus-interface) - requires `dbus` feature, preferred over oneshot
- [eBPF Dispatcher](#ebpf-dispatcher) - requires `bpf` feature, skip at runtime via `--no-dispatcher`
- [Interface setup](#interface-setup) - requires `netlink` feature, skip at runtime via `--no-interface-setup`
- [PTP Configuration and Status](#ptp-configuration-and-status) - requires `ptp` feature
- [Queue setup with detd](#queue-setup-with-detd) - requires `detd` feature, skip at runtime via `--no-queue-setup`
- [Configuration with sysrepo (YANG/NETCONF)](#configuration-via-sysrepo-yang-netconf) - requires `sysrepo` feature, alternative to `--config` with YAML file

## License

detnetctl itself (i.e. everything under the `src` directory) is published under the terms of the [GNU General Public License v3.0 or later](https://spdx.org/licenses/GPL-3.0-or-later.html). We are happy about every contribution to the main repository to improve detnetctl for everyone!

However, just interfacing with detnetctl via the D-Bus interface does not count as a derived work, so there is no need to publish your proprietary application that just uses detnetctl. In order to support that, the examples are licensed under the terms of the ["BSD Zero Clause License"](https://spdx.org/licenses/0BSD.html) and thus can be easily used as starting point for your integration. We still encourage you to share examples and use cases with us if they could be interesting for the community. However, pay attention that the examples focus on clarity so you need to extend the code to match the requirements for error handling and resilience of your application.

Please note that `detnetctl` has several dependencies with their own licenses. The `cargo-license` tool can give you an overview. Also note that `config/yang/schemas` is a Git submodule referring to the [Github YANG collection](https://github.com/YangModels/yang/) and for using its YANG models you need to conform to their respective licenses.

## Command Line Interface

```console
A TSN/DetNet Node Controller with Interference Protection

Usage: detnetctl [OPTIONS]

Options:
  -a, --app-name <APP_NAME>        Oneshot registration with the provided app name and do not spawn D-Bus service
  -g, --cgroup <CGROUP>            cgroup of the app required for oneshot registration
  -c, --config <FILE>              Use YAML configuration with the provided file. Otherwise, uses sysrepo
      --no-queue-setup <PRIORITY>  Skip queue setup and use the given priority for all streams
      --no-dispatcher              Skip installing eBPFs - no interference protection!
      --bpf-debug-output           Print eBPF debug output to kernel tracing
      --no-interface-setup         Skip setting up the link
  -p, --ptp-instance <INSTANCE>    Configure PTP for the given instance
  -h, --help                       Print help
  -V, --version                    Print version
```

## Oneshot Dry-Run Registration (Minimal Feature Set)

Only performs a one-shot dry-run reading the configuration from a YAML file.

### Build

1. Install [Rust](https://www.rust-lang.org/tools/install)
2. Start the build in the detnetctl directory
```console
cargo build --no-default-features
```

### Run

In the detnetctl directory run the following command

```console
./target/debug/detnetctl -c config/yaml/example.yml --no-queue-setup 3 --no-dispatcher --no-interface-setup --app-name app0 --cgroup /user.slice/
```

This will only read the configuration matching to `app0` from the configuration file, performs a dry run and prints out for example the following output:

```console
Request to register app0
  Fetched from configuration module: AppConfig {
    logical_interface: "enp86s0.5",
    physical_interface: "enp86s0",
    period_ns: Some(
        100000,
    ),
    offset_ns: Some(
        0,
    ),
    size_bytes: Some(
        1000,
    ),
    destination_address: Some(
        MacAddress("48:21:0b:56:db:da"),
    ),
    vid: Some(
        5,
    ),
    pcp: Some(
        3,
    ),
    addresses: Some(
        [
            (
                10.5.1.1,
                24,
            ),
        ],
    ),
}
  Interface enp86s0 down
  Result of queue setup: QueueSetupResponse {
    logical_interface: "enp86s0.5",
    priority: 3,
}
  Dispatcher installed for stream StreamIdentification {
    destination_address: Some(
        MacAddress("48:21:0b:56:db:da"),
    ),
    vlan_identifier: Some(
        5,
    ),
} with priority 3 on enp86s0
  VLAN interface enp86s0.5 properly configured
  Added 10.5.1.1/24 to enp86s0.5
  Interface enp86s0 up
  Interface enp86s0.5 up
  Finished after 131.4µs
Final result: RegisterResponse {
    logical_interface: "enp86s0.5",
}
```

## Registration via D-Bus Interface

Allows for registration of via D-Bus. This can be done by the application itself (for the interface description see [facade]) or via the `detnetctl-run` tool. For the former, the application needs to take care to put itself in an adequate cgroup (see [eBPF Dispatcher](#ebpf-dispatcher)), while the `detnetctl-run` tool requires a running systemd user session.

### Build

1. Make sure you have D-Bus and systemd running on your system
2. Make yourself familiar with the D-Bus policy in `config/dbus/detnetctl.conf` and change the policy user for the application to your username. Finally install it with
```console
sudo cp config/dbus/detnetctl.conf /etc/dbus-1/system.d/
```
3. Restart the D-Bus daemon, e.g.
```console
sudo systemctl restart dbus
```
4. Install the build dependencies for D-Bus applications, e.g.
```console
sudo apt install libdbus-1-dev libdbus-1-3 build-essential pkg-config
```
5. Build detnetctl
```console
cargo build --no-default-features --features dbus
```
6. Build the example application
```console
sudo apt install libxdp-dev
SETCAPS=1 make -C examples
```
The `SETCAPS` sets the required capabilities and for that calls `sudo setcap`, so you might get a password prompt.

### Run

Copy and adapt the configuration file according to your preference, especially the logical interface needs to be bindable from the application and should be able to reach the hostname you specify below. A minimal configuration file without VLAN and TSN settings would look like this:
```yaml
apps:
  app0:
    logical_interface: enp86s0
    physical_interface: enp86s0
```

Start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-queue-setup 2 --no-dispatcher --no-interface-setup
```

`sudo` is required here, since the D-Bus policy above only allows `root` to own `org.detnet.detnetctl`. You can adapt the policy accordingly if you like.

Then in a second terminal start the sample application with
```console
./target/debug/detnetctl-run app0 ./examples/simple/simple example.org
```

Here `app0` references the application in the configuration and everything else is the command and its arguments that will be started by `detnetctl-run`.

## Interface Setup

Up to now the transmission took place directly via the physical interface. Now, change the logical interface in the configuration to a VLAN interface (e.g. `enp86s0.5`) and set the VLAN ID (5 in this case). The VLAN interface will be automatically added by `detnetctl`.

### Configuration
Adapt the configuration to include the interface configuration, e.g.
```yaml
apps:
  app0:
    logical_interface: enp86s0.5
    physical_interface: enp86s0
    addresses: [[10.5.1.1, 24]]
    vid: 5
```

### Prepare second computer
In order to run the simple example, you also need to make sure that a webserver can be reached via this VLAN. For this, you can configure a VLAN interface on a second computer (referred to with hostname `webserver` and IP address `10.5.1.2` in the following) with e.g.

```console
webserver:~$ sudo ip link add link enp86s0 name enp86s0.5 type vlan id 5
webserver:~$ sudo ip address add 10.5.1.2/24 dev enp86s0.5
webserver:~$ sudo ip link set dev enp86s0.5 up
```

and install a webserver (like lighttpd) or just run one temporarily with

```console
webserver:~$ sudo python3 -m http.server 80
```

### Build
Again at the first computer start the build:
```console
cargo build --no-default-features --features dbus,netlink
```

### Run
Start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-queue-setup 3 --no-dispatcher
```
And in a second terminal
```console
./target/debug/detnetctl-run app0 ./examples/simple/simple 10.5.1.2
```

The sample application will now send over the VLAN. However, if you now start a second application with 
```console
./examples/simple/simple 10.5.1.2
```
it will happily connect, too. That is normal for general networking, but in DetNet/TSN context this implies that two applications generate traffic for the same DetNet flow or TSN stream respectively. Since the realtime guarantees for a DetNet flow or TSN stream are always only provided for a given amount of traffic, this can be very problematic and thus the access will be restricted in the next section.

## eBPF Dispatcher

Installs an eBPF at tc egress so that after an application has registered, only the application(s) in a certain cgroup can transmit for the given TSN stream. The respective cgroup will be provided during registration by the caller, so it is its responsibility to make sure that all applications within the given cgroup are permitted to send to the TSN stream. This usually means that the relevant application is isolated in its own cgroup (similar to isolating applications in cgroups for controlling CPU and memory utilization).

How the cgroups are managed is system-dependent. Today, this is usually the responsibility of a dedicated service like systemd ([reasons for this approach and how systemd handles it](https://www.freedesktop.org/wiki/Software/systemd/ControlGroupInterface/)), but there are other options like the (unfavored) option for [direct interfacing with the kernel cgroup interface](https://www.freedesktop.org/wiki/Software/systemd/PaxControlGroups/). For this documentation, we assume systemd is used, but `detnetctl` itself has no dependency on systemd (except for the `detnetctl-run` tool) and can be used with other means of managing cgroups.

### Configuration
To properly identify the TSN stream in the dispatcher and to set the PCP, we now also need to add the destination MAC address and the PCP to the configuration:
```yaml
apps:
  app0:
    logical_interface: enp86s0.5
    physical_interface: enp86s0
    addresses: [[10.5.1.1, 24]]
    vid: 5
    pcp: 3
    destination_address: 48:21:0b:56:db:da
```

### Build
1. Install the build dependencies for eBPF applications, i.e.
```console
sudo apt install libelf-dev clang
```
2. Build detnetctl
```console
cargo build --no-default-features --features dbus,netlink,bpf
```

### Run
Start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-queue-setup 3 --bpf-debug-output
```
Then in a second terminal start the sample application with
```console
./target/debug/detnetctl-run app0 ./examples/simple/simple 10.5.1.2
```
and start a second sample application with
```console
./examples/simple/simple 10.5.1.2
```
While the first application should happily connect, the second application should be blocked, that is it will not be able to establish a connection since all its traffic gets dropped. You can monitor the filter with 
```console
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## PTP Configuration and Status

### Build

1. Install `linuxptp`, configure and run `ptp4l` and `phc2sys`, either from your packet repository or from source as described at <https://tsn.readthedocs.io/timesync.html>.
2. Build detnetctl
```console
cargo build --no-default-features --features dbus,netlink,bpf,ptp
```

### Configuration

Adapt the configuration according to your needs. For the YAML file, the relevant section is `ptp`, for YANG (see below) it is `ieee1588-ptp:ptp`. There can be multiple PTP instances in the configuration file that will be selected by the `--ptp-instance` parameter. If it is not provided, no configuration will be applied, but the PTP status can still be requested.

```yaml
ptp:
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
    domain_number: 0
    gptp_profile: true
```

The most important setting that ensures the configuration is applied correctly is if the gPTP profile (IEEE 802.1AS) is used. If you are unsure, have a look at the `transportSpecific` field of the `ptp4l` configuration and the `--transportSpecific` argument of `phc2sys`. If it is `1`, you should set `gptp_profile` in the YAML file to `true` and in the YANG file the `sdo-id` to `256` (i.e. `0x100`). Otherwise, set it to `false` and `0`, respectively.

### Run

Then start detnetctl for YAML configuration as
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-queue-setup 3 --ptp-instance 1
```

At the start, the settings will be sent to ptp4l/phc2sys. It might take up to 1 minute until they are fully applied.

Since the PTP status depends on the interface to use, provide the VLAN (!) interface to the application like
```console
./target/debug/detnetctl-run app0 ./examples/simple/simple 10.5.1.2 enp86s0.5
```
You should see the PTP status printed every few seconds.


## Queue setup with detd

In order to actually distribute the TSN streams into different timeslots according to Enhancements for Scheduled Traffic (EST) aka IEEE 802.1Qbv, detnetctl can set up the queues / qdiscs according to the configuration to enable TSN communication using TAPRIO Qdiscs.

This requires a at least one network card supported by [detd](https://github.com/Avnu/detd) (e.g. Intel® Ethernet Controller I225-LM).

Hint: detd requires proper time synchronization between the TAI clock and the PHC (e.g. via phc2sys), otherwise it might set the basetime in the future and lead to packet drops until that.

### Configuration
In order for detd to calculate the size and position of the timeslot, the configuration needs to be extended:
```yaml
apps:
  app0:
    logical_interface: enp86s0.5
    physical_interface: enp86s0
    addresses: [[10.5.1.1, 24]]
    vid: 5
    pcp: 3
    destination_address: 48:21:0b:56:db:da 
    period_ns: 100000
    offset_ns: 0
    size_bytes: 1000
```

### Build

1. [Install and run detd](https://github.com/Avnu/detd)
2. Install build dependencies
```console
sudo apt install protobuf-compiler
```
3. Build detnetctl
```console
cargo build --no-default-features --features dbus,netlink,bpf,ptp,detd
```

### Run
```console
sudo ./target/debug/detnetctl -c myconfig.yml
```

Note that currently detd does not reset the TAPRIO configuration, so to retry you also have to restart detd if it would otherwise lead to conflicts.

For the `simple` example, there should be no noticable difference when now transmitting via the TAPRIO Qdisc. For a more complex example that tracks the timestamps have a look at the [timestamp example](timestamp_example/index.html).


## Configuration via sysrepo (YANG/NETCONF)

Instead of using a YAML file, the configuration can also be made via [sysrepo](https://www.sysrepo.org/) that uses YANG data models and can be configured via NETCONF.

### Build

1. Install [sysrepo](https://www.sysrepo.org/) and its dependencies. You might need to build from source, because most available packages are too old. It was successfully tested with the following versions:
```console
libsysrepo-dev: 2.2.36
libsysrepo7:    2.2.36
sysrepo-tools:  2.2.36

libyang2:       2.1.30.1
libyang2-dev:   2.1.30.1
libyang2-tools: 2.1.30.1

netopeer2:      2.1.49
libnetconf2-3:  2.1.28
```
2. Clone submodule to get YANG schema definitions
```console
git submodule update --init --recursive
```
3. Build detnetctl
```console
cargo build --no-default-features --features dbus,netlink,bpf,ptp,detd,sysrepo
```
or equivalent
```console
cargo build
```

### Run

Load the YANG configuration from `config/yang/example.json` after adapting it to your needs:
```console
sudo sysrepocfg --import=config/yang/example.json
```
In case of errors, load the missing schemas from `config/yang/schemas`, e.g.
```console
sudo sysrepoctl -i config/yang/schemas/standard/ietf/RFC/ietf-interfaces@2018-02-20.yang
sudo sysrepoctl -i config/yang/schemas/standard/ieee/draft/1588/ieee1588-ptp.yang
sudo sysrepoctl -i config/yang/schemas/standard/ietf/RFC/ietf-ethertypes@2019-03-04.yang
sudo sysrepoctl -i config/yang/schemas/standard/ietf/RFC/ietf-routing-types@2017-12-04.yang
sudo sysrepoctl -i config/yang/schemas/standard/ietf/RFC/ietf-packet-fields@2019-03-04.yang
sudo sysrepoctl -i config/yang/schemas/standard/ieee/published/802.1/ieee802-dot1q-types.yang
sudo sysrepoctl -i config/yang/schemas/experimental/ietf-extracted-YANG-modules/ietf-detnet@2022-10-04.yang
sudo sysrepoctl -i config/yang/schemas/standard/iana/iana-if-type@2023-01-26.yang
sudo sysrepoctl -i config/yang/schemas/experimental/ietf-extracted-YANG-modules/ietf-if-extensions@2023-01-26.yang -e sub-interfaces
sudo sysrepoctl -i config/yang/schemas/standard/ieee/published/802.1/ieee802-dot1q-tsn-types.yang
sudo sysrepoctl -i config/yang/tsn-interface-configuration.yang
```

Then start detnetctl as
```console
sudo ./target/debug/detnetctl
```
as well as the application like before.

