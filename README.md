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

- [Oneshot Dry-Run Registration (Minimal Feature Set)](#oneshot-dry-run-registration-minimal-feature-set) - using `--app-name`
- [Registration via D-Bus Interface](#registration-via-d-bus-interface) - requires `dbus` feature, preferred over oneshot
- [eBPF Dispatcher](#ebpf-dispatcher) - requires `bpf` feature, skip at runtime via `--no-dispatcher`
- [Interface setup](#interface-setup) - requires `netlink` feature, skip at runtime via `--no-interface-setup`
- [Queue setup with detd](#queue-setup-with-detd) - requires `detd` feature, skip at runtime via `--no-queue-setup`
- [Configuration with sysrepo (YANG/NETCONF)](#configuration-via-sysrepo-yang-netconf) - requires `sysrepo` feature, alternative to `--config` with YAML file
- [PTP Configuration and Status](#ptp-configuration-and-status) - requires `ptp` feature

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
./target/debug/detnetctl -c config/yaml/example.yml --no-queue-setup 3 --no-dispatcher --no-interface-setup --app-name app0
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
    destination_address: MacAddress("48:21:0b:56:db:da"),
    vlan_identifier: 5,
} with priority 3 on enp86s0
  VLAN interface enp86s0.5 properly configured
  Added 10.5.1.1/24 to enp86s0.5
  Interface enp86s0 up
  Interface enp86s0.5 up
  Finished after 137.8µs
Final result: RegisterResponse {
    logical_interface: "enp86s0.5",
    token: 4366212982257606631,
}
```

## Registration via D-Bus Interface

Allows for applications to register themselves via D-Bus. For the interface description see [facade].

### Build

1. Make sure you have D-Bus running on your system
2. Create a user that should later run the application, e.g.
```console
sudo adduser app0
```
2. Make yourself familiar with the D-Bus policy in `config/dbus/detnetctl.conf` and install it
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
    logical_interface: eth0
    physical_interface: eth0
```

Start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-queue-setup 2 --no-dispatcher
```

`sudo` is required here, since the D-Bus policy above only allows `root` to own `org.detnet.detnetctl`. You can adapt the policy accordingly if you like.

Then in a second terminal start the sample application with
```console
sudo -u app0 ./examples/simple/simple example.org app0
```

## Interface Setup

Up to now the transmission took place directly via the physical interface. Now, change the logical interface in the configuration to a VLAN interface (e.g. `eth0.5`) and set the VLAN ID (5 in this case). The VLAN interface will be automatically added by `detnetctl`.

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
Adapt the configuration (see `config/yaml/example.yml`) to include the required parameters and start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-queue-setup 3
```
And in a second terminal
```console
sudo -u app0 ./examples/simple/simple webserver app0
```



## eBPF Dispatcher

Install an eBPF at tc egress that after an application has registered, only that application (in possession of a dedicated token) can transmit for the given TSN stream.

This requires the support of the SO_TOKEN socket option. You can skip this feature if you do not have a matching kernel available.

### Build
1. Install the build dependencies for eBPF applications, i.e.
```console
sudo apt install libelf-dev clang
```
2. Build detnetctl
```console
cargo build --no-default-features --features dbus,netlink,bpf
```

If you have a libbpf version available that was synced with a kernel with SO_TOKEN patch, add the feature `libbpf_with_sotoken`.

### Run
Start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-queue-setup 3
```
Then in a second terminal start the sample application with
```console
sudo -u app0 ./examples/simple/simple webserver app0
```
and start a second sample application with
```console
sudo -u app0 ./examples/simple/simple webserver --skip-registration eth0.5
```
While the first application should happily connect, the second application should be blocked, that is it will not be able to establish a connection since all its traffic gets dropped. You can monitor the filter with 
```console
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Queue setup with detd

Set up the queues / qdiscs according to the configuration to enable TSN communication using TAPRIO Qdiscs aka Enhancements for Scheduled Traffic (EST) aka IEEE 802.1Qbv.

This requires a at least one network card supported by [detd](https://github.com/Avnu/detd) (e.g. Intel® Ethernet Controller I225-LM).

### Build

1. [Install and run detd](https://github.com/Avnu/detd)
2. Install build dependencies
```console
sudo apt install protobuf-compiler
```
3. Build detnetctl
```console
cargo build --no-default-features --features dbus,netlink,bpf,detd
```

### Run
```console
sudo ./target/debug/detnetctl -c myconfig.yml
```

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
cargo build --no-default-features --features dbus,netlink,bpf,detd,sysrepo
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
as well as the applications like before.

## PTP Configuration and Status

### Build

1. Install `linuxptp`, configure and run `ptp4l` and `phc2sys`, either from your packet repository or from source as described at <https://tsn.readthedocs.io/timesync.html>.
2. Build detnetctl
```console
cargo build --no-default-features --features dbus,netlink,bpf,detd,sysrepo,ptp
```
or equivalent
```console
cargo build
```

### Run

Adapt the configuration according to your needs. For the YAML file, the relevant section is `ptp`, for YANG it is `ieee1588-ptp:ptp`. There can be multiple PTP instances in the configuration file that will be selected by the `--ptp-instance` parameter. If it is not provided, no configuration will be applied, but the PTP status can still be requested.

The most important setting that ensures the configuration is applied correctly is if the gPTP profile (IEEE 802.1AS) is used. If you are unsure, have a look at the `transportSpecific` field of the `ptp4l` configuration and the `--transportSpecific` argument of `phc2sys`. If it is `1`, you should set `gptp_profile` in the YAML file to `true` and in the YANG file the `sdo-id` to `256` (i.e. `0x100`). Otherwise, set it to `false` and `0`, respectively.

Then start detnetctl for YAML configuration as
```console
sudo ./target/debug/detnetctl -c myconfig.yml --ptp-instance 1
```
or (after reloading the YANG file with `sysrepocfg`) for using the Sysrepo configuration
```console
sudo ./target/debug/detnetctl --ptp-instance 1
```

At the start, the settings will be sent to ptp4l/phc2sys. It might take up to 1 minute until they are fully applied.

Now start the `simple` example as before. You should see the PTP status printed every few seconds.

