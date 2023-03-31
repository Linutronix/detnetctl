# detnetctl - A TSN/DetNet Node Controller with Interference Protection

The purpose of detnetctl is to coordinate different applications requiring real-time communication (in the sense of TSN or DetNet) running on the same Linux system.
The main focus is to avoid interference between different networking applications, even if they can not be fully trusted to be cooperative.
For example, this prevents the situation that two applications send with the same `SO_PRIORITY` due to misconfiguration, bugs or security issues
and thus might sent their traffic in the same time slot leading to missed deadlines.

In its current status, this software should be classified as demonstrator or research prototype intended for collecting experience with the requirements.
For feedback or if you have a related productive use case, please contact [Linutronix](https://linutronix.de/).

## Features

The detnetctl software is split up into features that can be individually enabled to make it possible to try it out without the full set of dependencies.
The features are introduced one by one below, but you should be able to mix and match by adapting the respective `cargo build` commands.

- [Oneshot Dry-Run Registration (Minimal Feature Set)](#oneshot-dry-run-registration-minimal-feature-set) - using `--app-name`
- [Registration via D-Bus Interface](#registration-via-d-bus-interface) - requires `dbus` feature, preferred over oneshot
- [eBPF Guards](#ebpf-guards) - requires `bpf` feature, skip at runtime via `--no-guard`
- [NIC setup with detd](#nic-setup-with-detd) - requires `detd` feature, skip at runtime via `--no-nic-setup`
- [Configuration with sysrepo (YANG/NETCONF)](#configuration-via-sysrepo-yang-netconf) - requires `sysrepo` feature, alternative to `--config` with YAML file

## Command Line Interface

```console
A TSN/DetNet Node Controller with Interference Protection

Usage: detnetctl [OPTIONS]

Options:
  -a, --app-name <APP_NAME>      Oneshot registration with the provided app name and do not spawn D-Bus service
  -c, --config <FILE>            Use YAML configuration with the provided file. Otherwise, uses sysrepo.
      --no-nic-setup <PRIORITY>  Skip NIC setup and return the given PRIORITY
      --no-guard                 Skip installing eBPFs - no interference protection!
  -h, --help                     Print help
  -V, --version                  Print version
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
./target/debug/detnetctl -c config/yaml/example.yml --no-nic-setup 3 --no-guard --app-name app0
```

This will only read the configuration matching to `app0` from the configuration file, performs a dry run and prints out for example the following output:

```console
Request to register app0
Fetched from configuration module: EthernetConfig {
    logical_interface: "enp1s0.3",
    physical_interface: "enp1s0",
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
        MacAddress("cb:cb:cb:cb:cb:cb"),
    ),
    vid: Some(
        3,
    ),
    pcp: Some(
        3,
    ),
}
Result of NIC Setup: SocketConfig {
    logical_interface: "enp1s0.3",
    priority: 3,
}
Final result: RegisterResponse {
    logical_interface: "enp1s0.3",
    priority: 3,
    token: 11251116261202197512,
}
```

## Registration via D-Bus Interface

Allows for applications to register themselves via D-Bus.

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
SETCAPS=1 make -C examples
```
The `SETCAPS` sets the required capabilities and for that calls `sudo setcap`, so you might get a password prompt.

### Run

Copy and adapt the configuration file according to your preference, especially the logical interface needs to be bindable from the application and should be able to reach the hostname you specify below. A minimal configuration file without VLAN and TSN settings would look like this:
```yaml
app0:
  logical_interface: eth0
  physical_interface: eth0
```

Start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-nic-setup 2 --no-guard
```

`sudo` is required here, since the D-Bus policy above only allows `root` to own `org.detnet.detnetctl`. You can adapt the policy accordingly if you like.

Then in a second terminal start the sample application with
```console
sudo -u app0 ./examples/simple/simple example.org app0
```

## eBPF Guards

Install an eBPF at tc egress that after an application has registered, only that application (in possession of a dedicated token) can transmit for the given priority.

This requires the support of the SO_TOKEN socket option. You can skip this feature if you do not have a matching kernel available.

### Build
```console
cargo build --no-default-features --features dbus,bpf
```

If you have a libbpf version available that was synced with a kernel with SO_TOKEN patch, add the feature `libbpf_with_sotoken`.

### Run
Start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml --no-nic-setup 3
```
Then in a second terminal start the sample application with
```console
sudo -u app0 ./examples/simple/simple example.org app0
```
and start a second sample application with
```console
sudo -u app0 ./examples/simple/simple example.org --skip-registration eth0 3
```
Consider to replace `eth0` with your interface. The priority 3 given here matches the 3 provided to `--no-nic-setup`.
While the first application should happily connect, the second application should be blocked, that is it will not be able to establish a connection since all its traffic gets dropped. You can monitor the filter with 
```console
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## NIC setup with detd

Set up the network interface card (NIC) according to the configuration to enable TSN communication using TAPRIO Qdiscs aka Enhancements for Scheduled Traffic (EST) aka IEEE 802.1Qbv.

This requires a at least one network card supported by [detd](https://github.com/Avnu/detd) (e.g. Intel® Ethernet Controller I225-LM).

### Build

1. [Install and run detd](https://github.com/Avnu/detd)
2. Build detnetctl
```console
cargo build --no-default-features --features dbus,bpf,detd
```

### Run
Adapt the configuration (see `config/yaml/example.yml`) to include the required parameters and start the service with
```console
sudo ./target/debug/detnetctl -c myconfig.yml
```
Then start the applications as before.

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
cargo build --no-default-features --features dbus,bpf,detd,sysrepo
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
as well as the applications like before.

