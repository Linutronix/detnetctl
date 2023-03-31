# detnetctl - A TSN/DetNet Node Controller with Interference Protection

The purpose of detnetctl is to coordinate different applications requiring real-time communication (in the sense of TSN or DetNet) running on the same Linux system.
The main focus is to avoid interference between different networking applications, even if they can not be fully trusted to be cooperative.
For example, this prevents the situation that two applications send with the same `SO_PRIORITY` due to misconfiguration, bugs or security issues
and thus might sent their traffic in the same time slot leading to missed deadlines.

In its current status, this software should be classified as demonstrator or research prototype intended for collecting experience with the requirements.
For feedback or if you have a related productive use case, please contact [Linutronix](https://linutronix.de/).

## Command Line Interface

```console
A TSN/DetNet Node Controller with Interference Protection

Usage: detnetctl [OPTIONS]

Options:
  -a, --app-name <APP_NAME>      Oneshot registration with the provided app name
  -c, --config <FILE>            Use YAML configuration with the provided file
      --no-nic-setup <PRIORITY>  Skip NIC setup and return the given PRIORITY
      --no-guard                 Skip installing eBPFs - no interference protection!
  -h, --help                     Print help
  -V, --version                  Print version
```

## Oneshot Dry-Run Registration

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

