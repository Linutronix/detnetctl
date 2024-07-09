// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides sysrepo-based network configuration (for NETCONF integration)

use anyhow::{anyhow, Context, Error, Result};
use std::collections::BTreeMap;

use crate::configuration::{
    schedule::{GateControlEntry, GateControlEntryBuilder, GateOperation},
    BridgedApp, Configuration, Interface, OutgoingL2Builder, PcpEncodingTable,
    PcpEncodingTableBuilder, Schedule, ScheduleBuilder, Stream, StreamBuilder,
    StreamIdentification, UnbridgedApp,
};
use crate::ptp::{
    ClockAccuracy, ClockClass, PtpInstanceConfig, PtpInstanceConfigBuilder, TimeSource,
};
use log::debug;
use std::net::IpAddr;
use std::str::FromStr;
use yang2::data::{Data, DataNodeRef, DataTree};

mod helper;
use crate::configuration::sysrepo::helper::{FromDataValue, GetValueForXPath, SysrepoReader};

/// Reads configuration from sysrepo
pub struct SysrepoConfiguration {
    reader: SysrepoReader,
}

struct AppFlow {
    ingress_interfaces: Option<Vec<String>>,
    stream_id: Option<StreamIdentification>,
}

struct ServiceSublayer {
    outgoing_forwarding_sublayer: Option<String>,
}

struct ForwardingSublayer {
    outgoing_interface: Option<String>,
}

#[derive(Default)]
struct StreamHandling {
    tsn_handle: Option<u32>,
    outgoing_interface: Option<String>,
    priority: Option<u8>,
}

fn create_interface_config(interface: &DataNodeRef<'_>) -> Result<Interface> {
    let mut schedule = None;
    let mut pcp_encoding = None;

    if let Some(bridge_port) = interface
        .find_xpath("ieee802-dot1q-bridge:bridge-port")?
        .next()
    {
        schedule = Some(parse_schedule(&bridge_port)?);
        pcp_encoding = Some(parse_pcp_encoding(&bridge_port)?);
    }

    let addresses = get_interface_addresses(interface)?;

    Ok(Interface {
        schedule,
        taprio: None,
        pcp_encoding,
        addresses,
    })
}

impl Configuration for SysrepoConfiguration {
    fn get_interfaces(&mut self) -> Result<BTreeMap<String, Interface>> {
        let tree = self.reader.get_config("/interfaces")?;
        let interfaces = tree.find_xpath(concat!(
            "/interfaces/interface[",
            "ieee802-dot1q-bridge:bridge-port/",
            "ieee802-dot1q-sched-bridge:gate-parameter-table/",
            "admin-control-list/gate-control-entry]"
        ))?;

        interfaces
            .into_iter()
            .try_fold(BTreeMap::new(), |mut acc, interface| {
                if let Some(name) = interface.get_value_for_xpath::<String>("name")? {
                    acc.insert(name, create_interface_config(&interface)?);
                }

                Ok(acc)
            })
    }

    fn get_interface(&mut self, interface_name: &str) -> Result<Option<Interface>> {
        let tree = self.reader.get_config("/interfaces")?;
        let interfaces = tree.find_xpath("/interfaces/interface")?;

        for interface in interfaces {
            if let Some(name) = interface.get_value_for_xpath::<String>("name")? {
                if name == interface_name {
                    return Ok(Some(create_interface_config(&interface)?));
                }
            }
        }

        Ok(None)
    }

    /// Currently, the apps themselves cannot be configured via sysrepo
    fn get_unbridged_app(&mut self, _app_name: &str) -> Result<Option<UnbridgedApp>> {
        Ok(None)
    }

    /// Currently, the apps themselves cannot be configured via sysrepo
    fn get_unbridged_apps(&mut self) -> Result<BTreeMap<String, UnbridgedApp>> {
        Ok(BTreeMap::default())
    }

    /// Currently, the apps themselves cannot be configured via sysrepo
    fn get_bridged_app(&mut self, _app_name: &str) -> Result<Option<BridgedApp>> {
        Ok(None)
    }

    /// Currently, the apps themselves cannot be configured via sysrepo
    fn get_bridged_apps(&mut self) -> Result<BTreeMap<String, BridgedApp>> {
        Ok(BTreeMap::default())
    }

    /// Get and parse stream configuration from app flow
    ///
    /// According to RFC 9023 (Deterministic Networking (DetNet) Data Plane:
    /// IP over IEEE 802.1 Time-Sensitive Networking (TSN)) section 4.1,
    /// using DetNet over TSN requires the usage of a TSN stream identification
    /// according to IEEE 802.1CB after the packet has left the DetNet stack.
    /// Therefore, in the case of DetNet over TSN, the forwarding layer of the
    /// DetNet YANG model only provides an internal LAN interface (IANA type 247)
    /// that links it to the TSN stream identification where the final output
    /// interface is specified.
    ///
    /// For the moment, we neither support Mask-and-Match Stream identification,
    /// nor an active Stream identification that actually replaces L2 headers,
    /// but only use the original (Destination MAC, VLAN ID) of the application
    /// for TSN stream identification.
    fn get_stream(&mut self, stream_name: &str) -> Result<Option<Stream>> {
        let cfg = self
            .reader
            .get_config("/detnet | /interfaces | /stream-identity")?;
        get_app_flow(&cfg, stream_name)?
            .map(|app_flow| get_stream_config_from_app_flow(&cfg, stream_name, &app_flow))
            .transpose()
    }

    fn get_streams(&mut self) -> Result<BTreeMap<String, Stream>> {
        let cfg = self
            .reader
            .get_config("/detnet | /interfaces| /stream-identity")?;
        get_app_flows(&cfg)?
            .iter()
            .map(|(stream_name, app_flow)| {
                Ok((
                    String::from(stream_name),
                    get_stream_config_from_app_flow(&cfg, stream_name, app_flow)?,
                ))
            })
            .collect()
    }

    fn get_ptp_active_instance(&mut self) -> Result<Option<u32>> {
        // Not available via sysrepo. Needs to be configured by another configuration option.
        Ok(None)
    }

    fn get_ptp_config(&mut self, instance: u32) -> Result<Option<PtpInstanceConfig>> {
        let cfg = self.reader.get_config("/ptp")?;
        get_ptp_instance(&cfg, instance).context("Parsing of YANG PTP configuration failed")
    }
}

impl SysrepoConfiguration {
    /// Create a new `SysrepoConfiguration` and connect to `sysrepo`
    ///
    /// # Errors
    ///
    /// Will return `Err` if no proper connection can be set up to Sysrepo,
    /// usually because the service is not running.
    pub fn new() -> Result<Self> {
        Ok(Self {
            reader: SysrepoReader::new()?,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub fn mock_from_file(file: &str) -> Self {
        Self {
            reader: SysrepoReader::mock_from_file(file),
        }
    }
}

fn get_app_flow(tree: &DataTree, app_flow_name: &str) -> Result<Option<AppFlow>> {
    // It would be easier to put the provided flow_name inside the XPath expression,
    // but this could lead to a potential unsafe expression
    // (see https://owasp.org/www-community/attacks/XPATH_Injection - also for alternative implementations).
    let app_flows = tree.find_xpath("/detnet/app-flows/app-flow")?;
    for app_flow in app_flows {
        if let Some(name) = app_flow.get_value_for_xpath::<String>("name")? {
            if name == app_flow_name {
                return Ok(Some(parse_app_flow(&app_flow)?));
            }
        }
    }

    Ok(None)
}

fn get_app_flows(tree: &DataTree) -> Result<Vec<(String, AppFlow)>> {
    tree.find_xpath("/detnet/app-flows/app-flow")?
        .try_fold(vec![], |mut acc, app_flow| {
            match app_flow.get_value_for_xpath("name")? {
                Some(name) => {
                    acc.push((name, parse_app_flow(&app_flow)?));
                    Ok(acc)
                }
                None => Ok(acc),
            }
        })
}

fn parse_app_flow(app_flow: &DataNodeRef<'_>) -> Result<AppFlow> {
    let destination_address = app_flow
        .get_value_for_xpath::<String>("ingress/tsn-app-flow/destination-mac-address")?
        .map(|addr| addr.parse())
        .transpose()?;

    let ingress_interfaces = app_flow
        .find_xpath("ingress/interface")
        .ok()
        .map(|ifaces| -> Result<Vec<String>> {
            ifaces
                .filter_map(|iface| iface.get_value_for_xpath(".").transpose())
                .collect()
        })
        .transpose()?;

    Ok(AppFlow {
        ingress_interfaces,
        stream_id: Some(StreamIdentification {
            destination_address,
            vid: app_flow.get_value_for_xpath("ingress/tsn-app-flow/vlan-id")?,
        }),
    })
}

fn get_stream_config_from_app_flow(
    tree: &DataTree,
    stream_name: &str, /* used as name of app_flow */
    app_flow: &AppFlow,
) -> Result<Stream> {
    let service_sublayer = get_service_sublayer(tree, stream_name)?;
    let forwarding_sublayer = service_sublayer
        .and_then(|ssl| ssl.outgoing_forwarding_sublayer)
        .map(|ofsl| get_forwarding_sublayer(tree, &ofsl))
        .transpose()?
        .flatten();

    let ilan_interface = forwarding_sublayer.and_then(|fsl| fsl.outgoing_interface);
    let stream_handling = ilan_interface
        .as_ref()
        .and_then(|ilan| {
            app_flow
                .stream_id
                .as_ref()
                .map(|stream| get_stream_handling(tree, ilan, stream))
        })
        .transpose()?
        .flatten();

    Ok(StreamBuilder::new()
        .incoming_interfaces_opt(app_flow.ingress_interfaces.clone())
        .identifications(app_flow.stream_id.clone().map_or(Vec::new(), |v| vec![v]))
        .outgoing_l2(vec![OutgoingL2Builder::new()
            .outgoing_interface_opt(
                stream_handling
                    .as_ref()
                    .and_then(|s| s.outgoing_interface.clone()),
            )
            .priority_opt(stream_handling.and_then(|s| s.priority))
            .build()])
        .build())
}

fn get_service_sublayer(
    tree: &DataTree,
    incoming_app_flow: &str,
) -> Result<Option<ServiceSublayer>> {
    let service_sublayers = tree.find_xpath("/detnet/service/sub-layer")?;
    for service_sublayer in service_sublayers {
        let incoming_app_flows = service_sublayer.find_xpath("incoming/app-flow/flow")?;

        for app_flow in incoming_app_flows {
            let app_flow_name = String::try_from_data_value(
                app_flow
                    .value()
                    .ok_or_else(|| anyhow!("Missing app_flow value"))?,
            )?;

            if app_flow_name == incoming_app_flow {
                // TODO The service sublayer can in principle link to more than one outgoing
                // forwarding sublayer. It is currently unclear how to handle that properly.
                // For the moment we just reject that situation.

                let mut outgoing_forwarding_sublayers = service_sublayer
                    .find_xpath("outgoing/forwarding-sub-layer/service-outgoing/sub-layer")?;

                let outgoing_forwarding_sublayer = String::try_from_data_value(
                    outgoing_forwarding_sublayers
                        .next()
                        .and_then(|v| v.value())
                        .ok_or_else(|| {
                            anyhow!("No associated outgoing forwarding sublayer found")
                        })?,
                )?;

                if outgoing_forwarding_sublayers.next().is_some() {
                    return Err(anyhow!("Currently only exactly one outgoing forwarding sublayer per service sublayer is supported!"));
                }

                return Ok(Some(ServiceSublayer {
                    outgoing_forwarding_sublayer: Some(outgoing_forwarding_sublayer),
                }));
            }
        }
    }

    Ok(None)
}

fn get_forwarding_sublayer(
    tree: &DataTree,
    forwarding_sublayer_name: &str,
) -> Result<Option<ForwardingSublayer>> {
    let forwarding_sublayers = tree.find_xpath("/detnet/forwarding/sub-layer")?;
    for forwarding_sublayer in forwarding_sublayers {
        if let Some(name) = forwarding_sublayer.get_value_for_xpath::<String>("name")? {
            if name == forwarding_sublayer_name {
                return Ok(Some(ForwardingSublayer {
                    outgoing_interface: forwarding_sublayer
                        .get_value_for_xpath("outgoing/interface/outgoing-interface")?,
                }));
            }
        }
    }

    Ok(None)
}

fn get_ptp_instance(tree: &DataTree, instance_index: u32) -> Result<Option<PtpInstanceConfig>> {
    let instances = tree.find_xpath("/ptp/instances/instance")?;
    for instance in instances {
        if let Some(index) = instance.get_value_for_xpath::<u32>("instance-index")? {
            if index == instance_index {
                let clock_class = instance
                    .get_value_for_xpath::<String>("default-ds/clock-quality/clock-class")?
                    .map(|clock_class| ClockClass::from_str(&clock_class))
                    .transpose()?;
                let clock_accuracy = instance
                    .get_value_for_xpath::<String>("default-ds/clock-quality/clock-accuracy")?
                    .map(|clock_accuracy| ClockAccuracy::from_str(&clock_accuracy))
                    .transpose()?;
                let time_source = instance
                    .get_value_for_xpath::<String>("time-properties-ds/time-source")?
                    .map(|time_source| TimeSource::from_str(&time_source))
                    .transpose()?;

                let gptp_profile = instance
                    .get_value_for_xpath::<u16>("default-ds/sdo-id")?
                    .map(|sdo_id| match sdo_id {
                        0x000 => Ok(false),
                        0x100 => Ok(true),
                        _ => Err(anyhow!(
                            "Only sdoId 0x000 and 0x100 are supported at the moment"
                        )),
                    })
                    .transpose()?;

                return Ok(Some(
                    PtpInstanceConfigBuilder::new()
                        .clock_class_opt(clock_class)
                        .clock_accuracy_opt(clock_accuracy)
                        .offset_scaled_log_variance_opt(instance.get_value_for_xpath(
                            "default-ds/clock-quality/offset-scaled-log-variance",
                        )?)
                        .current_utc_offset_opt(
                            instance
                                .get_value_for_xpath("time-properties-ds/current-utc-offset")?,
                        )
                        .current_utc_offset_valid_opt(
                            instance.get_value_for_xpath(
                                "time-properties-ds/current-utc-offset-valid",
                            )?,
                        )
                        .leap59_opt(instance.get_value_for_xpath("time-properties-ds/leap59")?)
                        .leap61_opt(instance.get_value_for_xpath("time-properties-ds/leap61")?)
                        .time_traceable_opt(
                            instance.get_value_for_xpath("time-properties-ds/time-traceable")?,
                        )
                        .frequency_traceable_opt(
                            instance
                                .get_value_for_xpath("time-properties-ds/frequency-traceable")?,
                        )
                        .ptp_timescale_opt(
                            instance.get_value_for_xpath("time-properties-ds/ptp-timescale")?,
                        )
                        .time_source_opt(time_source)
                        .gptp_profile_opt(gptp_profile)
                        .build(),
                ));
            }
        }
    }

    Ok(None)
}

fn get_interface_addresses(interface: &DataNodeRef<'_>) -> Result<Option<Vec<(IpAddr, u8)>>> {
    Ok(interface
        .find_xpath("ipv4/address | ipv6/address")
        .ok()
        .map(|addrs| -> Result<Option<Vec<(IpAddr, u8)>>> {
            let collected = addrs
                .map(|address| -> Result<(IpAddr, u8)> {
                    let ip = address
                        .get_value_for_xpath::<String>("ip")?
                        .map(|addr| addr.parse::<IpAddr>())
                        .transpose()?
                        .ok_or_else(|| anyhow!("ip missing"))?;
                    let prefix_length: u8 = address
                        .get_value_for_xpath("prefix-length")?
                        .ok_or_else(|| anyhow!("ip missing"))?;

                    Ok((ip, prefix_length))
                })
                .collect::<Result<Vec<(IpAddr, u8)>>>()?;

            if collected.is_empty() {
                Ok(None)
            } else {
                Ok(Some(collected))
            }
        })
        .transpose()?
        .flatten())
}

fn parse_schedule(tree: &DataNodeRef<'_>) -> Result<Schedule> {
    let mut schedule = ScheduleBuilder::new();
    let tc_table = tree.find_xpath("traffic-class/traffic-class-table")?.next();

    // --- number_of_traffic_classes ---
    schedule = schedule.number_of_traffic_classes_opt(
        tc_table
            .as_ref()
            .map(|tab| tab.get_value_for_xpath("number-of-traffic-classes"))
            .transpose()?
            .flatten(),
    );

    // --- priority_map ---
    let mut priority_map = BTreeMap::<u8, u8>::default();
    if let Some(tcs) = tc_table {
        for prio in 0..8 {
            if let Some(tc) = tcs.get_value_for_xpath(&format!("priority{prio}"))? {
                priority_map.insert(prio, tc);
            }
        }
    }

    if !priority_map.is_empty() {
        schedule = schedule.priority_map(priority_map);
    }

    // --- basetime_ns and control_list ---
    if let Some(gates) = tree
        .find_xpath("ieee802-dot1q-sched-bridge:gate-parameter-table")?
        .next()
    {
        // -- basetime_ns --
        schedule = schedule.basetime_ns_opt(
            gates
                .get_value_for_xpath::<u64>("admin-base-time/seconds")?
                .map(|mut btime| {
                    btime *= 1_000_000_000;

                    Ok::<u64, Error>(
                        gates
                            .get_value_for_xpath::<u32>("admin-base-time/nanoseconds")?
                            .map_or_else(|| btime, |nanoseconds| btime + u64::from(nanoseconds)),
                    )
                })
                .transpose()?,
        );

        // -- control_list --
        schedule = schedule.control_list(
            gates
                .find_xpath("admin-control-list/gate-control-entry")?
                .map(|entry| {
                    let operation = entry
                        .get_value_for_xpath::<String>("operation-name")?
                        .map(|operation_name| {
                            operation_name
                                .split(':')
                                .last()
                                .map(|last_part| match last_part {
                                    "set-gate-states" => Ok(GateOperation::SetGates),
                                    "set-and-hold-mac" => Ok(GateOperation::SetAndHold),
                                    "set-and-release-mac" => Ok(GateOperation::SetAndRelease),
                                    _ => Err(anyhow!("Cannot parse operation-name {last_part}")),
                                })
                                .transpose()?
                                .ok_or_else(|| anyhow!("Cannot parse operation-name"))
                        })
                        .transpose()?;

                    Ok(GateControlEntryBuilder::new()
                        .operation_opt(operation)
                        .time_interval_ns_opt(entry.get_value_for_xpath("time-interval-value")?)
                        .traffic_classes_opt(
                            entry
                                .get_value_for_xpath::<u8>("gate-states-value")?
                                .map(|bitmask| {
                                    (0..8).filter(|&i| (bitmask & (1 << i)) != 0).collect()
                                }),
                        )
                        .build())
                })
                .collect::<Result<Vec<GateControlEntry>>>()?,
        );
    }

    Ok(schedule.build())
}

fn parse_pcp_encoding(tree: &DataNodeRef<'_>) -> Result<PcpEncodingTable> {
    const PCP_SELECTION: &str = "8P0D";

    let mut table = PcpEncodingTableBuilder::new();
    let pcp_selection: Option<String> = tree.get_value_for_xpath("pcp-selection")?;

    if let Some(selection) = pcp_selection {
        if selection != PCP_SELECTION {
            return Err(anyhow!(
                "Currently only {PCP_SELECTION} is supported for PCP mapping"
            ));
        }
    }

    let mappings = tree.find_xpath("pcp-encoding-table/pcp-encoding-map")?;
    for mapping in mappings {
        if let Some(selection) = mapping.get_value_for_xpath::<String>("pcp")? {
            if selection == PCP_SELECTION {
                let mut pcp_map = BTreeMap::<u8, u8>::default();
                for entry in mapping.find_xpath("priority-map")? {
                    if let Some(prio) = entry.get_value_for_xpath("priority")? {
                        if let Some(pcp) = entry.get_value_for_xpath("priority-code-point")? {
                            pcp_map.insert(prio, pcp);
                        }
                    }
                }

                if !pcp_map.is_empty() {
                    table = table.map(pcp_map);
                    break;
                }
            }
        }
    }

    Ok(table.build())
}

fn get_stream_handling(
    tree: &DataTree,
    ilan_interface: &str,
    stream: &StreamIdentification,
) -> Result<Option<StreamHandling>> {
    let mut result = StreamHandling::default();

    // First we need to find out the tsn_handle
    for stream_identity in tree.find_xpath("/stream-identity")? {
        for port in stream_identity.get_values_for_xpath::<String>("in-facing/input-port")? {
            if ilan_interface == port? {
                let potential_stream = stream_identity
                    .find_xpath("null-stream-identification")?
                    .next()
                    .map(|stream_id| -> Result<StreamIdentification> {
                        Ok(StreamIdentification {
                            destination_address: stream_id
                                .get_value_for_xpath::<String>("destination-mac")?
                                .map(|addr| addr.parse())
                                .transpose()?,
                            vid: stream_id.get_value_for_xpath("vlan")?,
                        })
                    })
                    .transpose()?;
                if Some(stream) == potential_stream.as_ref() {
                    result.tsn_handle = stream_identity.get_value_for_xpath("handle")?;
                    break;
                }
            }
        }

        if result.tsn_handle.is_some() {
            break;
        }
    }

    if result.tsn_handle.is_none() {
        // The corresponding data can also reasonably be provided via YAML, so just log as debug
        debug!("No matching tsn_handle can be found in the IEEE 802.1CB stream identification YANG configuration for interface {ilan_interface:?} and stream {stream:?}");
        return Ok(None);
    }

    // Secondly, we look for the other leg with the same handle to get
    // the outgoing interface and priority
    for stream_identity in tree.find_xpath("/stream-identity")? {
        if result.tsn_handle == stream_identity.get_value_for_xpath("handle")? {
            let mut ports =
                stream_identity.get_values_for_xpath::<String>("out-facing/output-port")?;
            result.outgoing_interface = ports.next().transpose()?;

            if ports.next().is_some() {
                return Err(anyhow!(
                    "Currently only a single out-facing/output-port is supported!"
                ));
            }

            result.priority = stream_identity
                .get_value_for_xpath("dmac-vlan-stream-identification/down/priority")?;
        }
    }

    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{Configuration, InterfaceBuilder, StreamIdentificationBuilder};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use test_log::test;

    #[test]
    fn test_get_stream_config_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let config = sysrepo_config.get_stream("stream0")?;

        let interface = String::from("enp86s0");
        let vid = 5;
        assert_eq!(
            config.unwrap(),
            StreamBuilder::new()
                .incoming_interfaces(vec![format!("{interface}.{vid}")])
                .identifications(vec![StreamIdentificationBuilder::new()
                    .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                    .vid(vid)
                    .build()])
                .outgoing_l2(vec![OutgoingL2Builder::new()
                    .outgoing_interface("enp86s0".to_owned())
                    .priority(3)
                    .build()])
                .build()
        );
        Ok(())
    }

    #[test]
    fn test_get_stream_config_happy_without_ip() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-without-ip.json",
        );
        let config = sysrepo_config.get_stream("stream0")?;

        let interface = String::from("enp86s0");
        let vid = 5;
        assert_eq!(
            config.unwrap(),
            StreamBuilder::new()
                .incoming_interfaces(vec![format!("{interface}.{vid}")])
                .identifications(vec![StreamIdentificationBuilder::new()
                    .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                    .vid(vid)
                    .build()])
                .outgoing_l2(vec![OutgoingL2Builder::new()
                    .outgoing_interface("enp86s0".to_owned())
                    .priority(3)
                    .build()])
                .build()
        );
        Ok(())
    }

    #[test]
    fn test_get_strem_config_missing() {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        assert!(sysrepo_config
            .get_stream("somemissingstream")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_get_ptp_config_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let config = sysrepo_config.get_ptp_config(1)?;

        assert_eq!(
            config.unwrap(),
            PtpInstanceConfigBuilder::new()
                .clock_class(ClockClass::Default)
                .clock_accuracy(ClockAccuracy::TimeAccurateToGreaterThan10S)
                .offset_scaled_log_variance(0xFFFF)
                .current_utc_offset(37)
                .current_utc_offset_valid(true)
                .leap59(false)
                .leap61(false)
                .time_traceable(true)
                .frequency_traceable(false)
                .ptp_timescale(true)
                .time_source(TimeSource::InternalOscillator)
                .gptp_profile(true)
                .build()
        );
        Ok(())
    }

    #[test]
    fn test_get_interface_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let interface = String::from("enp86s0");
        let config = sysrepo_config.get_interface(&interface)?;

        assert_eq!(
            config.unwrap(),
            InterfaceBuilder::new()
                .schedule(
                    ScheduleBuilder::new()
                        .number_of_traffic_classes(4)
                        .control_list(vec![
                            GateControlEntryBuilder::new()
                                .operation(GateOperation::SetGates)
                                .time_interval_ns(5000)
                                .traffic_classes(vec![0])
                                .build(),
                            GateControlEntryBuilder::new()
                                .operation(GateOperation::SetGates)
                                .time_interval_ns(5000)
                                .traffic_classes(vec![1])
                                .build(),
                        ])
                        .build()
                )
                .pcp_encoding(
                    PcpEncodingTableBuilder::new()
                        .map(BTreeMap::from([
                            (0, 1),
                            (1, 2),
                            (2, 3),
                            (3, 4),
                            (4, 5),
                            (5, 6),
                            (6, 7),
                            (7, 7)
                        ]))
                        .build()
                )
                .build()
        );

        let config_vlan = sysrepo_config.get_interface("enp86s0.5")?;
        assert_eq!(
            config_vlan.unwrap(),
            InterfaceBuilder::new()
                .addresses(vec![
                    (IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 24),
                    (
                        IpAddr::V6(Ipv6Addr::new(0xfd2a, 0xbc93, 0x8476, 0x634, 0, 0, 0, 0)),
                        64
                    )
                ])
                .build()
        );

        Ok(())
    }

    #[test]
    fn test_get_interface_happy_without_ip() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-without-ip.json",
        );
        let config = sysrepo_config.get_interface("enp86s0.5")?;

        assert_eq!(config.unwrap(), InterfaceBuilder::new().build());
        Ok(())
    }

    #[test]
    fn validate_example_yang() {
        SysrepoReader::mock_from_file("./config/yang/example.json")
            .get_config("")
            .unwrap();
    }
}
