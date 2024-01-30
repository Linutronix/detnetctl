// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides sysrepo-based network configuration (for NETCONF integration)

use anyhow::{anyhow, Context, Error, Result};
use std::collections::HashMap;

use crate::configuration::{
    schedule::{GateControlEntry, GateControlEntryBuilder, GateOperation},
    AppConfig, Configuration, Schedule, ScheduleBuilder, StreamIdentification, TsnInterfaceConfig,
};
use crate::ptp::{
    ClockAccuracy, ClockClass, PtpInstanceConfig, PtpInstanceConfigBuilder, TimeSource,
};
use eui48::MacAddress;
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
    traffic_profile: Option<String>,
}

struct ServiceSublayer {
    outgoing_forwarding_sublayer: Option<String>,
}

struct ForwardingSublayer {
    outgoing_interface: Option<String>,
}

struct TSNInterfaceConfig {
    offset_ns: Option<u32>,
    destination_address: Option<MacAddress>,
    vid: Option<u16>, // actually 12 bit
    pcp: Option<u8>,  // actually 3 bit
}

struct TrafficProfile {
    period_ns: u32,
    size_bytes: u32,
}

struct VLANInterface {
    name: String,
    physical_interface: Option<String>,
    addresses: Option<Vec<(IpAddr, u8)>>,
}

impl Configuration for SysrepoConfiguration {
    fn get_interface_configs(&mut self) -> Result<HashMap<String, TsnInterfaceConfig>> {
        let tree = self.reader.get_config("/interfaces")?;
        let interfaces = tree.find_xpath(concat!(
            "/interfaces/interface[",
            "ieee802-dot1q-bridge:bridge-port/",
            "ieee802-dot1q-sched-bridge:gate-parameter-table/",
            "admin-control-list/gate-control-entry]"
        ))?;

        interfaces
            .into_iter()
            .try_fold(HashMap::new(), |mut acc, interface| {
                if let Some(bridge_port) = interface
                    .find_xpath("ieee802-dot1q-bridge:bridge-port")?
                    .next()
                {
                    if let Some(name) = interface.get_value_for_xpath::<String>("name")? {
                        let tsn_interface_config = TsnInterfaceConfig {
                            schedule: Some(parse_schedule(&bridge_port)?),
                            taprio: None,
                        };
                        acc.insert(name, tsn_interface_config);
                    }
                }

                Ok(acc)
            })
    }

    fn get_interface_config(&mut self, interface_name: &str) -> Result<Option<TsnInterfaceConfig>> {
        let tree = self.reader.get_config("/interfaces")?;
        let interfaces = tree.find_xpath("/interfaces/interface")?;

        for interface in interfaces {
            if let Some(name) = interface.get_value_for_xpath::<String>("name")? {
                if name == interface_name {
                    let tsn_interface_config = TsnInterfaceConfig {
                        schedule: Some(parse_schedule(
                            &interface
                                .find_xpath("ieee802-dot1q-bridge:bridge-port")?
                                .next()
                                .ok_or_else(|| {
                                    anyhow!("bridge-port section not found for interface")
                                })?,
                        )?),
                        taprio: None,
                    };
                    return Ok(Some(tsn_interface_config));
                }
            }
        }

        Ok(None)
    }

    /// Get and parse configuration
    ///
    /// IP/MPLS over TSN is explicitly out of scope of the current version of the DetNet YANG model
    /// (see
    /// <https://datatracker.ietf.org/meeting/110/materials/slides-110-detnet-sessb-detnet-configuration-yang-model-walkthrough-02.pdf>
    /// for the draft-ietf-detnet-yang-09 walkthough, but does not seem to have changed in the more recent drafts).
    /// The tsn-app-flow in the YANG model is NOT for IP over TSN, but for TSN over MPLS (RFC 9024)!
    /// For the link to the Ethernet layer there was a placeholder in the older drafts
    /// and starting with <https://datatracker.ietf.org/doc/html/draft-ietf-detnet-yang-10> it was
    /// apparently decided to use only the interface as reference to the Ethernet layer.
    ///
    /// In order to implement "over TSN" use cases there are two alternatives:
    /// 1. Enhance the DetNet YANG model to cover the "over TSN" use cases.
    /// 2. Specify all TSN details via the TSN YANG models and only provide
    ///    a link from the DetNet YANG model. This seems to be the perferred option
    ///    in the WG to keep the separation. For this using only the interface
    ///    is proposed without changes to the DetNet YANG model.
    ///    (-> <https://mailarchive.ietf.org/arch/msg/detnet/DpTC_K8_Ce5ztww-9Yi08RmqAS0/>)
    ///
    /// This might be feasible since apparently (according to IEEE 802.1q) there is a 1:1 mapping
    /// between (VLAN) interface and time aware offset. This implies each stream needs
    /// a dedicated interface and the interface could be used as handle to link the DetNet flow
    /// (interface is referenced for the app-flow as well as for next hops within the network)
    /// with the TSN interface configuration or even the TSN stream.
    /// It needs to be investigated if that is sufficient!
    ///
    /// At the moment we use only the interface configuration from the TSN configuration
    /// and use the traffic specification from the DetNet configuration. By this, it is sufficient
    /// to link to the interface from the DetNet layer and not to the talker itself.
    ///
    /// Still, it is required to get the parent interface (e.g. enp1s0) of the VLAN interface (e.g. enp1s0.5)
    /// to set up the NIC. This is currently done via the parent-interface specified by
    /// <https://datatracker.ietf.org/doc/draft-ietf-netmod-intf-ext-yang/>
    /// (sub-interfaces feature needs to be enabled via 'sysrepoctl -c ietf-if-extensions -e sub-interfaces')
    fn get_app_config(&mut self, app_name: &str) -> Result<Option<AppConfig>> {
        let cfg = self.reader.get_config(
            "/detnet | /tsn-interface-configuration | /interfaces | /stream-identity",
        )?;
        get_app_flow(&cfg, app_name)?
            .map(|app_flow| get_app_config_from_app_flow(&cfg, app_name, &app_flow))
            .transpose()
    }

    fn get_app_configs(&mut self) -> Result<HashMap<String, AppConfig>> {
        let cfg = self.reader.get_config(
            "/detnet | /tsn-interface-configuration | /interfaces | /stream-identity",
        )?;
        get_app_flows(&cfg)?
            .iter()
            .map(|(app_name, app_flow)| {
                Ok((
                    String::from(app_name),
                    get_app_config_from_app_flow(&cfg, app_name, app_flow)?,
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

fn get_app_flow(tree: &DataTree, app_name: &str) -> Result<Option<AppFlow>> {
    // It would be easier to put the provided app_name inside the XPath expression,
    // but this could lead to a potential unsafe expression
    // (see https://owasp.org/www-community/attacks/XPATH_Injection - also for alternative implementations).
    let app_flows = tree.find_xpath("/detnet/app-flows/app-flow")?;
    for app_flow in app_flows {
        if let Some(name) = app_flow.get_value_for_xpath::<String>("name")? {
            if name == app_name {
                return Ok(Some(AppFlow {
                    traffic_profile: app_flow.get_value_for_xpath("traffic-profile")?,
                }));
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
                    acc.push((
                        name,
                        AppFlow {
                            traffic_profile: app_flow.get_value_for_xpath("traffic-profile")?,
                        },
                    ));
                    Ok(acc)
                }
                None => Ok(acc),
            }
        })
}

fn get_app_config_from_app_flow(
    tree: &DataTree,
    app_name: &str,
    app_flow: &AppFlow,
) -> Result<AppConfig> {
    let service_sublayer = get_service_sublayer(tree, app_name)?;
    let forwarding_sublayer = service_sublayer
        .and_then(|ssl| ssl.outgoing_forwarding_sublayer)
        .map(|ofsl| get_forwarding_sublayer(tree, &ofsl))
        .transpose()?
        .flatten();
    let traffic_profile = app_flow
        .traffic_profile
        .as_ref()
        .map(|profile| get_traffic_profile(tree, profile))
        .transpose()?
        .flatten();
    let outgoing_interface = forwarding_sublayer.and_then(|fsl| fsl.outgoing_interface);
    let tsn_interface_cfg = outgoing_interface
        .as_ref()
        .map(|iface| get_tsn_interface_config(tree, iface))
        .transpose()?
        .flatten();
    let logical_interface = outgoing_interface
        .as_ref()
        .map(|iface| get_logical_interface(tree, iface))
        .transpose()?
        .flatten();

    Ok(AppConfig {
        logical_interface: logical_interface.as_ref().map(|iface| iface.name.clone()),
        physical_interface: logical_interface
            .as_ref()
            .and_then(|iface| iface.physical_interface.clone()),
        period_ns: traffic_profile.as_ref().map(|profile| profile.period_ns),
        offset_ns: tsn_interface_cfg.as_ref().and_then(|cfg| cfg.offset_ns),
        size_bytes: traffic_profile.as_ref().map(|profile| profile.size_bytes),
        stream: Some(StreamIdentification {
            destination_address: tsn_interface_cfg
                .as_ref()
                .and_then(|cfg| cfg.destination_address),
            vid: tsn_interface_cfg.as_ref().and_then(|cfg| cfg.vid),
        }),
        pcp: tsn_interface_cfg.as_ref().and_then(|cfg| cfg.pcp),
        addresses: logical_interface
            .as_ref()
            .and_then(|iface| iface.addresses.clone()),
        cgroup: None,
    })
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

fn get_traffic_profile(
    tree: &DataTree,
    traffic_profile_name: &str,
) -> Result<Option<TrafficProfile>> {
    let traffic_profiles = tree.find_xpath("/detnet/traffic-profile")?;
    for profile in traffic_profiles {
        if let Some(name) = profile.get_value_for_xpath::<String>("name")? {
            if name == traffic_profile_name {
                let max_pkts_per_interval: u32 = profile
                    .get_value_for_xpath("traffic-spec/max-pkts-per-interval")?
                    .ok_or_else(|| {
                        anyhow!("Size can not be calculated since max-pkts-per-interval is missing")
                    })?;
                let max_payload_size: u32 = profile
                    .get_value_for_xpath("traffic-spec/max-payload-size")?
                    .ok_or_else(|| {
                        anyhow!("Size can not be calculated since max-payload-size is missing")
                    })?;

                return Ok(Some(TrafficProfile {
                    period_ns: profile
                        .get_value_for_xpath("traffic-spec/interval")?
                        .ok_or_else(|| anyhow!("traffic-spec/interval is missing"))?,

                    // TODO is that sufficient or do we need to incorporate inter-frame spacing, headers etc.?
                    size_bytes: max_pkts_per_interval
                        .checked_mul(max_payload_size)
                        .ok_or_else(|| anyhow!("overflow of slot size"))?,
                }));
            }
        }
    }

    Ok(None)
}

fn get_tsn_interface_config(
    tree: &DataTree,
    interface_name: &str,
) -> Result<Option<TSNInterfaceConfig>> {
    let interface_configs = tree.find_xpath("/tsn-interface-configuration/interface-list")?;
    for interface_config in interface_configs {
        if let Some(name) = interface_config.get_value_for_xpath::<String>("interface-name")? {
            if name == interface_name {
                const DSTADDRPATH: &str =
                    "config-list/ieee802-mac-addresses/destination-mac-address";
                const VLANIDPATH: &str = "config-list/ieee802-vlan-tag/vlan-id";
                const PCPPATH: &str = "config-list/ieee802-vlan-tag/priority-code-point";
                let destination_address = interface_config
                    .get_value_for_xpath::<String>(DSTADDRPATH)?
                    .map(|addr| addr.parse())
                    .transpose()?;
                return Ok(Some(TSNInterfaceConfig {
                    offset_ns: interface_config
                        .get_value_for_xpath("config-list/time-aware-offset")?,
                    destination_address,
                    vid: interface_config.get_value_for_xpath(VLANIDPATH)?,
                    pcp: interface_config.get_value_for_xpath(PCPPATH)?,
                }));
            }
        }
    }

    Ok(None)
}

fn get_logical_interface(tree: &DataTree, interface_name: &str) -> Result<Option<VLANInterface>> {
    let interfaces = tree.find_xpath("/interfaces/interface")?;
    for interface in interfaces {
        if let Some(name) = interface.get_value_for_xpath::<String>("name")? {
            if name == interface_name {
                let addresses = interface
                    .find_xpath("ipv4/address | ipv6/address")
                    .ok()
                    .map(|addrs| {
                        addrs
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
                            .collect::<Result<Vec<(IpAddr, u8)>>>()
                    })
                    .transpose()?;

                return Ok(Some(VLANInterface {
                    name: interface_name.to_owned(),
                    physical_interface: interface.get_value_for_xpath("parent-interface")?,
                    addresses,
                }));
            }
        }
    }

    Ok(None)
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
    let mut priority_map = HashMap::<u8, u8>::default();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AppConfig, Configuration};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_get_app_config_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let config = sysrepo_config.get_app_config("app0")?;

        let interface = String::from("enp86s0");
        let vid = 5;
        assert_eq!(
            config.unwrap(),
            AppConfig {
                logical_interface: Some(format!("{interface}.{vid}")),
                physical_interface: Some(interface),
                period_ns: Some(2_000_000),
                offset_ns: Some(0),
                size_bytes: Some(15000),
                stream: Some(StreamIdentification {
                    destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                    vid: Some(vid),
                }),
                pcp: Some(3),
                addresses: Some(vec![
                    (IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 24),
                    (
                        IpAddr::V6(Ipv6Addr::new(0xfd2a, 0xbc93, 0x8476, 0x634, 0, 0, 0, 0)),
                        64
                    )
                ]),
                cgroup: None,
            }
        );
        Ok(())
    }

    #[test]
    fn test_get_app_config_happy_without_ip() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-without-ip.json",
        );
        let config = sysrepo_config.get_app_config("app0")?;

        let interface = String::from("enp86s0");
        let vid = 5;
        assert_eq!(
            config.unwrap(),
            AppConfig {
                logical_interface: Some(format!("{interface}.{vid}")),
                physical_interface: Some(interface),
                period_ns: Some(2_000_000),
                offset_ns: Some(0),
                size_bytes: Some(15000),
                stream: Some(StreamIdentification {
                    destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                    vid: Some(vid),
                }),
                pcp: Some(3),
                addresses: Some(vec![]),
                cgroup: None,
            }
        );
        Ok(())
    }

    #[test]
    fn test_get_app_config_missing() {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        assert!(sysrepo_config
            .get_app_config("somemissingapp")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_get_app_config_missing_time_aware_offset() {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-missing-time-aware-offset.json",
        );
        assert!(sysrepo_config
            .get_app_config("app0")
            .unwrap()
            .unwrap()
            .offset_ns
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
    fn validate_example_yang() {
        SysrepoReader::mock_from_file("./config/yang/example.json")
            .get_config("")
            .unwrap();
    }
}
