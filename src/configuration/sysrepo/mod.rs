// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides sysrepo-based network configuration (for NETCONF integration)

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;

use crate::configuration::{AppConfig, Configuration, PtpConfig};
use crate::ptp::{ClockAccuracy, ClockClass, TimeSource};
use eui48::MacAddress;
use std::net::IpAddr;
use std::str::FromStr;
use yang2::data::{Data, DataTree};

mod helper;
use crate::configuration::sysrepo::helper::{FromDataValue, GetValueForXPath, SysrepoReader};

/// Reads configuration from sysrepo
pub struct SysrepoConfiguration {
    reader: SysrepoReader,
}

struct AppFlow {
    traffic_profile: String,
}

struct ServiceSublayer {
    outgoing_forwarding_sublayer: String,
}

struct ForwardingSublayer {
    outgoing_interface: String,
}

struct TSNInterfaceConfig {
    offset_ns: u32,
    destination_address: MacAddress,
    vid: u16, // actually 12 bit
    pcp: u8,  // actually 3 bit
}

struct TrafficProfile {
    period_ns: u32,
    size_bytes: u32,
}

struct VLANInterface {
    name: String,
    physical_interface: String,
    addresses: Option<Vec<(IpAddr, u8)>>,
}

impl Configuration for SysrepoConfiguration {
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
    fn get_app_config(&mut self, app_name: &str) -> Result<AppConfig> {
        let cfg = self
            .reader
            .get_config("/detnet | /tsn-interface-configuration | /interfaces")?;
        let app_flow = get_app_flow(&cfg, app_name)?;
        get_app_config_from_app_flow(&cfg, app_name, &app_flow)
    }

    fn get_app_configs(&mut self) -> Result<HashMap<String, AppConfig>> {
        let cfg = self
            .reader
            .get_config("/detnet | /tsn-interface-configuration | /interfaces")?;
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

    fn get_ptp_config(&mut self, instance: u32) -> Result<PtpConfig> {
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

fn get_app_flow(tree: &DataTree, app_name: &str) -> Result<AppFlow> {
    // It would be easier to put the provided app_name inside the XPath expression,
    // but this could lead to a potential unsafe expression
    // (see https://owasp.org/www-community/attacks/XPATH_Injection - also for alternative implementations).
    let app_flows = tree.find_xpath("/detnet/app-flows/app-flow")?;
    for app_flow in app_flows {
        let name: String = app_flow.get_value_for_xpath("name")?;

        if name == app_name {
            return Ok(AppFlow {
                traffic_profile: app_flow.get_value_for_xpath("traffic-profile")?,
            });
        }
    }

    Err(anyhow!("App flow not found"))
}

fn get_app_flows(tree: &DataTree) -> Result<Vec<(String, AppFlow)>> {
    tree.find_xpath("/detnet/app-flows/app-flow")?
        .map(|app_flow| {
            let name: String = app_flow.get_value_for_xpath("name")?;
            Ok((
                name,
                AppFlow {
                    traffic_profile: app_flow.get_value_for_xpath("traffic-profile")?,
                },
            ))
        })
        .collect()
}

fn get_app_config_from_app_flow(
    tree: &DataTree,
    app_name: &str,
    app_flow: &AppFlow,
) -> Result<AppConfig> {
    let service_sublayer = get_service_sublayer(tree, app_name)?;
    let forwarding_sublayer =
        get_forwarding_sublayer(tree, &service_sublayer.outgoing_forwarding_sublayer)?;
    let traffic_profile = get_traffic_profile(tree, &app_flow.traffic_profile)?;
    let tsn_interface_cfg =
        get_tsn_interface_config(tree, &forwarding_sublayer.outgoing_interface)?;
    let logical_interface = get_logical_interface(tree, &forwarding_sublayer.outgoing_interface)?;

    Ok(AppConfig {
        logical_interface: logical_interface.name,
        physical_interface: logical_interface.physical_interface,
        period_ns: Some(traffic_profile.period_ns),
        offset_ns: Some(tsn_interface_cfg.offset_ns),
        size_bytes: Some(traffic_profile.size_bytes),
        destination_address: Some(tsn_interface_cfg.destination_address),
        vid: Some(tsn_interface_cfg.vid),
        pcp: Some(tsn_interface_cfg.pcp),
        addresses: logical_interface.addresses,
    })
}

fn get_service_sublayer(tree: &DataTree, incoming_app_flow: &str) -> Result<ServiceSublayer> {
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

                return Ok(ServiceSublayer {
                    outgoing_forwarding_sublayer,
                });
            }
        }
    }

    Err(anyhow!("No matching service sublayer found"))
}

fn get_forwarding_sublayer(
    tree: &DataTree,
    forwarding_sublayer_name: &str,
) -> Result<ForwardingSublayer> {
    let forwarding_sublayers = tree.find_xpath("/detnet/forwarding/sub-layer")?;
    for forwarding_sublayer in forwarding_sublayers {
        let name: String = forwarding_sublayer.get_value_for_xpath("name")?;

        if name == forwarding_sublayer_name {
            return Ok(ForwardingSublayer {
                outgoing_interface: forwarding_sublayer
                    .get_value_for_xpath("outgoing/interface/outgoing-interface")?,
            });
        }
    }

    Err(anyhow!("No matching forwarding sublayer found"))
}

fn get_ptp_instance(tree: &DataTree, instance_index: u32) -> Result<PtpConfig> {
    let instances = tree.find_xpath("/ptp/instances/instance")?;
    for instance in instances {
        let index: u32 = instance.get_value_for_xpath("instance-index")?;

        if index == instance_index {
            let clock_class: String =
                instance.get_value_for_xpath("default-ds/clock-quality/clock-class")?;
            let clock_accuracy: String =
                instance.get_value_for_xpath("default-ds/clock-quality/clock-accuracy")?;
            let time_source: String =
                instance.get_value_for_xpath("time-properties-ds/time-source")?;

            let sdo_id: u16 = instance.get_value_for_xpath("default-ds/sdo-id")?;
            let gptp_profile = match sdo_id {
                0x000 => false,
                0x100 => true,
                _ => {
                    return Err(anyhow!(
                        "Only sdoId 0x000 and 0x100 are supported at the moment"
                    ))
                }
            };

            return Ok(PtpConfig {
                clock_class: ClockClass::from_str(&clock_class)?,
                clock_accuracy: ClockAccuracy::from_str(&clock_accuracy)?,
                offset_scaled_log_variance: instance
                    .get_value_for_xpath("default-ds/clock-quality/offset-scaled-log-variance")?,
                current_utc_offset: instance
                    .get_value_for_xpath("time-properties-ds/current-utc-offset")?,
                current_utc_offset_valid: instance
                    .get_value_for_xpath("time-properties-ds/current-utc-offset-valid")?,
                leap59: instance.get_value_for_xpath("time-properties-ds/leap59")?,
                leap61: instance.get_value_for_xpath("time-properties-ds/leap61")?,
                time_traceable: instance
                    .get_value_for_xpath("time-properties-ds/time-traceable")?,
                frequency_traceable: instance
                    .get_value_for_xpath("time-properties-ds/frequency-traceable")?,
                ptp_timescale: instance.get_value_for_xpath("time-properties-ds/ptp-timescale")?,
                time_source: TimeSource::from_str(&time_source)?,
                domain_number: instance.get_value_for_xpath("default-ds/domain-number")?,
                gptp_profile,
            });
        }
    }

    Err(anyhow!("PTP instance {} not found", instance_index))
}

fn get_traffic_profile(tree: &DataTree, traffic_profile_name: &str) -> Result<TrafficProfile> {
    let traffic_profiles = tree.find_xpath("/detnet/traffic-profile")?;
    for profile in traffic_profiles {
        let name: String = profile.get_value_for_xpath("name")?;

        if name == traffic_profile_name {
            let max_pkts_per_interval: u32 =
                profile.get_value_for_xpath("traffic-spec/max-pkts-per-interval")?;
            let max_payload_size: u32 =
                profile.get_value_for_xpath("traffic-spec/max-payload-size")?;

            return Ok(TrafficProfile {
                period_ns: profile.get_value_for_xpath("traffic-spec/interval")?,

                // TODO is that sufficient or do we need to incorporate inter-frame spacing, headers etc.?
                size_bytes: max_pkts_per_interval
                    .checked_mul(max_payload_size)
                    .ok_or_else(|| anyhow!("overflow of slot size"))?,
            });
        }
    }

    Err(anyhow!("Traffic profile not found"))
}

fn get_tsn_interface_config(tree: &DataTree, interface_name: &str) -> Result<TSNInterfaceConfig> {
    let interface_configs = tree.find_xpath("/tsn-interface-configuration/interface-list")?;
    for interface_config in interface_configs {
        let name: String = interface_config.get_value_for_xpath("interface-name")?;

        if name == interface_name {
            const DSTADDRPATH: &str = "config-list/ieee802-mac-addresses/destination-mac-address";
            const VLANIDPATH: &str = "config-list/ieee802-vlan-tag/vlan-id";
            const PCPPATH: &str = "config-list/ieee802-vlan-tag/priority-code-point";
            let destination_address_string: String =
                interface_config.get_value_for_xpath(DSTADDRPATH)?;
            return Ok(TSNInterfaceConfig {
                offset_ns: interface_config.get_value_for_xpath("config-list/time-aware-offset")?,
                destination_address: destination_address_string.parse()?,
                vid: interface_config.get_value_for_xpath(VLANIDPATH)?,
                pcp: interface_config.get_value_for_xpath(PCPPATH)?,
            });
        }
    }

    Err(anyhow!("TSN interface configuration not found"))
}

fn get_logical_interface(tree: &DataTree, interface_name: &str) -> Result<VLANInterface> {
    let interfaces = tree.find_xpath("/interfaces/interface")?;
    for interface in interfaces {
        let name: String = interface.get_value_for_xpath("name")?;

        if name == interface_name {
            let addresses = interface
                .find_xpath("ipv4/address | ipv6/address")
                .ok()
                .map(|addrs| {
                    addrs
                        .map(|address| -> Result<(IpAddr, u8)> {
                            let ip = address
                                .get_value_for_xpath::<String>("ip")?
                                .parse::<IpAddr>()?;
                            let prefix_length: u8 = address.get_value_for_xpath("prefix-length")?;
                            Ok((ip, prefix_length))
                        })
                        .collect::<Result<Vec<(IpAddr, u8)>>>()
                })
                .transpose()?;

            return Ok(VLANInterface {
                name: interface_name.to_owned(),
                physical_interface: interface.get_value_for_xpath("parent-interface")?,
                addresses,
            });
        }
    }

    Err(anyhow!("VLAN interface not found in configuration"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AppConfig, Configuration};
    use crate::ptp::PtpConfig;
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
            config,
            AppConfig {
                logical_interface: format!("{interface}.{vid}"),
                physical_interface: interface,
                period_ns: Some(2_000_000),
                offset_ns: Some(0),
                size_bytes: Some(15000),
                destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(vid),
                pcp: Some(3),
                addresses: Some(vec![
                    (IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 24),
                    (
                        IpAddr::V6(Ipv6Addr::new(0xfd2a, 0xbc93, 0x8476, 0x634, 0, 0, 0, 0)),
                        64
                    )
                ])
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
            config,
            AppConfig {
                logical_interface: format!("{interface}.{vid}"),
                physical_interface: interface,
                period_ns: Some(2_000_000),
                offset_ns: Some(0),
                size_bytes: Some(15000),
                destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(vid),
                pcp: Some(3),
                addresses: Some(vec![])
            }
        );
        Ok(())
    }

    #[test]
    #[should_panic(expected = "App flow not found")]
    fn test_get_app_config_missing() {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        sysrepo_config.get_app_config("somemissingapp").unwrap();
    }

    #[test]
    #[should_panic(expected = "config-list/time-aware-offset missing")]
    fn test_get_app_config_invalid_file() {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-missing-time-aware-offset.json",
        );
        sysrepo_config.get_app_config("app0").unwrap();
    }

    #[test]
    fn test_get_ptp_config_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let config = sysrepo_config.get_ptp_config(1)?;

        assert_eq!(
            config,
            PtpConfig {
                clock_class: ClockClass::Default,
                clock_accuracy: ClockAccuracy::TimeAccurateToGreaterThan10S,
                offset_scaled_log_variance: 0xFFFF,
                current_utc_offset: 37,
                current_utc_offset_valid: true,
                leap59: false,
                leap61: false,
                time_traceable: true,
                frequency_traceable: false,
                ptp_timescale: true,
                time_source: TimeSource::InternalOscillator,
                domain_number: 0,
                gptp_profile: true,
            }
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
