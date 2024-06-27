// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides sysrepo-based network configuration (for NETCONF integration)

use anyhow::{anyhow, Context, Error, Result};
use std::collections::BTreeMap;

use crate::configuration::detnet::{
    AppFlow, AppFlowBuilder, Flow, FlowBuilder, FlowIdentificationBuilder, IncomingForwarding,
    IncomingForwardingBuilder, MplsHeader, MplsHeaderBuilder, OutgoingForwarding,
    OutgoingForwardingBuilder, UdpIpHeader, UdpIpHeaderBuilder,
};
use crate::configuration::{
    schedule::{GateControlEntry, GateControlEntryBuilder, GateOperation},
    BridgedApp, Configuration, Interface, OutgoingL2, OutgoingL2Builder, PcpEncodingTable,
    PcpEncodingTableBuilder, Schedule, ScheduleBuilder, Stream, StreamIdentification, UnbridgedApp,
};
use crate::ptp::{
    ClockAccuracy, ClockClass, PtpInstanceConfig, PtpInstanceConfigBuilder, TimeSource,
};
use eui48::MacAddress;
use log::debug;
use std::net::IpAddr;
use std::str::FromStr;
use yang2::data::{Data, DataNodeRef, DataTree};

mod helper;
use crate::configuration::sysrepo::helper::{GetValueForXPath, SysrepoReader};

/// Reads configuration from sysrepo
pub struct SysrepoConfiguration {
    reader: SysrepoReader,
}

#[derive(Debug)]
struct YangAppFlow {
    ingress_interfaces: Option<Vec<String>>,
    stream_id: Option<StreamIdentification>,
    egress_l2: Option<OutgoingL2>,
}

#[derive(Debug)]
struct ServiceSublayer {
    incoming_app_flows: Vec<String>,
    outgoing_app_flows: Vec<String>,
    outgoing_forwarding_sublayers: Vec<(String, Option<MplsHeader>)>,
    incoming_service_id_label: Option<u32>,
}

#[derive(Debug)]
struct OutgoingForwardingSublayer {
    ip: Option<UdpIpHeader>,
    outgoing_interface: Option<String>,
}

#[derive(Debug)]
struct IncomingForwardingSublayer {
    incoming_interface: Option<String>,
    udp_source_port: Option<u16>,
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

    let ip_addresses = get_interface_ip_addresses(interface)?;

    let mac_address = get_interface_mac_address(interface)?;

    Ok(Interface {
        schedule,
        taprio: None,
        pcp_encoding,
        ip_addresses,
        mac_address,
        promiscuous: None,
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

    /// Currently, streams cannot be configured via sysrepo
    /// However, in contrast to apps there is already a matching YANG module
    /// (for IEEE 802.1CB) so this is just a matter of implementation.
    fn get_stream(&mut self, _stream_name: &str) -> Result<Option<Stream>> {
        Ok(None)
    }

    /// Currently, streams cannot be configured via sysrepo
    /// However, in contrast to apps there is already a matching YANG module
    /// (for IEEE 802.1CB) so this is just a matter of implementation.
    fn get_streams(&mut self) -> Result<BTreeMap<String, Stream>> {
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
    fn get_flow(&mut self, service_sublayer_name: &str) -> Result<Option<Flow>> {
        let cfg = self
            .reader
            .get_config("/detnet | /interfaces | /stream-identity")?;
        get_service_sublayer(&cfg, service_sublayer_name)?
            .map(|service_sublayer| {
                get_flow_config_from_service_sublayer(&cfg, service_sublayer_name, service_sublayer)
            })
            .transpose()
    }

    fn get_flows(&mut self) -> Result<BTreeMap<String, Flow>> {
        let cfg = self
            .reader
            .get_config("/detnet | /interfaces| /stream-identity")?;
        get_service_sublayers(&cfg)?
            .into_iter()
            .map(|(service_sublayer_name, service_sublayer)| {
                let flow_config = get_flow_config_from_service_sublayer(
                    &cfg,
                    &service_sublayer_name,
                    service_sublayer,
                )?;

                Ok((service_sublayer_name, flow_config))
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

fn get_app_flow(tree: &DataTree, app_flow_name: &str) -> Result<Option<YangAppFlow>> {
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

fn get_service_sublayer(
    tree: &DataTree,
    service_sublayer_name: &str,
) -> Result<Option<ServiceSublayer>> {
    // It would be easier to put the provided flow_name inside the XPath expression,
    // but this could lead to a potential unsafe expression
    // (see https://owasp.org/www-community/attacks/XPATH_Injection - also for alternative implementations).
    let service_sublayers = tree.find_xpath("/detnet/service/sub-layer")?;
    for service_sublayer in service_sublayers {
        if let Some(name) = service_sublayer.get_value_for_xpath::<String>("name")? {
            if name == service_sublayer_name {
                return Ok(Some(parse_service_sublayer(&service_sublayer)?));
            }
        }
    }

    Ok(None)
}

fn get_service_sublayers(tree: &DataTree) -> Result<Vec<(String, ServiceSublayer)>> {
    tree.find_xpath("/detnet/service-sublayers/service-sublayer")?
        .try_fold(vec![], |mut acc, service_sublayer| {
            match service_sublayer.get_value_for_xpath("name")? {
                Some(name) => {
                    acc.push((name, parse_service_sublayer(&service_sublayer)?));
                    Ok(acc)
                }
                None => Ok(acc),
            }
        })
}

fn parse_app_flow(app_flow: &DataNodeRef<'_>) -> Result<YangAppFlow> {
    let destination_address = app_flow
        .get_value_for_xpath::<String>("ingress/tsn-app-flow/destination-mac-address")?
        .map(|addr| addr.parse())
        .transpose()?;

    let ingress_interfaces = app_flow
        .get_values_for_xpath::<String>("ingress/interface")?
        .collect::<Result<Vec<String>>>()?;

    let mut egress_interfaces =
        app_flow.get_values_for_xpath::<String>("egress/ethernet/interface")?;

    let mut egress_l2 = None;

    // Collect all egress information for the app flow
    if let Some(egress_interface) = egress_interfaces.next() {
        let mut outgoing_l2_builder =
            OutgoingL2Builder::new().outgoing_interface(egress_interface?);

        if let Some(tsn_egress) = app_flow
            .find_xpath("egress/tsn-app-flow")
            .ok()
            .and_then(|mut e| e.next())
        {
            outgoing_l2_builder = outgoing_l2_builder.source_opt(
                tsn_egress
                    .get_value_for_xpath::<String>("source-mac-address")?
                    .map(|addr| addr.parse())
                    .transpose()?,
            );

            outgoing_l2_builder = outgoing_l2_builder.destination_opt(
                tsn_egress
                    .get_value_for_xpath::<String>("destination-mac-address")?
                    .map(|addr| addr.parse())
                    .transpose()?,
            );

            outgoing_l2_builder =
                outgoing_l2_builder.vid_opt(tsn_egress.get_value_for_xpath::<u16>("vlan-id")?);

            outgoing_l2_builder =
                outgoing_l2_builder.pcp_opt(tsn_egress.get_value_for_xpath::<u8>("pcp")?);

            outgoing_l2_builder = outgoing_l2_builder
                .ether_type_opt(tsn_egress.get_value_for_xpath::<u16>("ethertype")?);
        }

        egress_l2 = Some(outgoing_l2_builder.build());
    }

    if egress_interfaces.next().is_some() {
        return Err(anyhow!(
            "Currently only a single egress/ethernet/interface is supported"
        ));
    }

    Ok(YangAppFlow {
        ingress_interfaces: Some(ingress_interfaces),
        stream_id: Some(StreamIdentification {
            destination_address,
            vid: app_flow.get_value_for_xpath("ingress/tsn-app-flow/vlan-id")?,
        }),
        egress_l2,
    })
}

fn get_flow_config_from_service_sublayer(
    tree: &DataTree,
    service_sublayer_name: &str,
    service_sublayer: ServiceSublayer,
) -> Result<Flow> {
    let incoming_app_flows = service_sublayer
        .incoming_app_flows
        .iter()
        .map(|app_flow_name| -> Result<AppFlow> {
            let app_flow = get_app_flow(tree, app_flow_name)?
                .ok_or_else(|| anyhow!("App flow {app_flow_name} not found"))?;
            Ok(AppFlowBuilder::new()
                .ingress_interfaces_opt(app_flow.ingress_interfaces)
                .ingress_identification_opt(app_flow.stream_id)
                .build())
        })
        .collect::<Result<Vec<AppFlow>>>()?;

    let outgoing_app_flows = service_sublayer
        .outgoing_app_flows
        .iter()
        .map(|app_flow_name| -> Result<AppFlow> {
            let app_flow = get_app_flow(tree, app_flow_name)?
                .ok_or_else(|| anyhow!("App flow {app_flow_name} not found"))?;
            Ok(AppFlowBuilder::new()
                .egress_l2_opt(app_flow.egress_l2)
                .build())
        })
        .collect::<Result<Vec<AppFlow>>>()?;

    let outgoing_forwarding = service_sublayer
        .outgoing_forwarding_sublayers
        .into_iter()
        .map(|(ofsl, mpls)| -> Result<OutgoingForwarding> {
            let fsl = get_outgoing_forwarding_sublayer(tree, &ofsl)?
                .ok_or_else(|| anyhow!("Outgoing forwarding sublayer {ofsl} not found"))?;

            let ilan = fsl
                .outgoing_interface
                .ok_or_else(|| anyhow!("Outgoing interface missing for {ofsl}"))?;
            let ip = fsl
                .ip
                .as_ref()
                .ok_or_else(|| anyhow!("Forwarding without IP header currently not supported"))?;
            let outgoing_l2 = get_outgoing_l2(tree, &ilan, ip)?;

            let fwd = OutgoingForwardingBuilder::new()
                .mpls_opt(mpls)
                .ip_opt(fsl.ip)
                .outgoing_l2_opt(outgoing_l2);

            Ok(fwd.build())
        })
        .collect::<Result<Vec<OutgoingForwarding>>>()?;

    let incoming_forwarding = get_incoming_forwarding_sublayers(tree, service_sublayer_name)?
        .into_iter()
        .map(|ifsl| {
            Ok(IncomingForwardingBuilder::new()
                .incoming_interface_opt(ifsl.incoming_interface)
                .identification(
                    FlowIdentificationBuilder::new()
                        .udp_source_port_opt(ifsl.udp_source_port)
                        .mpls_label_opt(service_sublayer.incoming_service_id_label)
                        .build(),
                )
                .build())
        })
        .collect::<Result<Vec<IncomingForwarding>>>()?;

    Ok(FlowBuilder::new()
        .incoming_app_flows_opt((!incoming_app_flows.is_empty()).then_some(incoming_app_flows))
        .outgoing_app_flows_opt((!outgoing_app_flows.is_empty()).then_some(outgoing_app_flows))
        .outgoing_forwarding_opt((!outgoing_forwarding.is_empty()).then_some(outgoing_forwarding))
        .incoming_forwarding_opt((!incoming_forwarding.is_empty()).then_some(incoming_forwarding))
        .build())
}

fn parse_service_sublayer(service_sublayer: &DataNodeRef<'_>) -> Result<ServiceSublayer> {
    let incoming_app_flows = service_sublayer
        .get_values_for_xpath::<String>("incoming/app-flow/flow")?
        .collect::<Result<Vec<String>>>()?;
    let outgoing_app_flows = service_sublayer
        .get_values_for_xpath::<String>("outgoing/app-flow/flow")?
        .collect::<Result<Vec<String>>>()?;

    let outgoing_forwarding_sublayers = service_sublayer
        .find_xpath("outgoing/forwarding-sub-layer/service-outgoing")?
        .map(|service_outgoing| -> Result<(String, Option<MplsHeader>)> {
            let fsl = service_outgoing
                .get_value_for_xpath::<String>("sub-layer")?
                .ok_or_else(|| anyhow!("Forwarding sublayer missing in service-outgoing"))?;

            let mut mpls_stack = service_outgoing.find_xpath("mpls-label-stack/entry")?;
            let mpls_entry = mpls_stack.next();
            if mpls_stack.next().is_some() {
                return Err(anyhow!(
                    "Currently only at most one MPLS stack entry is supported!"
                ));
            }

            let mpls = mpls_entry
                .map(|e| -> Result<MplsHeader> {
                    Ok(MplsHeaderBuilder::new()
                        .label_opt(
                            e.get_value_for_xpath::<String>("label")?
                                .map(|s| s.parse())
                                .transpose()?,
                        )
                        .ttl_opt(e.get_value_for_xpath("ttl")?)
                        .tc_opt(e.get_value_for_xpath("traffic-class")?)
                        .build())
                })
                .transpose()?;

            Ok((fsl, mpls))
        })
        .collect::<Result<Vec<(String, Option<MplsHeader>)>>>()?;

    let incoming_service_id_label = service_sublayer
        .get_value_for_xpath::<String>("incoming/service-id/label")?
        .map(|s| s.parse())
        .transpose()?;

    // Check for any tags not supported at the moment
    for tag in [
        "src-ip-prefix",
        "dest-ip-prefix",
        "protocol-next-header",
        "dscp",
        "flow-label",
        "source-port",
        "destination-port",
        "ipsec-spi",
        "mpls-label-stack",
    ] {
        if service_sublayer
            .get_value_for_xpath::<String>(&format!("incoming/service-id/{}", &tag))?
            .is_some()
        {
            return Err(anyhow!(
                "{tag} in incoming/service-id currently not supported"
            ));
        }
    }

    Ok(ServiceSublayer {
        incoming_app_flows,
        outgoing_app_flows,
        outgoing_forwarding_sublayers,
        incoming_service_id_label,
    })
}

fn get_outgoing_forwarding_sublayer(
    tree: &DataTree,
    forwarding_sublayer_name: &str,
) -> Result<Option<OutgoingForwardingSublayer>> {
    let forwarding_sublayers = tree.find_xpath("/detnet/forwarding/sub-layer")?;
    for forwarding_sublayer in forwarding_sublayers {
        if let Some(name) = forwarding_sublayer.get_value_for_xpath::<String>("name")? {
            if name == forwarding_sublayer_name {
                let Some(out) = forwarding_sublayer.find_xpath("outgoing/interface")?.next() else {
                    return Ok(None);
                };

                let mut ip = UdpIpHeaderBuilder::new();
                let mut ip_provided = false;

                if let Some(src) = out.get_value_for_xpath::<String>("src-ip-address")? {
                    ip = ip.source(src.parse()?);
                    ip_provided = true;
                }

                if let Some(dest) = out.get_value_for_xpath::<String>("dest-ip-address")? {
                    ip = ip.destination(dest.parse()?);
                    ip_provided = true;
                }

                if let Some(pnh) = out.get_value_for_xpath("protocol-next-header")? {
                    ip = ip.protocol_next_header(pnh);
                    ip_provided = true;
                }

                if let Some(dscp) = out.get_value_for_xpath("dscp")? {
                    ip = ip.dscp(dscp);
                    ip_provided = true;
                }

                if let Some(flow) = out.get_value_for_xpath("flow-label")? {
                    ip = ip.flow(flow);
                    ip_provided = true;
                }

                if let Some(srcport) = out.get_value_for_xpath("source-port")? {
                    ip = ip.source_port(srcport);
                    ip_provided = true;
                }

                if let Some(destport) = out.get_value_for_xpath("destination-port")? {
                    ip = ip.destination_port(destport);
                    ip_provided = true;
                }

                return Ok(Some(OutgoingForwardingSublayer {
                    ip: ip_provided.then_some(ip.build()),
                    outgoing_interface: forwarding_sublayer
                        .get_value_for_xpath("outgoing/interface/outgoing-interface")?,
                }));
            }
        }
    }

    Ok(None)
}

fn get_incoming_forwarding_sublayers(
    tree: &DataTree,
    outgoing_service_sublayer_name: &str,
) -> Result<Vec<IncomingForwardingSublayer>> {
    let forwarding_sublayers = tree.find_xpath("/detnet/forwarding/sub-layer")?;

    forwarding_sublayers
        .map(|fsl: DataNodeRef<'_>| -> Result<Option<IncomingForwardingSublayer>> {
            for ossl in
                fsl.get_values_for_xpath::<String>("outgoing/service-sub-layer/sub-layer")?
            {
                if ossl? == outgoing_service_sublayer_name {
                    // this fsl will send into the given service sublayer

                    // Check for any tags not supported at the moment
                    for tag in [
                        "src-ip-prefix",
                        "dest-ip-prefix",
                        "protocol-next-header",
                        "dscp",
                        "flow-label",
                        "destination-port",
                        "ipsec-spi",
                        "mpls-label-stack",
                        "label",
                    ] {
                        if fsl
                            .get_value_for_xpath::<String>(&format!("incoming/forwarding-id/{}", &tag))?
                            .is_some()
                        {
                            return Err(anyhow!(
                                "{tag} in incoming/forwarding-id currently not supported"
                            ));
                        }
                    }

                    // Parse UDP source port
                    let udp_source_port = fsl
                        .find_xpath("incoming/forwarding-id/source-port")?
                        .next()
                        .map(|sport| -> Result<u16> {
                            let operator = sport.get_value_for_xpath::<String>("operator")?;
                            if operator != Some("eq".to_owned()) {
                                return Err(anyhow!("Only eq operator is supported currently for incoming/forwarding-id/destination-port"));
                            }

                            sport.get_value_for_xpath("port")?.ok_or_else(|| anyhow!("port missing in incoming/forwarding-id/destination-port"))
                        }).transpose()?;

                    return Ok(Some(IncomingForwardingSublayer {
                        incoming_interface: fsl
                            .get_value_for_xpath("incoming/forwarding-id/interface")?,
                        udp_source_port,
                    }));
                }
            }

            Ok(None)
        })
        .filter_map(Result::transpose)
        .collect()
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

fn get_interface_ip_addresses(interface: &DataNodeRef<'_>) -> Result<Option<Vec<(IpAddr, u8)>>> {
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

fn get_interface_mac_address(interface: &DataNodeRef<'_>) -> Result<Option<MacAddress>> {
    Ok(interface
        .get_value_for_xpath::<String>("phys-address")?
        .map(|addr| addr.parse())
        .transpose()?)
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

fn get_outgoing_l2(
    tree: &DataTree,
    ilan_interface: &str,
    ip: &UdpIpHeader,
) -> Result<Option<Vec<OutgoingL2>>> {
    let mut tsn_handle: Option<u32> = None;

    // First we need to find out the tsn_handle
    for stream_identity in tree.find_xpath("/stream-identity")? {
        for port in stream_identity.get_values_for_xpath::<String>("in-facing/input-port")? {
            if ilan_interface == port? {
                let Some(stream_id) = stream_identity
                    .find_xpath("ip-stream-identification")?
                    .next()
                else {
                    continue;
                };

                if !is_stream_matching(&stream_id, ip)? {
                    continue;
                }

                tsn_handle = stream_identity.get_value_for_xpath("handle")?;

                break;
            }
        }

        if tsn_handle.is_some() {
            break;
        }
    }

    if tsn_handle.is_none() {
        // The corresponding data can also reasonably be provided via YAML, so just log as debug
        debug!("No matching tsn_handle can be found in the IEEE 802.1CB stream identification YANG configuration for interface {ilan_interface:?} to identify {ip:?}");
        return Ok(None);
    }

    // Secondly, we look for the other leg with the same handle to get
    // the outgoing interface
    let mut l2s = vec![];
    for stream_identity in tree.find_xpath("/stream-identity")? {
        if tsn_handle == stream_identity.get_value_for_xpath("handle")? {
            let ports = stream_identity
                .get_values_for_xpath::<String>("out-facing/output-port")?
                .collect::<Result<Vec<String>>>()?;

            for port in ports {
                l2s.push(
                    OutgoingL2Builder::new()
                        .outgoing_interface(port)
                        .destination_opt(
                            stream_identity
                                .get_value_for_xpath::<String>(
                                    "dmac-vlan-stream-identification/down/destination-mac",
                                )?
                                .map(|d| d.parse())
                                .transpose()?,
                        )
                        .vid_opt(
                            stream_identity
                                .get_value_for_xpath("dmac-vlan-stream-identification/down/vlan")?,
                        )
                        .build(),
                );
            }
        }
    }

    if l2s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(l2s))
    }
}

fn is_stream_matching(stream_id: &DataNodeRef<'_>, ip: &UdpIpHeader) -> Result<bool> {
    if stream_id
        .get_value_for_xpath::<String>("destination-mac")?
        .is_some()
    {
        return Err(anyhow!(
            "destination-mac in ip-stream-identification currently not supported"
        ));
    }

    if stream_id.get_value_for_xpath::<String>("tagged")?.is_some() {
        return Err(anyhow!(
            "tagged in ip-stream-identification currently not supported"
        ));
    }

    if stream_id.get_value_for_xpath::<String>("vlan")?.is_some() {
        return Err(anyhow!(
            "vlan in ip-stream-identification currently not supported"
        ));
    }

    if let Some(src) = stream_id.get_value_for_xpath::<String>("ip-source")? {
        if src.parse::<IpAddr>()? != *ip.source()? {
            return Ok(false);
        }
    }

    if let Some(dest) = stream_id.get_value_for_xpath::<String>("ip-destination")? {
        if dest.parse::<IpAddr>()? != *ip.destination()? {
            return Ok(false);
        }
    }

    if let Some(dscp) = stream_id.get_value_for_xpath::<u8>("dscp")? {
        if &dscp != ip.dscp()? {
            return Ok(false);
        }
    }

    if let Some(pnh) = stream_id.get_value_for_xpath::<u8>("next-protocol")? {
        if &pnh != ip.protocol_next_header()? {
            return Ok(false);
        }
    }

    if let Some(srcport) = stream_id.get_value_for_xpath::<u16>("source-port")? {
        if &srcport != ip.source_port()? {
            return Ok(false);
        }
    }

    if let Some(dstport) = stream_id.get_value_for_xpath::<u16>("destination-port")? {
        if &dstport != ip.destination_port()? {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{Configuration, InterfaceBuilder, StreamIdentificationBuilder};
    use pretty_assertions::assert_eq;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use test_log::test;

    const INTERFACE_DECAPSULATED: &str = "enp86s0";
    const INTERFACE_ENCAPSULATED: &str = "enp87s0";

    #[test]
    fn test_get_ingress_config_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-ingress-successful.json",
        );
        let config = sysrepo_config.get_flow("ssl-1")?;

        assert_eq!(
            config.unwrap(),
            FlowBuilder::new()
                .incoming_app_flows(vec![AppFlowBuilder::new()
                    .ingress_interfaces(vec![INTERFACE_DECAPSULATED.to_owned()])
                    .ingress_identification(
                        StreamIdentificationBuilder::new()
                            .destination_address("CB:cb:cb:cb:cb:AB".parse()?)
                            .vid(5)
                            .build()
                    )
                    .build()])
                .outgoing_forwarding(vec![OutgoingForwardingBuilder::new()
                    .mpls(MplsHeaderBuilder::new().label(1234).build())
                    .ip(UdpIpHeaderBuilder::new()
                        .source("10.0.1.1".parse()?)
                        .destination("10.0.1.2".parse()?)
                        .source_port(3456)
                        .build())
                    .outgoing_l2(vec![OutgoingL2Builder::new()
                        .outgoing_interface(INTERFACE_ENCAPSULATED.to_owned())
                        .vid(13)
                        .build()])
                    .build()])
                .build()
        );
        Ok(())
    }

    #[test]
    fn test_get_egress_config_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-egress-successful.json",
        );
        let config = sysrepo_config.get_flow("ssl-1")?;

        assert_eq!(
            config.unwrap(),
            FlowBuilder::new()
                .outgoing_app_flows(vec![AppFlowBuilder::new()
                    .egress_l2(
                        OutgoingL2Builder::new()
                            .outgoing_interface(INTERFACE_DECAPSULATED.to_owned())
                            .destination("CB:cb:cb:cb:cb:ab".parse()?)
                            .vid(5)
                            .pcp(3)
                            .build()
                    )
                    .build()])
                .incoming_forwarding(vec![IncomingForwardingBuilder::new()
                    .incoming_interface(INTERFACE_ENCAPSULATED.to_owned())
                    .identification(
                        FlowIdentificationBuilder::new()
                            .mpls_label(1234)
                            .udp_source_port(3456)
                            .build()
                    )
                    .build()])
                .build()
        );
        Ok(())
    }

    #[test]
    #[should_panic(expected = "Forwarding without IP header currently not supported")]
    fn test_get_ingress_config_without_ip() {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-without-ip.json",
        );

        sysrepo_config.get_flow("ssl-1").unwrap();
    }

    #[test]
    fn test_get_ingress_config_missing() {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-ingress-successful.json",
        );
        assert!(sysrepo_config.get_flow("somemissingssl").unwrap().is_none());
    }

    #[test]
    fn test_get_ptp_config_happy() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-ingress-successful.json",
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
            "./src/configuration/sysrepo/test-ingress-successful.json",
        );
        let interface = String::from("enp87s0");
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
                .ip_addresses(vec![
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
