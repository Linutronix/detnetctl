//! Provides sysrepo-based network configuration (for NETCONF integration)
use anyhow::{anyhow, Result};

#[cfg(not(test))]
use {sysrepo::SrConn, sysrepo::SrData, sysrepo::SrSession};

#[cfg(test)]
mod mocks;
#[cfg(test)]
use {mocks::MockSrConn as SrConn, mocks::MockSrData as SrData, mocks::MockSrSession as SrSession};

use yang2::context::{Context, ContextFlags};

use crate::configuration;
use eui48::MacAddress;
use ipnet::IpNet;
use std::net::IpAddr;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use yang2::data::{Data, DataTree};

mod helper;
use crate::configuration::sysrepo::helper::*;

/// Reads configuration from sysrepo
pub struct SysrepoConfiguration {
    ctx: Arc<Mutex<SysrepoContext>>,
}

struct SysrepoContext {
    _sr: SrConn, // never used, but referenced by sess
    sess: SrSession,
    libyang_ctx: Arc<Context>,
}

unsafe impl Send for SysrepoConfiguration {} // should be taken care of by sysrepo_rs in the future

struct AppFlow {
    interface: String,
    traffic_profile: String,
    source_address: Option<IpAddr>,
    source_address_prefix_length: Option<u8>,
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
}

impl configuration::Configuration for SysrepoConfiguration {
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
    fn get_app_config(&mut self, app_name: &str) -> Result<configuration::AppConfig> {
        let cfg = self.get_detnet_and_tsn_config()?;
        let app_flow = get_app_flow(cfg.tree(), app_name)?;
        let traffic_profile = get_traffic_profile(cfg.tree(), &app_flow.traffic_profile)?;
        let tsn_interface_cfg = get_tsn_interface_config(cfg.tree(), &app_flow.interface)?;
        let logical_interface = get_logical_interface(cfg.tree(), &app_flow.interface)?;

        Ok(configuration::AppConfig {
            logical_interface: logical_interface.name,
            physical_interface: logical_interface.physical_interface,
            period_ns: Some(traffic_profile.period_ns),
            offset_ns: Some(tsn_interface_cfg.offset_ns),
            size_bytes: Some(traffic_profile.size_bytes),
            destination_address: Some(tsn_interface_cfg.destination_address),
            vid: Some(tsn_interface_cfg.vid),
            pcp: Some(tsn_interface_cfg.pcp),
            ip_address: app_flow.source_address,
            prefix_length: app_flow.source_address_prefix_length,
        })
    }
}

impl SysrepoConfiguration {
    /// Create a new SysrepoConfiguration and connect to sysrepo
    pub fn new() -> Result<Self> {
        let ds = sysrepo::SrDatastore::Running;

        sysrepo::log_stderr(sysrepo::SrLogLevel::Debug);

        // Connect to sysrepo
        let mut sr = match SrConn::new(0) {
            Ok(sr) => sr,
            Err(_) => return Err(anyhow!("Could not connect to sysrepo")),
        };

        // Start session
        let sess = match sr.start_session(ds) {
            Ok(sess) => sess,
            Err(_) => return Err(anyhow!("Could not start sysrepo session")),
        };
        let unowned_sess = sess.clone();

        // Setup libyang context
        let libyang_ctx =
            Context::new(ContextFlags::NO_YANGLIBRARY).expect("Failed to create context");
        let libyang_ctx = Arc::new(libyang_ctx);

        Ok(SysrepoConfiguration {
            ctx: Arc::new(Mutex::new(SysrepoContext {
                _sr: sr,
                sess: unowned_sess,
                libyang_ctx,
            })),
        })
    }

    fn get_detnet_and_tsn_config(&mut self) -> Result<SrData> {
        const XPATH_DETNET_AND_TSN: &str = "/detnet | /tsn-interface-configuration | /interfaces";
        let mut lock = self
            .ctx
            .lock()
            .or(Err(anyhow!("Poisoned Sysrepo Context")))?;
        let context = lock.deref_mut();
        match context
            .sess
            .get_data(&context.libyang_ctx, XPATH_DETNET_AND_TSN, None, None, 0)
        {
            Ok(values) => Ok(values),
            Err(_) => Err(anyhow!("Can not get sysrepo data")),
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
            let ip =
                match app_flow.get_value_for_xpath::<String>("ingress/ip-app-flow/src-ip-prefix") {
                    Ok(srcipprefix) => Some(srcipprefix.parse::<IpNet>()?),
                    Err(_) => None,
                };

            return Ok(AppFlow {
                interface: app_flow.get_value_for_xpath("ingress/interface")?,
                traffic_profile: app_flow.get_value_for_xpath("traffic-profile")?,
                source_address: ip.map(|prefix| prefix.addr()),
                source_address_prefix_length: ip.map(|prefix| prefix.prefix_len()),
            });
        }
    }

    Err(anyhow!("App flow not found"))
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
                size_bytes: max_pkts_per_interval * max_payload_size,
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
            let destination_address_string: String =
                interface_config.get_value_for_xpath(DSTADDRPATH)?;
            const VLANIDPATH: &str = "config-list/ieee802-vlan-tag/vlan-id";
            const PCPPATH: &str = "config-list/ieee802-vlan-tag/priority-code-point";
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
            return Ok(VLANInterface {
                name: interface_name.to_string(),
                physical_interface: interface.get_value_for_xpath("parent-interface")?,
            });
        }
    }

    Err(anyhow!("VLAN interface not found in configuration"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AppConfig, Configuration};
    use std::fs::File;
    use std::net::{IpAddr, Ipv4Addr};
    use yang2::data::{DataFormat, DataParserFlags, DataTree, DataValidationFlags};

    fn create_sysrepo_config(file: &str) -> SysrepoConfiguration {
        let sr = SrConn::default();
        let mut sess = SrSession::default();
        let mut libyang_ctx =
            Context::new(ContextFlags::NO_YANGLIBRARY).expect("Failed to create context");
        libyang_ctx
            .set_searchdir("./config/yang")
            .expect("Failed to set YANG search directory");

        let modules = &[
            ("iana-if-type", vec![]),
            ("ietf-if-extensions", vec!["sub-interfaces"]),
            ("ietf-detnet", vec![]),
            ("tsn-interface-configuration", vec![]),
        ];

        for (module_name, features) in modules {
            libyang_ctx
                .load_module(module_name, None, features)
                .expect("Failed to load module");
        }

        let libyang_ctx = Arc::new(libyang_ctx);

        let filename = String::from(file);
        sess.expect_get_data()
            .returning(move |context, _xpath, _max_depth, _timeout, _opts| {
                let tree = DataTree::parse_file(
                    context,
                    File::open(filename.clone()).expect("file not found"),
                    DataFormat::JSON,
                    DataParserFlags::STRICT,
                    DataValidationFlags::NO_STATE,
                )
                .expect("could not parse");

                let mut data = SrData::default();
                data.expect_tree().return_const(tree);
                Ok(data)
            });

        SysrepoConfiguration {
            ctx: Arc::new(Mutex::new(SysrepoContext {
                _sr: sr,
                sess,
                libyang_ctx,
            })),
        }
    }

    #[test]
    fn test_get_app_config_happy() -> Result<()> {
        let mut sysrepo_config =
            create_sysrepo_config("./src/configuration/sysrepo/test-successful.json");
        let config = sysrepo_config.get_app_config("app0")?;

        let interface = String::from("enp1s0");
        let vid = 5;
        assert_eq!(
            config,
            AppConfig {
                logical_interface: format!("{}.{}", interface, vid),
                physical_interface: interface,
                period_ns: Some(2000000),
                offset_ns: Some(0),
                size_bytes: Some(15000),
                destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(vid),
                pcp: Some(3),
                ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))),
                prefix_length: Some(32),
            }
        );
        Ok(())
    }

    #[test]
    fn test_get_app_config_happy_without_ip() -> Result<()> {
        let mut sysrepo_config =
            create_sysrepo_config("./src/configuration/sysrepo/test-without-ip.json");
        let config = sysrepo_config.get_app_config("app0")?;

        let interface = String::from("enp1s0");
        let vid = 5;
        assert_eq!(
            config,
            AppConfig {
                logical_interface: format!("{}.{}", interface, vid),
                physical_interface: interface,
                period_ns: Some(2000000),
                offset_ns: Some(0),
                size_bytes: Some(15000),
                destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(vid),
                pcp: Some(3),
                ip_address: None,
                prefix_length: None,
            }
        );
        Ok(())
    }

    #[test]
    #[should_panic(expected = "App flow not found")]
    fn test_get_app_config_missing() {
        let mut sysrepo_config =
            create_sysrepo_config("./src/configuration/sysrepo/test-successful.json");
        sysrepo_config.get_app_config("somemissingapp").unwrap();
    }

    #[test]
    #[should_panic(expected = "config-list/time-aware-offset missing")]
    fn test_get_app_config_invalid_file() {
        let mut sysrepo_config = create_sysrepo_config(
            "./src/configuration/sysrepo/test-missing-time-aware-offset.json",
        );
        sysrepo_config.get_app_config("app0").unwrap();
    }
}
