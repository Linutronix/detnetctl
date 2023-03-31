use crate::configuration;
use crate::nic_setup::{NICSetup, SocketConfig};
use anyhow::{anyhow, Context, Result};
use prost::Message;
use std::path::Path;

pub mod detdipc {
    include!(concat!(env!("OUT_DIR"), "/detdipc.rs"));
}

use std::os::unix::net::UnixDatagram;

const DETD_SOCK: &str = "/var/run/detd/detd_service.sock";

/// Configures the NIC using the external detd service
#[derive(Debug)]
pub struct DetdGateway {
    socket: UnixDatagram,
}

impl DetdGateway {
    /// Create a new DetdGateway and connect to detd via UNIX socket
    ///
    /// # Arguments
    ///
    /// * `remote_socket_path` - Path to the detd socket,
    ///                          /var/run/detd/detd_service.sock is used if None is provided
    ///
    /// * `local_socket_path` - Path to the own socket,
    ///                         Uses an abstract socket if None is provided
    ///
    pub fn new(
        remote_socket_path: Option<&Path>,
        local_socket_path: Option<&Path>,
    ) -> Result<Self> {
        let socket = UnixDatagram::bind(local_socket_path.unwrap_or(Path::new("")))
            .context("Failed to bind to local UNIX socket")?;
        socket
            .connect(remote_socket_path.unwrap_or(Path::new(DETD_SOCK)))
            .context("Failed to connect to detd")?;
        Ok(DetdGateway { socket })
    }
}

impl NICSetup for DetdGateway {
    fn apply_config(&self, config: &configuration::EthernetConfig) -> Result<SocketConfig> {
        if config.offset_ns > config.period_ns {
            return Err(anyhow!("Not possible to setup if offset > period!"));
        }

        let request = detdipc::StreamQosRequest {
            period: config
                .period_ns
                .ok_or(anyhow!("Period is required for detd!"))?,
            size: config
                .size_bytes
                .ok_or(anyhow!("Size is required for detd!"))?,
            interface: config.physical_interface.clone(),
            dmac: config
                .destination_address
                .ok_or(anyhow!("Destination address is required for detd!"))?
                .to_hex_string(),
            vid: u32::from(config.vid.ok_or(anyhow!("VLAN ID is required for detd!"))?),
            pcp: u32::from(config.pcp.ok_or(anyhow!("PCP is required for detd!"))?),
            txmin: config
                .offset_ns
                .ok_or(anyhow!("Offset is required for detd!"))?,

            // currently unused by detd (https://github.com/Avnu/detd/blob/e94346dfe9bd595f601ba02f27b12db79339bf88/detd/service.py#L228)
            txmax: config
                .offset_ns
                .ok_or(anyhow!("Offset is required for detd!"))?,

            // currently only false supported by detd (https://github.com/Avnu/detd/blob/e94346dfe9bd595f601ba02f27b12db79339bf88/detd/service.py#L301)
            setup_socket: false,

            // currently not properly passed to config (bug?) (https://github.com/Avnu/detd/blob/e94346dfe9bd595f601ba02f27b12db79339bf88/detd/service.py#L228)
            basetime: 0,
        };

        let mut message = vec![];
        request.encode(&mut message)?;
        self.socket.send(&message)?;
        let mut buf = [0; 1024];
        let count = self.socket.recv(&mut buf)?;

        let response = detdipc::StreamQosResponse::decode(&buf[..count])?;

        if !response.ok {
            return Err(anyhow!("Setup of NIC not possible!"));
        }

        if response.vlan_interface != config.logical_interface {
            return Err(anyhow!(
                "Interface returned from NIC setup does not match VLAN interface in configuration!"
            ));
        }

        Ok(SocketConfig {
            logical_interface: response.vlan_interface,
            priority: response.socket_priority as u8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;
    use std::thread;
    use std::time::Duration;

    fn run_test(
        ethernet_config: configuration::EthernetConfig,
        mut response: Box<
            dyn FnMut(&detdipc::StreamQosRequest) -> detdipc::StreamQosResponse + Send,
        >,
    ) -> Result<SocketConfig> {
        let detd_socket_file = tempfile::Builder::new().make(|path| UnixDatagram::bind(path))?;

        let gateway = tempfile::Builder::new().make(|path| {
            DetdGateway::new(Some(detd_socket_file.path()), Some(path))
                .map_err(|e| Error::new(std::io::ErrorKind::Other, e))
        })?;

        let detddummy = thread::spawn(move || {
            let socket = &detd_socket_file.as_file();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("set_read_timeout function failed");

            let mut buf = [0; 1024];
            let (count, address) = match socket.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => {
                    return;
                }
            };

            let request = detdipc::StreamQosRequest::decode(&buf[..count]).unwrap();

            let mut message = vec![];
            let resp = response(&request);
            resp.encode(&mut message).unwrap();
            socket
                .send_to(&message, address.as_pathname().unwrap())
                .unwrap();
        });

        let result = gateway.as_file().apply_config(&ethernet_config);

        let _ = detddummy.join();

        Ok(result?)
    }

    fn generate_ethernet_config(offset: u32) -> configuration::EthernetConfig {
        configuration::EthernetConfig {
            logical_interface: String::from("eth0.3"),
            physical_interface: String::from("eth0"),
            period_ns: Some(1000 * 100),
            offset_ns: Some(offset),
            size_bytes: Some(1000),
            destination_address: Some("8a:de:82:a1:59:5a".parse().unwrap()),
            vid: Some(3),
            pcp: Some(4),
        }
    }

    #[test]
    fn test_happy() -> Result<()> {
        let socket_config = run_test(
            generate_ethernet_config(0),
            Box::new(|request| detdipc::StreamQosResponse {
                ok: true,
                socket_priority: 5,
                vlan_interface: request.interface.to_owned() + "." + &request.vid.to_string(),
            }),
        )?;

        assert_eq!(socket_config.logical_interface, "eth0.3");
        assert_eq!(socket_config.priority, 5);

        Ok(())
    }

    #[test]
    fn test_invalid_offset() -> Result<()> {
        let socket_config = run_test(
            generate_ethernet_config(1000 * 1000),
            Box::new(|request| detdipc::StreamQosResponse {
                ok: true,
                socket_priority: 5,
                vlan_interface: request.interface.to_owned() + "." + &request.vid.to_string(),
            }),
        );

        assert!(socket_config.is_err());

        Ok(())
    }

    #[test]
    fn test_response_not_ok() -> Result<()> {
        let socket_config = run_test(
            generate_ethernet_config(0),
            Box::new(|request| detdipc::StreamQosResponse {
                ok: false,
                socket_priority: 5,
                vlan_interface: request.interface.to_owned() + "." + &request.vid.to_string(),
            }),
        );

        assert!(socket_config.is_err());

        Ok(())
    }

    #[test]
    fn test_not_matching_vlan_interface() -> Result<()> {
        let socket_config = run_test(
            generate_ethernet_config(0),
            Box::new(|_| detdipc::StreamQosResponse {
                ok: true,
                socket_priority: 5,
                vlan_interface: "abc0".to_string(),
            }),
        );

        assert!(socket_config.is_err());

        Ok(())
    }
}
