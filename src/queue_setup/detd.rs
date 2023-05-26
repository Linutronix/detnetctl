use crate::configuration;
use crate::queue_setup::{QueueSetup, SocketConfig};
use anyhow::{anyhow, Context, Result};
use prost::Message;
use std::path::{Path, PathBuf};

pub mod detdipc {
    include!(concat!(env!("OUT_DIR"), "/detdipc.rs"));
}

use std::os::unix::net::UnixDatagram;

const DETD_SOCK: &str = "/var/run/detd/detd_service.sock";

/// Configures the NIC using the external detd service
#[derive(Debug)]
pub struct DetdGateway {
    remote_socket_path: PathBuf,
    local_socket_path: PathBuf,
}

impl DetdGateway {
    /// Create a new `DetdGateway` and connect to detd via UNIX socket
    ///
    /// # Arguments
    ///
    /// * `remote_socket_path` - Path to the detd socket,
    ///                          `/var/run/detd/detd_service.sock` is used if None is provided
    ///
    /// * `local_socket_path` - Path to the own socket,
    ///                         Uses an abstract socket if None is provided
    #[must_use]
    pub fn new(remote_socket_path: Option<&Path>, local_socket_path: Option<&Path>) -> Self {
        Self {
            remote_socket_path: remote_socket_path
                .unwrap_or_else(|| Path::new(DETD_SOCK))
                .to_path_buf(),
            local_socket_path: local_socket_path
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf(),
        }
    }
}

impl QueueSetup for DetdGateway {
    fn apply_config(&self, config: &configuration::AppConfig) -> Result<SocketConfig> {
        if config.offset_ns > config.period_ns {
            return Err(anyhow!("Not possible to setup if offset > period!"));
        }
        let socket = UnixDatagram::bind(self.local_socket_path.as_path())
            .context("Failed to bind to local UNIX socket")?;
        socket
            .connect(self.remote_socket_path.as_path())
            .context("Failed to connect to detd")?;

        let request = detdipc::StreamQosRequest {
            period: config
                .period_ns
                .ok_or_else(|| anyhow!("Period is required for detd!"))?,
            size: config
                .size_bytes
                .ok_or_else(|| anyhow!("Size is required for detd!"))?,
            interface: config.physical_interface.clone(),
            dmac: config
                .destination_address
                .ok_or_else(|| anyhow!("Destination address is required for detd!"))?
                .to_hex_string(),
            vid: u32::from(
                config
                    .vid
                    .ok_or_else(|| anyhow!("VLAN ID is required for detd!"))?,
            ),
            pcp: u32::from(
                config
                    .pcp
                    .ok_or_else(|| anyhow!("PCP is required for detd!"))?,
            ),
            txmin: config
                .offset_ns
                .ok_or_else(|| anyhow!("Offset is required for detd!"))?,

            // currently unused by detd (https://github.com/Avnu/detd/blob/e94346dfe9bd595f601ba02f27b12db79339bf88/detd/service.py#L228)
            txmax: config
                .offset_ns
                .ok_or_else(|| anyhow!("Offset is required for detd!"))?,

            // currently only false supported by detd (https://github.com/Avnu/detd/blob/e94346dfe9bd595f601ba02f27b12db79339bf88/detd/service.py#L301)
            setup_socket: false,

            // currently not properly passed to config (bug?) (https://github.com/Avnu/detd/blob/e94346dfe9bd595f601ba02f27b12db79339bf88/detd/service.py#L228)
            basetime: 0,
        };

        let mut message = vec![];
        request.encode(&mut message)?;
        socket.send(&message)?;
        let mut buf = [0; 1024];
        let count = socket.recv(&mut buf)?;

        let response = detdipc::StreamQosResponse::decode(
            buf.get(..count)
                .ok_or_else(|| anyhow!("buffer too small"))?,
        )?;

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
            priority: u8::try_from(response.socket_priority)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;
    use std::time::Duration;

    fn run_test(
        app_config: &configuration::AppConfig,
        mut response: Box<
            dyn FnMut(&detdipc::StreamQosRequest) -> detdipc::StreamQosResponse + Send,
        >,
    ) -> Result<SocketConfig> {
        let detd_socket_file = tempfile::Builder::new().make(|path| UnixDatagram::bind(path))?;

        let gateway = tempfile::Builder::new()
            .make(|path| Ok(DetdGateway::new(Some(detd_socket_file.path()), Some(path))))?;

        let detddummy = thread::spawn(move || {
            let socket = &detd_socket_file.as_file();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("set_read_timeout function failed");

            let mut buf = [0; 1024];
            let Ok((count, address)) = socket.recv_from(&mut buf) else {
                return;
            };

            let request = detdipc::StreamQosRequest::decode(&buf[..count]).unwrap();

            let mut message = vec![];
            let resp = response(&request);
            resp.encode(&mut message).unwrap();
            socket
                .send_to(&message, address.as_pathname().unwrap())
                .unwrap();
        });

        let result = gateway.as_file().apply_config(app_config);

        let _ = detddummy.join();

        result
    }

    fn generate_app_config(offset: u32) -> configuration::AppConfig {
        configuration::AppConfig {
            logical_interface: String::from("eth0.3"),
            physical_interface: String::from("eth0"),
            period_ns: Some(1000 * 100),
            offset_ns: Some(offset),
            size_bytes: Some(1000),
            destination_address: Some("8a:de:82:a1:59:5a".parse().unwrap()),
            vid: Some(3),
            pcp: Some(4),
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3))),
            prefix_length: Some(16),
        }
    }

    #[test]
    fn test_happy() -> Result<()> {
        let socket_config = run_test(
            &generate_app_config(0),
            Box::new(|request| detdipc::StreamQosResponse {
                ok: true,
                socket_priority: 5,
                vlan_interface: request.interface.clone() + "." + &request.vid.to_string(),
            }),
        )?;

        assert_eq!(socket_config.logical_interface, "eth0.3");
        assert_eq!(socket_config.priority, 5);

        Ok(())
    }

    #[test]
    #[should_panic(expected = "Not possible to setup if offset > period!")]
    fn test_invalid_offset() {
        run_test(
            &generate_app_config(1000 * 1000),
            Box::new(|request| detdipc::StreamQosResponse {
                ok: true,
                socket_priority: 5,
                vlan_interface: request.interface.clone() + "." + &request.vid.to_string(),
            }),
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "Setup of NIC not possible!")]
    fn test_response_not_ok() {
        run_test(
            &generate_app_config(0),
            Box::new(|request| detdipc::StreamQosResponse {
                ok: false,
                socket_priority: 5,
                vlan_interface: request.interface.clone() + "." + &request.vid.to_string(),
            }),
        )
        .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Interface returned from NIC setup does not match VLAN interface in configuration!"
    )]
    fn test_not_matching_vlan_interface() {
        run_test(
            &generate_app_config(0),
            Box::new(|_| detdipc::StreamQosResponse {
                ok: true,
                socket_priority: 5,
                vlan_interface: "abc0".to_owned(),
            }),
        )
        .unwrap();
    }
}
