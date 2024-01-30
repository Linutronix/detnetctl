// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration;
use crate::queue_setup::{QueueSetup, QueueSetupResponse};
use anyhow::{anyhow, Context, Result};
use options_struct_derive::validate_are_some;
use prost::Message;
use std::path::{Path, PathBuf};

#[allow(unreachable_pub)] // this is generated code
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
    fn apply_config(&self, config: &configuration::AppConfig) -> Result<QueueSetupResponse> {
        validate_are_some!(
            config,
            logical_interface,
            physical_interface,
            period_ns,
            offset_ns,
            size_bytes,
            stream,
            pcp
        )?;

        let stream = config.stream()?;
        validate_are_some!(stream, destination_address, vid)?;

        if *config.offset_ns()? > *config.period_ns()? {
            return Err(anyhow!("Not possible to setup if offset > period!"));
        }
        let socket = UnixDatagram::bind(self.local_socket_path.as_path())
            .context("Failed to bind to local UNIX socket")?;
        socket
            .connect(self.remote_socket_path.as_path())
            .context("Failed to connect to detd")?;

        let request = detdipc::StreamQosRequest {
            period: *config.period_ns()?,
            size: *config.size_bytes()?,
            interface: config.physical_interface()?.clone(),
            dmac: stream.destination_address()?.to_hex_string(),
            vid: u32::from(*stream.vid()?),
            pcp: u32::from(*config.pcp()?),
            txmin: *config.offset_ns()?,

            // currently unused by detd (https://github.com/Avnu/detd/blob/e94346dfe9bd595f601ba02f27b12db79339bf88/detd/service.py#L228)
            txmax: *config.offset_ns()?,

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
            return Err(anyhow!(
                "Setup of queues via detd not possible! See /var/log/detd.log"
            ));
        }

        if &response.vlan_interface != config.logical_interface()? {
            return Err(anyhow!(
                "Interface returned from NIC setup does not match VLAN interface in configuration!"
            ));
        }

        Ok(QueueSetupResponse {
            logical_interface: response.vlan_interface,
            priority: response.socket_priority,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AppConfigBuilder, StreamIdentificationBuilder};
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;
    use std::time::Duration;

    fn run_test(
        app_config: &configuration::AppConfig,
        mut response: Box<
            dyn FnMut(&detdipc::StreamQosRequest) -> detdipc::StreamQosResponse + Send,
        >,
    ) -> Result<QueueSetupResponse> {
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

        drop(detddummy.join());

        result
    }

    fn generate_app_config(offset: u32) -> configuration::AppConfig {
        AppConfigBuilder::new()
            .logical_interface("eth0.3".to_owned())
            .physical_interface("eth0".to_owned())
            .period_ns(1000 * 100)
            .offset_ns(offset)
            .size_bytes(1000)
            .stream(
                StreamIdentificationBuilder::new()
                    .destination_address("8a:de:82:a1:59:5a".parse().unwrap())
                    .vid(3)
                    .build(),
            )
            .pcp(4)
            .addresses(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)])
            .build()
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
    #[should_panic(expected = "Setup of queues via detd not possible!")]
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
