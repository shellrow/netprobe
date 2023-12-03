pub mod icmp;
pub mod tcp;
pub mod udp;

use crate::setting::ProbeSetting;
use crate::result::{ProbeResult, PingResult};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use xenet::net::interface::Interface;

/// Pinger structure
///
/// Contains various settings for ping
#[derive(Clone, Debug)]
pub struct Pinger {
    /// Probe Setting
    pub probe_setting: ProbeSetting,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<ProbeResult>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<ProbeResult>>>,
}

impl Pinger {
    /// Create new Pinger instance with destination IP address
    pub fn new(setting: ProbeSetting) -> Result<Pinger, String> {
        let (tx, rx) = channel();
        let pinger = Pinger {
            probe_setting: setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        };
        return Ok(pinger);
    }
    /// Run ping
    pub fn ping(&self) -> Result<PingResult, String> {
        run_ping(&self.probe_setting, &self.tx)
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<ProbeResult>>> {
        self.rx.clone()
    }
}

fn run_ping(setting: &ProbeSetting, msg_tx: &Arc<Mutex<Sender<ProbeResult>>>) -> Result<PingResult, String> {
    let interface: Interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(format!("run_ping: unable to get interface by index {}", setting.if_index)),
    };
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(setting.receive_timeout),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    // Create a channel to send/receive packet
    let (mut tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("run_ping: unable to create channel".to_string()),
        Err(e) => return Err(format!("run_ping: unable to create channel: {}", e)),
    };
    match setting.protocol {
        crate::setting::Protocol::ICMP => {
            let result = icmp::icmp_ping(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        crate::setting::Protocol::TCP => {
            let result = tcp::tcp_ping(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        crate::setting::Protocol::UDP => {
            let result = udp::udp_ping(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
    }
}
