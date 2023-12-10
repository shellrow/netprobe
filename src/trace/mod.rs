pub(crate) mod udp;

use crate::result::{ProbeResult, TracerouteResult};
use crate::setting::ProbeSetting;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use xenet::net::interface::Interface;

/// Tracer structure.
///
/// Supports UDP Traceroute.
#[derive(Clone, Debug)]
pub struct Tracer {
    /// Probe Setting
    pub probe_setting: ProbeSetting,
    /// Sender for progress messaging
    tx: Arc<Mutex<Sender<ProbeResult>>>,
    /// Receiver for progress messaging
    rx: Arc<Mutex<Receiver<ProbeResult>>>,
}

impl Tracer {
    /// Create new Tracer instance with setting
    pub fn new(setting: ProbeSetting) -> Result<Tracer, String> {
        // Check interface
        if crate::interface::get_interface_by_index(setting.if_index).is_none() {
            if crate::interface::get_interface_by_name(setting.if_name.clone()).is_none() {
                return Err(format!(
                    "Tracer::new: unable to get interface. index: {}, name: {}",
                    setting.if_index, setting.if_name
                ));
            }
        }
        let (tx, rx) = channel();
        let tracer = Tracer {
            probe_setting: setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        };
        return Ok(tracer);
    }
    /// Run traceroute
    pub fn trace(&self) -> Result<TracerouteResult, String> {
        run_traceroute(&self.probe_setting, &self.tx)
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<ProbeResult>>> {
        self.rx.clone()
    }
}

fn run_traceroute(
    setting: &ProbeSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> Result<TracerouteResult, String> {
    let interface: Interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => {
            return Err(format!(
                "run_traceroute: unable to get interface by index {}",
                setting.if_index
            ))
        }
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
        Ok(_) => return Err("run_traceroute: unable to create channel".to_string()),
        Err(e) => return Err(format!("run_traceroute: unable to create channel: {}", e)),
    };
    match setting.protocol {
        crate::setting::Protocol::ICMP => Err("ICMP traceroute is not supported".to_string()),
        crate::setting::Protocol::TCP => Err("TCP traceroute is not supported".to_string()),
        crate::setting::Protocol::UDP => {
            let result = udp::udp_trace(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        _ => {
            return Err("run_ping: unsupported protocol".to_string());
        }
    }
}
