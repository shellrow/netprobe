pub mod icmp;
pub mod tcp;
pub mod udp;

use crate::setting::ProbeSetting;
use crate::result::{ProbeResult, PingResult};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

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

fn run_ping(setting: &ProbeSetting, tx: &Arc<Mutex<Sender<ProbeResult>>>) -> Result<PingResult, String> {
    return Ok(PingResult::new());
}
