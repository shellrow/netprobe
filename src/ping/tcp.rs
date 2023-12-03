use xenet::datalink::{DataLinkSender, DataLinkReceiver};

use crate::setting::ProbeSetting;
use crate::result::{ProbeResult, PingResult};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

pub(crate) fn tcp_ping(tx: &mut Box<dyn DataLinkSender>, rx: &mut Box<dyn DataLinkReceiver>, setting: &ProbeSetting, msg_tx: &Arc<Mutex<Sender<ProbeResult>>>) -> PingResult {
    let mut result = PingResult::new();
    
    result
}
