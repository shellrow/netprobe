use xenet::datalink::{DataLinkSender, DataLinkReceiver};

use crate::setting::ProbeSetting;
use crate::result::{ProbeResult, TracerouteResult};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

fn udp_trace(channel: (&mut Box<dyn DataLinkSender>, &mut Box<dyn DataLinkReceiver>), setting: &ProbeSetting, msg_tx: &Arc<Mutex<Sender<ProbeResult>>>) -> TracerouteResult {
    let mut result = TracerouteResult::new();
    
    result
}
