use xenet::datalink::{DataLinkSender, DataLinkReceiver};

use crate::{setting::ProbeSetting, result::TracerouteResult};

fn udp_trace(channel: (&mut Box<dyn DataLinkSender>, &mut Box<dyn DataLinkReceiver>), setting: &ProbeSetting) -> TracerouteResult {
    let mut result = TracerouteResult::new();
    
    result
}
