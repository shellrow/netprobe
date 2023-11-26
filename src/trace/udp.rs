use xenet::datalink::{DataLinkSender, DataLinkReceiver};

use crate::setting::ProbeSetting;

fn udp_trace(channel: (&mut Box<dyn DataLinkSender>, &mut Box<dyn DataLinkReceiver>), setting: &ProbeSetting, seq: u8) {
    
}
