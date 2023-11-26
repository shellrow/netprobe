use xenet::datalink::{DataLinkSender, DataLinkReceiver};

use crate::setting::ProbeSetting;

fn tcp_ping(channel: (&mut Box<dyn DataLinkSender>, &mut Box<dyn DataLinkReceiver>), setting: &ProbeSetting, seq: u8) {
    
}
