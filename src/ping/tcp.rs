use xenet::datalink::{DataLinkSender, DataLinkReceiver};

use crate::setting::ProbeSetting;
use crate::result::PingResult;

fn tcp_ping(channel: (&mut Box<dyn DataLinkSender>, &mut Box<dyn DataLinkReceiver>), setting: &ProbeSetting) -> PingResult {
    let mut result = PingResult::new();
    
    result
}
