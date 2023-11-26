use xenet::net::mac::MacAddr;
use xenet::packet::ip::IpNextLevelProtocol;
use std::time::Duration;
use std::net::IpAddr;

//#[cfg(feature = "serde")]
//use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
//#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProbeSetting {
    pub if_index: u32,
    pub if_name: String,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_hostname: String,
    pub dst_port: u16,
    pub hop_limit: u8,
    pub count: u8,
    pub protocol: IpNextLevelProtocol,
    pub receive_timeout: Duration,
    pub probe_timeout: Duration,
    pub send_rate: Duration,
}
