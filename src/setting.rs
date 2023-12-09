pub use xenet::net::mac::MacAddr;
use std::time::Duration;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use crate::dns::{lookup_host_name, lookup_ip_addr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The protocol to use for the probe
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProbeSetting {
    pub if_index: u32,
    pub if_name: String,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_ip: IpAddr,
    pub dst_hostname: String,
    pub dst_port: Option<u16>,
    pub hop_limit: u8,
    pub count: u8,
    pub protocol: Protocol,
    pub receive_timeout: Duration,
    pub probe_timeout: Duration,
    pub send_rate: Duration,
    pub use_tun: bool,
    pub loopback: bool,
}

impl ProbeSetting {
    pub fn new() -> ProbeSetting {
        ProbeSetting {
            if_index: 0,
            if_name: String::new(),
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: None,
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_hostname: String::new(),
            dst_port: None,
            hop_limit: 64,
            count: 4,
            protocol: Protocol::ICMP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            use_tun: false,
            loopback: false,
        }
    }
    pub fn with_if_index(mut self, if_index: u32) -> ProbeSetting {
        self.if_index = if_index;
        self
    }
    pub fn with_if_name(mut self, if_name: String) -> ProbeSetting {
        self.if_name = if_name;
        self
    }
    pub fn with_dst_hostname(mut self, dst_hostname: String) -> ProbeSetting {
        self.dst_hostname = dst_hostname.clone();
        if let Some(ip) = lookup_host_name(dst_hostname) {
            self.dst_ip = ip;
        }
        self
    }
    pub fn with_dst_ip(mut self, dst_ip: IpAddr) -> ProbeSetting {
        self.dst_ip = dst_ip.clone();
        if let Some(hostname) = lookup_ip_addr(dst_ip) {
            self.dst_hostname = hostname;
        }
        self
    }
    pub fn with_dst_port(mut self, dst_port: u16) -> ProbeSetting {
        self.dst_port = Some(dst_port);
        self
    }
    pub fn with_protocol(mut self, protocol: Protocol) -> ProbeSetting {
        self.protocol = protocol;
        self
    }
    pub fn with_count(mut self, count: u8) -> ProbeSetting {
        self.count = count;
        self
    }
    pub fn with_hop_limit(mut self, hop_limit: u8) -> ProbeSetting {
        self.hop_limit = hop_limit;
        self
    }
    pub fn with_receive_timeout(mut self, receive_timeout: Duration) -> ProbeSetting {
        self.receive_timeout = receive_timeout;
        self
    }
    pub fn with_probe_timeout(mut self, probe_timeout: Duration) -> ProbeSetting {
        self.probe_timeout = probe_timeout;
        self
    }
    pub fn with_send_rate(mut self, send_rate: Duration) -> ProbeSetting {
        self.send_rate = send_rate;
        self
    }
    pub fn with_use_tun(mut self, use_tun: bool) -> ProbeSetting {
        self.use_tun = use_tun;
        self
    }
    pub fn with_loopback(mut self, loopback: bool) -> ProbeSetting {
        self.loopback = loopback;
        self
    }
    pub fn icmp_ping_default(dst_ip_addr: IpAddr, count: u8) -> Result<ProbeSetting, String> {
        let default_interface = xenet::net::interface::get_default_interface()?;
        let src_ip: IpAddr = match dst_ip_addr {
            IpAddr::V4(_) => {
                match crate::interface::get_interface_ipv4(&default_interface) {
                    Some(ip) => ip,
                    None => {
                        return Err(String::from(
                            "IPv4 address not found on default interface.",
                        ))
                    }
                }
            }
            IpAddr::V6(ipv6_addr) => {
                if xenet::net::ipnet::is_global_ipv6(&ipv6_addr) {
                    match crate::interface::get_interface_global_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Global IPv6 address not found on default interface.",
                            ))
                        }
                    }
                } else {
                    match crate::interface::get_interface_local_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Local IPv6 address not found on default interface.",
                            ))
                        }
                    }
                }
            }
        };
        let use_tun = default_interface.is_tun();
        let loopback = default_interface.is_loopback();
        
        let setting = ProbeSetting {
            if_index: default_interface.index,
            if_name: default_interface.name.clone(),
            src_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_interface_macaddr(&default_interface) },
            dst_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_gateway_macaddr(&default_interface) },
            src_ip: src_ip,
            src_port: None,
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: None,
            hop_limit: 64,
            count: count,
            protocol: Protocol::ICMP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            use_tun: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
    pub fn tcp_ping_default(dst_ip_addr: IpAddr, dst_port:u16, count: u8) -> Result<ProbeSetting, String> {
        let default_interface = xenet::net::interface::get_default_interface()?;
        let src_ip: IpAddr = match dst_ip_addr {
            IpAddr::V4(_) => {
                match crate::interface::get_interface_ipv4(&default_interface) {
                    Some(ip) => ip,
                    None => {
                        return Err(String::from(
                            "IPv4 address not found on default interface.",
                        ))
                    }
                }
            }
            IpAddr::V6(ipv6_addr) => {
                if xenet::net::ipnet::is_global_ipv6(&ipv6_addr) {
                    match crate::interface::get_interface_global_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Global IPv6 address not found on default interface.",
                            ))
                        }
                    }
                } else {
                    match crate::interface::get_interface_local_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Local IPv6 address not found on default interface.",
                            ))
                        }
                    }
                }
            }
        };
        let use_tun = default_interface.is_tun();
        let loopback = default_interface.is_loopback();
        
        let setting = ProbeSetting {
            if_index: default_interface.index,
            if_name: default_interface.name.clone(),
            src_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_interface_macaddr(&default_interface) },
            dst_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_gateway_macaddr(&default_interface) },
            src_ip: src_ip,
            src_port: Some(crate::packet::tcp::TCP_DEFAULT_SRC_PORT),
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: Some(dst_port),
            hop_limit: 64,
            count: count,
            protocol: Protocol::TCP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            use_tun: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
    pub fn udp_ping_default(dst_ip_addr: IpAddr, count: u8) -> Result<ProbeSetting, String> {
        let default_interface = xenet::net::interface::get_default_interface()?;
        let src_ip: IpAddr = match dst_ip_addr {
            IpAddr::V4(_) => {
                match crate::interface::get_interface_ipv4(&default_interface) {
                    Some(ip) => ip,
                    None => {
                        return Err(String::from(
                            "IPv4 address not found on default interface.",
                        ))
                    }
                }
            }
            IpAddr::V6(ipv6_addr) => {
                if xenet::net::ipnet::is_global_ipv6(&ipv6_addr) {
                    match crate::interface::get_interface_global_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Global IPv6 address not found on default interface.",
                            ))
                        }
                    }
                } else {
                    match crate::interface::get_interface_local_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Local IPv6 address not found on default interface.",
                            ))
                        }
                    }
                }
            }
        };
        let use_tun = default_interface.is_tun();
        let loopback = default_interface.is_loopback();
        
        let setting = ProbeSetting {
            if_index: default_interface.index,
            if_name: default_interface.name.clone(),
            src_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_interface_macaddr(&default_interface) },
            dst_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_gateway_macaddr(&default_interface) },
            src_ip: src_ip,
            src_port: Some(crate::packet::udp::UDP_DEFAULT_SRC_PORT),
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: Some(crate::packet::udp::UDP_BASE_DST_PORT),
            hop_limit: 64,
            count: count,
            protocol: Protocol::UDP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            use_tun: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
    pub fn udp_trace_default(dst_ip_addr: IpAddr, count: u8) -> Result<ProbeSetting, String> {
        let default_interface = xenet::net::interface::get_default_interface()?;
        let src_ip: IpAddr = match dst_ip_addr {
            IpAddr::V4(_) => {
                match crate::interface::get_interface_ipv4(&default_interface) {
                    Some(ip) => ip,
                    None => {
                        return Err(String::from(
                            "IPv4 address not found on default interface.",
                        ))
                    }
                }
            }
            IpAddr::V6(ipv6_addr) => {
                if xenet::net::ipnet::is_global_ipv6(&ipv6_addr) {
                    match crate::interface::get_interface_global_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Global IPv6 address not found on default interface.",
                            ))
                        }
                    }
                } else {
                    match crate::interface::get_interface_local_ipv6(&default_interface) {
                        Some(ip) => ip,
                        None => {
                            return Err(String::from(
                                "Local IPv6 address not found on default interface.",
                            ))
                        }
                    }
                }
            }
        };
        let use_tun = default_interface.is_tun();
        let loopback = default_interface.is_loopback();
        
        let setting = ProbeSetting {
            if_index: default_interface.index,
            if_name: default_interface.name.clone(),
            src_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_interface_macaddr(&default_interface) },
            dst_mac: if use_tun { MacAddr::zero() } else { crate::interface::get_gateway_macaddr(&default_interface) },
            src_ip: src_ip,
            src_port: Some(crate::packet::udp::UDP_DEFAULT_SRC_PORT),
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: Some(crate::packet::udp::UDP_BASE_DST_PORT),
            hop_limit: 64,
            count: count,
            protocol: Protocol::UDP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            use_tun: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
}
