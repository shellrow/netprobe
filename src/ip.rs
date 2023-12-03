use std::net::IpAddr;

pub fn is_global_addr(ip_addr: IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ipv4) => xenet::net::ipnet::is_global_ipv4(&ipv4),
        IpAddr::V6(ipv6) => xenet::net::ipnet::is_global_ipv6(&ipv6),
    }
}

pub(crate) fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    } else if 64 < ttl && ttl <= 128 {
        128
    } else {
        255
    }
}
