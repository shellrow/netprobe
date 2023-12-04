use std::net::IpAddr;

use xenet::net::interface::Interface;
use xenet::net::mac::MacAddr;

pub(crate) fn get_interface_by_index(index: u32) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        if iface.index == index {
            return Some(iface);
        }
    }
    return None;
}

pub(crate) fn get_interface_by_name(name: String) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        if iface.name == name {
            return Some(iface);
        }
    }
    return None;
}

pub(crate) fn get_interface_ipv4(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv4.clone() {
        return Some(IpAddr::V4(ip.addr));
    }
    return None;
}

pub(crate) fn get_interface_global_ipv6(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv6.clone() {
        if xenet::net::ipnet::is_global_ipv6(&ip.addr) {
            return Some(IpAddr::V6(ip.addr));
        }
    }
    return None;
}

pub(crate) fn get_interface_local_ipv6(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv6.clone() {
        if !xenet::net::ipnet::is_global_ipv6(&ip.addr) {
            return Some(IpAddr::V6(ip.addr));
        }
    }
    return None;
}

pub(crate) fn get_interface_macaddr(iface: &Interface) -> MacAddr {
    match &iface.mac_addr {
        Some(mac_addr) => mac_addr.clone(),
        None => MacAddr::zero(),
    }
}

pub(crate) fn get_gateway_macaddr(iface: &Interface) -> MacAddr {
    match &iface.gateway {
        Some(gateway) => gateway.mac_addr.clone(),
        None => MacAddr::zero(),
    }
}
