use crate::setting::ProbeSetting;
use crate::fp::FingerprintType;
use std::net::{IpAddr, SocketAddr};
use xenet::packet::ethernet::EtherType;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::packet::tcp::{TcpFlags, TcpOption};
use xenet::util::packet_builder::builder::PacketBuilder;
use xenet::util::packet_builder::ethernet::EthernetPacketBuilder;
use xenet::util::packet_builder::ipv4::Ipv4PacketBuilder;
use xenet::util::packet_builder::ipv6::Ipv6PacketBuilder;
use xenet::util::packet_builder::tcp::TcpPacketBuilder;

pub(crate) const TCP_DEFAULT_SRC_PORT: u16 = 44322;
pub(crate) const TCP_DEFAULT_DST_PORT: u16 = 80;

/// Build TCP packet
pub fn build_tcp_packet(setting: ProbeSetting, hop_limit: Option<u8>) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();

    // Ethernet Header
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: setting.src_mac,
        dst_mac: setting.dst_mac,
        ether_type: match setting.dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    // IP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let mut ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Tcp);
                if let Some(hoplimit) = hop_limit {
                    ipv4_packet_builder.ttl = Some(hoplimit);
                } else {
                    ipv4_packet_builder.ttl = Some(setting.hop_limit);
                }
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv4) => {
                let mut ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Tcp);
                if let Some(hoplimit) = hop_limit {
                    ipv6_packet_builder.hop_limit = Some(hoplimit);
                } else {
                    ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                }
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    // TCP Header
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(
            setting.src_ip,
            setting.src_port.unwrap_or(TCP_DEFAULT_SRC_PORT),
        ),
        SocketAddr::new(
            setting.dst_ip,
            setting.dst_port.unwrap_or(TCP_DEFAULT_DST_PORT),
        ),
    );
    tcp_packet_builder.flags = TcpFlags::SYN;
    tcp_packet_builder.options = vec![
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ];
    packet_builder.set_tcp(tcp_packet_builder);

    if setting.tunnel {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}

/// Build TCP probe packet
pub fn build_tcp_probe_packet(setting: ProbeSetting, probe_type: FingerprintType) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();

    // Ethernet Header
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: setting.src_mac,
        dst_mac: setting.dst_mac,
        ether_type: match setting.dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    // IP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let mut ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Tcp);
                ipv4_packet_builder.ttl = Some(setting.hop_limit);
                ipv4_packet_builder.total_length = Some(64);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv4) => {
                let mut ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Tcp);
                ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                ipv6_packet_builder.payload_length = Some(44);
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    // TCP Header
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(
            setting.src_ip,
            setting.src_port.unwrap_or(TCP_DEFAULT_SRC_PORT),
        ),
        SocketAddr::new(
            setting.dst_ip,
            setting.dst_port.unwrap_or(TCP_DEFAULT_DST_PORT),
        ),
    );
    match probe_type {
        FingerprintType::TcpSynAck => {
            tcp_packet_builder.flags = TcpFlags::SYN;
        }
        FingerprintType::TcpRstAck => {
            tcp_packet_builder.flags = TcpFlags::SYN;
        }
        FingerprintType::TcpEcn => {
            tcp_packet_builder.flags = TcpFlags::CWR | TcpFlags::ECE | TcpFlags::SYN;
        }
        _ => {
            tcp_packet_builder.flags = TcpFlags::SYN;
        }
    }
    tcp_packet_builder.window = 65535;
    tcp_packet_builder.options = vec![
        TcpOption::mss(1460),
        TcpOption::nop(),
        TcpOption::wscale(6),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::timestamp(u32::MAX, u32::MIN),
        TcpOption::sack_perm(),
    ];
    packet_builder.set_tcp(tcp_packet_builder);

    if setting.tunnel {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}

#[allow(dead_code)]
pub fn build_tcp_control_packet(probe_setting: ProbeSetting, tcp_flags: u8) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: probe_setting.src_mac.clone(),
        dst_mac: probe_setting.dst_mac.clone(),
        ether_type: if probe_setting.src_ip.is_ipv4() {
            EtherType::Ipv4
        } else {
            EtherType::Ipv6
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match probe_setting.src_ip {
        IpAddr::V4(src_ipv4) => match probe_setting.dst_ip {
            IpAddr::V4(dst_ipv4) => {
                let ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Tcp);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(src_ipv6) => match probe_setting.dst_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(dst_ipv6) => {
                let ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv6, dst_ipv6, IpNextLevelProtocol::Tcp);
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(
            probe_setting.src_ip,
            probe_setting.src_port.unwrap_or(TCP_DEFAULT_SRC_PORT),
        ),
        SocketAddr::new(
            probe_setting.dst_ip,
            probe_setting.dst_port.unwrap_or(TCP_DEFAULT_DST_PORT),
        ),
    );
    tcp_packet_builder.window = 65535;
    tcp_packet_builder.flags = tcp_flags;
    packet_builder.set_tcp(tcp_packet_builder);
    if probe_setting.tunnel {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}
