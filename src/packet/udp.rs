use crate::setting::ProbeSetting;
use std::net::{IpAddr, SocketAddr};
use xenet::packet::ethernet::EtherType;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::util::packet_builder::builder::PacketBuilder;
use xenet::util::packet_builder::ethernet::EthernetPacketBuilder;
use xenet::util::packet_builder::ipv4::Ipv4PacketBuilder;
use xenet::util::packet_builder::ipv6::Ipv6PacketBuilder;
use xenet::util::packet_builder::udp::UdpPacketBuilder;

pub(crate) const UDP_DEFAULT_SRC_PORT: u16 = 53445;
pub(crate) const UDP_BASE_DST_PORT: u16 = 33435;

/// Build UDP packet
pub fn build_udp_packet(setting: ProbeSetting, hop_limit: Option<u8>) -> Vec<u8> {
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
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Udp);
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
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Udp);
                if let Some(hoplimit) = hop_limit {
                    ipv6_packet_builder.hop_limit = Some(hoplimit);
                } else {
                    ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                }
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    // UDP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(
                        IpAddr::V4(src_ipv4),
                        setting.src_port.unwrap_or(UDP_DEFAULT_SRC_PORT),
                    ),
                    SocketAddr::new(
                        IpAddr::V4(dst_ipv4),
                        setting.dst_port.unwrap_or(UDP_BASE_DST_PORT),
                    ),
                );
                packet_builder.set_udp(udp_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv6) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(
                        IpAddr::V6(src_ipv6),
                        setting.src_port.unwrap_or(UDP_DEFAULT_SRC_PORT),
                    ),
                    SocketAddr::new(
                        IpAddr::V6(dst_ipv6),
                        setting.dst_port.unwrap_or(UDP_BASE_DST_PORT),
                    ),
                );
                packet_builder.set_udp(udp_packet_builder);
            }
        },
    }
    if setting.tunnel {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}

/// Build UDP probe packet
pub fn build_udp_probe_packet(setting: ProbeSetting) -> Vec<u8> {
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
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Udp);
                ipv4_packet_builder.ttl = Some(setting.hop_limit);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv4) => {
                let mut ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Udp);
                ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    // UDP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(
                        IpAddr::V4(src_ipv4),
                        setting.src_port.unwrap_or(UDP_DEFAULT_SRC_PORT),
                    ),
                    SocketAddr::new(
                        IpAddr::V4(dst_ipv4),
                        setting.dst_port.unwrap_or(UDP_BASE_DST_PORT),
                    ),
                );
                packet_builder.set_udp(udp_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv6) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(
                        IpAddr::V6(src_ipv6),
                        setting.src_port.unwrap_or(UDP_DEFAULT_SRC_PORT),
                    ),
                    SocketAddr::new(
                        IpAddr::V6(dst_ipv6),
                        setting.dst_port.unwrap_or(UDP_BASE_DST_PORT),
                    ),
                );
                packet_builder.set_udp(udp_packet_builder);
            }
        },
    }
    if setting.tunnel {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}
