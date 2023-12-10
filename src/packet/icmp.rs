use crate::setting::ProbeSetting;
use std::net::IpAddr;
use xenet::packet::ethernet::EtherType;
use xenet::packet::icmp::IcmpType;
use xenet::packet::icmpv6::Icmpv6Type;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::util::packet_builder::builder::PacketBuilder;
use xenet::util::packet_builder::ethernet::EthernetPacketBuilder;
use xenet::util::packet_builder::icmp::IcmpPacketBuilder;
use xenet::util::packet_builder::icmpv6::Icmpv6PacketBuilder;
use xenet::util::packet_builder::ipv4::Ipv4PacketBuilder;
use xenet::util::packet_builder::ipv6::Ipv6PacketBuilder;

/// Build ICMP packet
pub fn build_icmp_packet(setting: ProbeSetting, hop_limit: Option<u8>) -> Vec<u8> {
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
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Icmp);
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
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Icmpv6);
                if let Some(hoplimit) = hop_limit {
                    ipv6_packet_builder.hop_limit = Some(hoplimit);
                } else {
                    ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                }
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    // ICMP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let mut icmp_packet_builder = IcmpPacketBuilder::new(src_ipv4, dst_ipv4);
                icmp_packet_builder.icmp_type = IcmpType::EchoRequest;
                packet_builder.set_icmp(icmp_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv6) => {
                let mut icmpv6_packet_builder = Icmpv6PacketBuilder::new(src_ipv6, dst_ipv6);
                icmpv6_packet_builder.icmpv6_type = Icmpv6Type::EchoRequest;
                packet_builder.set_icmpv6(icmpv6_packet_builder);
            }
        },
    }
    if setting.use_tun {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}
