use std::net::IpAddr;

use xenet::net::mac::MacAddr;
use xenet::util::packet_builder::builder::PacketBuilder;
use xenet::util::packet_builder::ethernet::EthernetPacketBuilder;
use xenet::util::packet_builder::ipv6::Ipv6PacketBuilder;
use xenet::util::packet_builder::ndp::NdpPacketBuilder;
use xenet::packet::ethernet::EtherType;
use xenet::packet::ethernet::MAC_ADDR_LEN;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::packet::icmpv6::ndp::{NDP_SOL_PACKET_LEN, NDP_OPT_PACKET_LEN};
use crate::setting::ProbeSetting;

pub fn build_ndp_packet(setting: ProbeSetting) -> Vec<u8> {
    // Packet builder for ICMP Echo Request
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: setting.src_mac,
        dst_mac: MacAddr::broadcast(),
        ether_type: EtherType::Ipv6,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    match setting.src_ip {
        IpAddr::V4(_) => {}
        IpAddr::V6(src_ipv6) => {
            match setting.dst_ip {
                IpAddr::V4(_) => {}
                IpAddr::V6(dst_ipv6) => {
                    let mut ipv6_packet_builder = Ipv6PacketBuilder::new(src_ipv6, dst_ipv6, IpNextLevelProtocol::Icmpv6);
                    ipv6_packet_builder.payload_length = Some((NDP_SOL_PACKET_LEN + NDP_OPT_PACKET_LEN + MAC_ADDR_LEN) as u16);
                    ipv6_packet_builder.hop_limit = Some(u8::MAX);
                    packet_builder.set_ipv6(ipv6_packet_builder);

                    let ndp_packet_builder = NdpPacketBuilder::new(setting.src_mac, src_ipv6, dst_ipv6);
                    packet_builder.set_ndp(ndp_packet_builder);
                }
            }
        }
    }
    packet_builder.packet()
}
