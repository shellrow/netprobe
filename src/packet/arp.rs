use std::net::IpAddr;

use xenet::net::mac::MacAddr;
use xenet::util::packet_builder::builder::PacketBuilder;
use xenet::util::packet_builder::ethernet::EthernetPacketBuilder;
use xenet::util::packet_builder::arp::ArpPacketBuilder;
use xenet::packet::ethernet::EtherType;

use crate::setting::ProbeSetting;

/// Build ARP packet
pub fn build_arp_packet(setting: ProbeSetting) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    // Ethernet Header
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: setting.src_mac,
        dst_mac: MacAddr::broadcast(),
        ether_type: EtherType::Arp,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match setting.src_ip {
        IpAddr::V4(src_ipv4) => {
            match setting.dst_ip {
                IpAddr::V4(dst_ipv4) => {
                    // ARP Header
                    let arp_packet = ArpPacketBuilder {
                        src_mac: setting.src_mac,
                        dst_mac: MacAddr::broadcast(),
                        src_ip: src_ipv4,
                        dst_ip: dst_ipv4,
                    };
                    packet_builder.set_arp(arp_packet);
                }
                IpAddr::V6(_) => {}
            }
        }
        IpAddr::V6(_) => {}
    }
    packet_builder.packet()
}
