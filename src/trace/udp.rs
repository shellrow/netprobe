use crate::result::PortStatus;
use crate::result::{NodeType, ProbeResult, ProbeStatus, TracerouteResult};
use crate::setting::{ProbeSetting, Protocol};
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xenet::datalink::{DataLinkReceiver, DataLinkSender};
use xenet::net::mac::MacAddr;
use xenet::packet::frame::{Frame, ParseOption};
use xenet::packet::icmp::IcmpType;
use xenet::packet::icmpv6::Icmpv6Type;

pub(crate) fn udp_trace(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    setting: &ProbeSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> TracerouteResult {
    let mut result = TracerouteResult::new();
    result.protocol = Protocol::UDP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.use_tun {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    let mut dst_reached: bool = false;
    for seq_ttl in 1..setting.hop_limit {
        let udp_packet: Vec<u8> =
            crate::packet::udp::build_udp_packet(setting.clone(), Some(seq_ttl));
        let send_time = Instant::now();
        match tx.send(&udp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    let mut mac_addr: MacAddr = MacAddr::zero();
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(ethernet_header) = &datalink_layer.ethernet {
                            mac_addr = ethernet_header.source;
                        }
                    }
                    if let Some(ip_layer) = &frame.ip {
                        // IPv4
                        if let Some(ipv4_header) = &ip_layer.ipv4 {
                            // ICMP
                            if let Some(icmp_header) = &ip_layer.icmp {
                                match icmp_header.icmp_type {
                                    IcmpType::TimeExceeded => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V4(ipv4_header.source),
                                            host_name: ipv4_header.source.to_string(),
                                            port_number: None,
                                            port_status: None,
                                            ttl: ipv4_header.ttl,
                                            hop: crate::ip::guess_initial_ttl(ipv4_header.ttl)
                                                - ipv4_header.ttl,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: if seq_ttl == 1 {
                                                NodeType::DefaultGateway
                                            } else {
                                                NodeType::Relay
                                            },
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        break;
                                    }
                                    IcmpType::DestinationUnreachable => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V4(ipv4_header.source),
                                            host_name: ipv4_header.source.to_string(),
                                            port_number: setting.dst_port,
                                            port_status: Some(PortStatus::Closed),
                                            ttl: ipv4_header.ttl,
                                            hop: crate::ip::guess_initial_ttl(ipv4_header.ttl)
                                                - ipv4_header.ttl,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: NodeType::Destination,
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        dst_reached = true;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        // IPv6
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            // ICMPv6
                            if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                match icmpv6_header.icmpv6_type {
                                    Icmpv6Type::TimeExceeded => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V6(ipv6_header.source),
                                            host_name: ipv6_header.source.to_string(),
                                            port_number: None,
                                            port_status: None,
                                            ttl: ipv6_header.hop_limit,
                                            hop: crate::ip::guess_initial_ttl(
                                                ipv6_header.hop_limit,
                                            ) - ipv6_header.hop_limit,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: if seq_ttl == 1 {
                                                NodeType::DefaultGateway
                                            } else {
                                                NodeType::Relay
                                            },
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        break;
                                    }
                                    Icmpv6Type::DestinationUnreachable => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V6(ipv6_header.source),
                                            host_name: ipv6_header.source.to_string(),
                                            port_number: setting.dst_port,
                                            port_status: Some(PortStatus::Closed),
                                            ttl: ipv6_header.hop_limit,
                                            hop: crate::ip::guess_initial_ttl(
                                                ipv6_header.hop_limit,
                                            ) - ipv6_header.hop_limit,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: NodeType::Destination,
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        dst_reached = true;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    let probe_result = ProbeResult::trace_timeout(
                        seq_ttl,
                        Protocol::UDP,
                        udp_packet.len(),
                        NodeType::Relay,
                    );
                    responses.push(probe_result.clone());
                    match msg_tx.lock() {
                        Ok(lr) => match lr.send(probe_result) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                    break;
                }
            }
            let wait_time: Duration = Instant::now().duration_since(send_time);
            if wait_time > setting.receive_timeout {
                let probe_result = ProbeResult::trace_timeout(
                    seq_ttl,
                    Protocol::UDP,
                    udp_packet.len(),
                    NodeType::Relay,
                );
                responses.push(probe_result.clone());
                match msg_tx.lock() {
                    Ok(lr) => match lr.send(probe_result) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
                break;
            }
        }
        if dst_reached {
            break;
        }
        if seq_ttl < setting.hop_limit {
            std::thread::sleep(setting.send_rate);
        }
    }
    let probe_time = Instant::now().duration_since(start_time);
    result.end_time = crate::sys::get_sysdate();
    result.elapsed_time = probe_time;
    result.nodes = responses;
    result.probe_status = ProbeStatus::new();
    result
}
