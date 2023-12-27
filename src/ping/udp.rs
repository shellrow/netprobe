use crate::result::PortStatus;
use crate::result::{NodeType, PingResult, PingStat, ProbeResult, ProbeStatus};
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

pub(crate) fn udp_ping(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    setting: &ProbeSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> PingResult {
    let mut result = PingResult::new();
    result.protocol = Protocol::UDP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.tunnel {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    for seq in 1..setting.count + 1 {
        let udp_packet: Vec<u8> = crate::packet::udp::build_udp_packet(setting.clone(), None);
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
                            if IpAddr::V4(ipv4_header.source) != setting.dst_ip || IpAddr::V4(ipv4_header.destination) != setting.src_ip {
                                continue;
                            }
                            // ICMP
                            if let Some(icmp_header) = &ip_layer.icmp {
                                if icmp_header.icmp_type == IcmpType::DestinationUnreachable {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: mac_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
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
                                    break;
                                }
                            }
                        }
                        // IPv6
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            if IpAddr::V6(ipv6_header.destination) != setting.src_ip {
                                continue;
                            }
                            // ICMPv6
                            if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                if icmpv6_header.icmpv6_type == Icmpv6Type::DestinationUnreachable {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: mac_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
                                        port_number: setting.dst_port,
                                        port_status: Some(PortStatus::Closed),
                                        ttl: ipv6_header.hop_limit,
                                        hop: crate::ip::guess_initial_ttl(ipv6_header.hop_limit)
                                            - ipv6_header.hop_limit,
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
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    let probe_result = ProbeResult::timeout(
                        seq,
                        setting.dst_ip,
                        setting.dst_hostname.clone(),
                        Protocol::UDP,
                        udp_packet.len(),
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
                let probe_result = ProbeResult::timeout(
                    seq,
                    setting.dst_ip,
                    setting.dst_hostname.clone(),
                    Protocol::UDP,
                    udp_packet.len(),
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
        if seq < setting.count {
            std::thread::sleep(setting.send_rate);
        }
    }
    let probe_time = Instant::now().duration_since(start_time);
    result.end_time = crate::sys::get_sysdate();
    result.elapsed_time = probe_time;
    let ping_stat: PingStat = PingStat {
        responses: responses.clone(),
        probe_time: probe_time,
        transmitted_count: setting.count as usize,
        received_count: responses.len(),
        min: responses
            .iter()
            .map(|r| r.rtt)
            .min()
            .unwrap_or(Duration::from_millis(0)),
        avg: responses
            .iter()
            .fold(Duration::from_millis(0), |acc, r| acc + r.rtt)
            / responses.len() as u32,
        max: responses
            .iter()
            .map(|r| r.rtt)
            .max()
            .unwrap_or(Duration::from_millis(0)),
    };
    result.stat = ping_stat;
    result.probe_status = ProbeStatus::new();
    result
}
