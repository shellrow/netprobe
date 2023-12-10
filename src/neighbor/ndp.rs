use xenet::datalink::{DataLinkSender, DataLinkReceiver};
use xenet::packet::frame::{ParseOption, Frame};
use xenet::packet::icmpv6::Icmpv6Type;
use crate::setting::{ProbeSetting, Protocol};
use crate::result::{ProbeResult, DeviceResolveResult, ProbeStatus, NodeType};
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};

pub(crate) fn run_ndp(tx: &mut Box<dyn DataLinkSender>, rx: &mut Box<dyn DataLinkReceiver>, setting: &ProbeSetting, msg_tx: &Arc<Mutex<Sender<ProbeResult>>>) -> DeviceResolveResult {
    let mut result = DeviceResolveResult::new();
    result.protocol = Protocol::NDP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.use_tun {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    for seq in 1..setting.count + 1 {
        let ndp_packet: Vec<u8> = crate::packet::ndp::build_ndp_packet(setting.clone());
        let send_time = Instant::now();
        match tx.send(&ndp_packet) {
            Some(_) => {},
            None => eprintln!("Failed to send packet"),
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(ethernet_header) = &datalink_layer.ethernet {
                            if let Some(ip_layer) = &frame.ip {
                                // IPv6
                                if let Some(ipv6_header) = &ip_layer.ipv6 {
                                    if IpAddr::V6(ipv6_header.source) != setting.dst_ip {
                                        continue;
                                    }
                                    // ICMPv6
                                    if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                        if icmpv6_header.icmpv6_type == Icmpv6Type::NeighborAdvertisement {
                                            let probe_result: ProbeResult = ProbeResult {
                                                seq: seq,
                                                mac_addr: ethernet_header.source,
                                                ip_addr: setting.dst_ip,
                                                host_name: setting.dst_hostname.clone(),
                                                port_number: None,
                                                port_status: None,
                                                ttl: ipv6_header.hop_limit,
                                                hop: crate::ip::guess_initial_ttl(ipv6_header.hop_limit) - ipv6_header.hop_limit,
                                                rtt: recv_time,
                                                probe_status: ProbeStatus::new(),
                                                protocol: Protocol::NDP,
                                                node_type: NodeType::Destination,
                                                sent_packet_size: ndp_packet.len(),
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
                    }
                },
                Err(e) => {
                    eprintln!("Failed to receive packet: {}", e);
                    let probe_result = ProbeResult::timeout(seq, setting.dst_ip, setting.dst_hostname.clone(), Protocol::NDP, ndp_packet.len());
                    responses.push(probe_result.clone());
                    match msg_tx.lock() {
                        Ok(lr) => match lr.send(probe_result) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                    break;
                },
            }
            let wait_time: Duration = Instant::now().duration_since(send_time);
            if wait_time > setting.receive_timeout {
                let probe_result = ProbeResult::timeout(seq, setting.dst_ip, setting.dst_hostname.clone(), Protocol::NDP, ndp_packet.len());
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
    result.results = responses;
    result.probe_status = ProbeStatus::new();
    result
}
