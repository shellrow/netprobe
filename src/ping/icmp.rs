use xenet::datalink::{DataLinkSender, DataLinkReceiver};
use xenet::packet::frame::{ParseOption, Frame};
use xenet::packet::icmp::IcmpType;
use xenet::packet::icmpv6::Icmpv6Type;
use crate::setting::{ProbeSetting, Protocol};
use crate::result::{ProbeResult, PingResult, ProbeStatus, NodeType, PingStat};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};

pub(crate) fn icmp_ping(tx: &mut Box<dyn DataLinkSender>, rx: &mut Box<dyn DataLinkReceiver>, setting: &ProbeSetting, msg_tx: &Arc<Mutex<Sender<ProbeResult>>>) -> PingResult {
    let mut result = PingResult::new();
    result.protocol = Protocol::ICMP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.use_tun {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::get_sysdate();
    let start_time = Instant::now();
    let mut probe_time = Duration::from_millis(0);
    let mut responses: Vec<ProbeResult> = Vec::new();
    for seq in 1..setting.count + 1 {
        let icmp_packet: Vec<u8> = crate::packet::icmp::build_icmp_packet(setting.clone(), None);
        let send_time = Instant::now();
        match tx.send(&icmp_packet) {
            Some(_) => {},
            None => eprintln!("Failed to send packet"),
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    if let Some(ip_layer) = &frame.ip {
                        // IPv4 ICMP
                        if let Some(icmp_header) = &ip_layer.icmp {
                            if icmp_header.icmp_type == IcmpType::EchoReply {
                                let ttl = ip_layer.ipv4.as_ref().unwrap().ttl;
                                let probe_result: ProbeResult = ProbeResult {
                                    seq: seq,
                                    ip_addr: setting.dst_ip,
                                    host_name: setting.dst_hostname.clone(),
                                    port_number: None,
                                    port_status: None,
                                    ttl: ttl,
                                    hop: crate::ip::guess_initial_ttl(ttl) - ttl,
                                    rtt: recv_time,
                                    probe_status: ProbeStatus::new(),
                                    protocol: Protocol::ICMP,
                                    node_type: NodeType::Destination,
                                    sent_packet_size: icmp_packet.len(),
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
                            }
                        }
                        // IPv6 ICMP (ICMPv6)
                        if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                            if icmpv6_header.icmpv6_type == Icmpv6Type::EchoReply {
                                let ttl = ip_layer.ipv6.as_ref().unwrap().hop_limit;
                                let probe_result: ProbeResult = ProbeResult {
                                    seq: seq,
                                    ip_addr: setting.dst_ip,
                                    host_name: setting.dst_hostname.clone(),
                                    port_number: None,
                                    port_status: None,
                                    ttl: ttl,
                                    hop: crate::ip::guess_initial_ttl(ttl) - ttl,
                                    rtt: recv_time,
                                    probe_status: ProbeStatus::new(),
                                    protocol: Protocol::ICMP,
                                    node_type: NodeType::Destination,
                                    sent_packet_size: icmp_packet.len(),
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
                            }
                        }
                    }
                },
                Err(e) => eprintln!("Failed to receive packet: {}", e),
            }
            probe_time = Instant::now().duration_since(start_time);
            if probe_time > setting.probe_timeout {
                result.probe_status = ProbeStatus::with_timeout_message(format!("Request timeout for icmp_seq {}", seq));
                return result;
            }
        }
    }
    result.end_time = crate::sys::get_sysdate();
    result.elapsed_time = Instant::now().duration_since(start_time);
    let ping_stat: PingStat = PingStat {
        responses: responses.clone(),
        probe_time: probe_time,
        transmitted_count: setting.count as usize,
        received_count: responses.len(),
        min: responses.iter().map(|r| r.rtt).min().unwrap_or(Duration::from_millis(0)),
        avg: responses.iter().fold(Duration::from_millis(0), |acc, r| acc + r.rtt) / responses.len() as u32,
        max: responses.iter().map(|r| r.rtt).max().unwrap_or(Duration::from_millis(0)),
    };
    result.stat = ping_stat;
    result.probe_status = ProbeStatus::new();
    result
}
