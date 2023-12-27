use crate::result::{DeviceResolveResult, NodeType, ProbeResult, ProbeStatus};
use crate::setting::{ProbeSetting, Protocol};
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xenet::datalink::{DataLinkReceiver, DataLinkSender};
use xenet::packet::arp::ArpOperation;
use xenet::packet::frame::{Frame, ParseOption};

pub(crate) fn run_arp(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    setting: &ProbeSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> DeviceResolveResult {
    let mut result = DeviceResolveResult::new();
    result.protocol = Protocol::ARP;
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
        let arp_packet: Vec<u8> = crate::packet::arp::build_arp_packet(setting.clone());
        let send_time = Instant::now();
        match tx.send(&arp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(_ethernet_header) = &datalink_layer.ethernet {
                            if let Some(ip_layer) = &frame.ip {
                                if let Some(ipv4_header) = &ip_layer.ipv4 {
                                    if IpAddr::V4(ipv4_header.source) != setting.dst_ip || IpAddr::V4(ipv4_header.destination) != setting.src_ip {
                                        continue;
                                    }
                                }
                            }
                            // ARP
                            if let Some(arp_header) = &datalink_layer.arp {
                                if arp_header.operation == ArpOperation::Reply {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: arp_header.sender_hw_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
                                        port_number: None,
                                        port_status: None,
                                        ttl: 0,
                                        hop: 0,
                                        rtt: recv_time,
                                        probe_status: ProbeStatus::new(),
                                        protocol: Protocol::ARP,
                                        node_type: NodeType::Destination,
                                        sent_packet_size: arp_packet.len(),
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
                        Protocol::ARP,
                        arp_packet.len(),
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
                    Protocol::ARP,
                    arp_packet.len(),
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
    result.results = responses;
    result.probe_status = ProbeStatus::new();
    result
}
