use std::{time::{Instant, Duration}, net::IpAddr};

use crate::setting::{ProbeSetting, Protocol};
use crate::result::ProbeStatus;
use default_net::Interface;
use xenet::packet::{frame::{Frame, ParseOption}, icmp, icmpv6, tcp::TcpFlags};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Probes for ICMP fingerprinting
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum  FingerprintType {
    IcmpEcho,
    IcmpTimestamp,
    IcmpAddressMask,
    IcmpInformation,
    IcmpUnreachable,
    TcpSynAck,
    TcpRstAck,
    TcpEcn,
}

impl FingerprintType {
    pub fn protocol(&self) -> Protocol {
        match self {
            FingerprintType::IcmpEcho => Protocol::ICMP,
            FingerprintType::IcmpTimestamp => Protocol::ICMP,
            FingerprintType::IcmpAddressMask => Protocol::ICMP,
            FingerprintType::IcmpInformation => Protocol::ICMP,
            FingerprintType::IcmpUnreachable => Protocol::UDP,
            FingerprintType::TcpSynAck => Protocol::TCP,
            FingerprintType::TcpRstAck => Protocol::TCP,
            FingerprintType::TcpEcn => Protocol::TCP,
        }
    }
}

/// Result of fingerprinting
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Fingerprint {
    pub probe_status: ProbeStatus,
    pub rtt: Duration,
    pub packet_frame: Option<Frame>,
}

/// Struct for fingerprint probe
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Fingerprinter {
    /// Probe setting
    pub probe_setting: ProbeSetting,
    /// ProbeType
    pub probe_type: FingerprintType,
    // Result of fingerprinting
    pub fingerprint: Fingerprint,
}

impl Fingerprinter {
    /// Create new Fingerprinter instance
    pub fn new(setting: ProbeSetting, probe_type: FingerprintType) -> Fingerprinter {
        Fingerprinter {
            probe_setting: setting,
            probe_type: probe_type,
            fingerprint: Fingerprint {
                probe_status: ProbeStatus::new(),
                rtt: Duration::new(0, 0),
                packet_frame: None,
            },
        }
    }
    pub fn run_probe(&mut self) {
        self.fingerprint = run_probe_impl(self);
    }
    pub fn probe(& self) -> Fingerprint {
        run_probe_impl(self)
    }
}

fn run_probe_impl(fp: &Fingerprinter) -> Fingerprint {
    let mut result: Fingerprint = Fingerprint {
        probe_status: ProbeStatus::new(),
        rtt: Duration::new(0, 0),
        packet_frame: None,
    };
    let interface: Interface = match crate::interface::get_interface_by_index(fp.probe_setting.if_index) {
        Some(interface) => interface,
        None => {
            result.probe_status = ProbeStatus::with_error_message("run_probe: unable to get interface by index".to_string());
            result.packet_frame = None;
            return result;
        }
    };
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(fp.probe_setting.receive_timeout),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    // Create a channel to send/receive packet
    let (mut tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            result.probe_status = ProbeStatus::with_error_message("run_probe: unable to create channel".to_string());
            result.packet_frame = None;
            return result;
        },
        Err(e) => {
            result.probe_status = ProbeStatus::with_error_message(format!("run_probe: unable to create channel: {}", e));
            result.packet_frame = None;
            return result;
        },
    };
    let mut parse_option: ParseOption = ParseOption::default();
    if fp.probe_setting.tunnel {
        let payload_offset = if fp.probe_setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    let probe_packet = match fp.probe_type {
        FingerprintType::IcmpEcho => crate::packet::icmp::build_icmp_probe_packet(fp.probe_setting.clone(), fp.probe_type),
        FingerprintType::IcmpTimestamp => crate::packet::icmp::build_icmp_probe_packet(fp.probe_setting.clone(), fp.probe_type),
        FingerprintType::IcmpAddressMask => crate::packet::icmp::build_icmp_probe_packet(fp.probe_setting.clone(), fp.probe_type),
        FingerprintType::IcmpInformation => crate::packet::icmp::build_icmp_probe_packet(fp.probe_setting.clone(), fp.probe_type),
        FingerprintType::IcmpUnreachable => crate::packet::udp::build_udp_probe_packet(fp.probe_setting.clone()),
        FingerprintType::TcpSynAck => crate::packet::tcp::build_tcp_probe_packet(fp.probe_setting.clone(), fp.probe_type),
        FingerprintType::TcpRstAck => crate::packet::tcp::build_tcp_probe_packet(fp.probe_setting.clone(), fp.probe_type),
        FingerprintType::TcpEcn => crate::packet::tcp::build_tcp_probe_packet(fp.probe_setting.clone(), fp.probe_type),
    };
    let send_time = Instant::now();
    match tx.send(&probe_packet) {
        Some(_) => {}
        None => {},
    }
    loop {
        match rx.next() {
            Ok(packet) => {
                let recv_time: Duration = Instant::now().duration_since(send_time);
                let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                match fp.probe_type.protocol() {
                    Protocol::ICMP | Protocol::UDP => {
                        if filter_icmp_packet(&frame, &fp.probe_setting, &fp.probe_type) {
                            result.probe_status = ProbeStatus::new();
                            result.rtt = recv_time;
                            result.packet_frame = Some(frame);
                            break;
                        }  
                    },
                    Protocol::TCP => {
                        if filter_tcp_packet(&frame, &fp.probe_setting, &fp.probe_type) {
                            result.probe_status = ProbeStatus::new();
                            result.rtt = recv_time;
                            result.packet_frame = Some(frame);
                            break;
                        }
                    },
                    _ => {},
                }
            },
            Err(_e) => {}
        }
        let wait_time: Duration = Instant::now().duration_since(send_time);
        if wait_time > fp.probe_setting.receive_timeout {
            result.probe_status = ProbeStatus::with_timeout_message("Probe timeout".to_string());
            result.packet_frame = None;
            break;
        }
    }
    result
}

fn filter_icmp_packet(frame: &Frame, setting: &ProbeSetting, probe_type: &FingerprintType) -> bool {
    if let Some(ip_layer) = &frame.ip {
        if let Some(ipv4_header) = &ip_layer.ipv4 {
            if IpAddr::V4(ipv4_header.source) == setting.dst_ip {
                if let Some(icmp_header) = &ip_layer.icmp {
                    match probe_type {
                        FingerprintType::IcmpEcho => {
                            if icmp_header.icmp_type == icmp::IcmpType::EchoReply {
                                return true;
                            }
                        },
                        FingerprintType::IcmpTimestamp => {
                            if icmp_header.icmp_type == icmp::IcmpType::TimestampReply {
                                return true;
                            }
                        },
                        FingerprintType::IcmpAddressMask => {
                            if icmp_header.icmp_type == icmp::IcmpType::AddressMaskReply {
                                return true;
                            }
                        },
                        FingerprintType::IcmpInformation => {
                            if icmp_header.icmp_type == icmp::IcmpType::InformationReply {
                                return true;
                            }
                        },
                        FingerprintType::IcmpUnreachable => {
                            if icmp_header.icmp_type == icmp::IcmpType::DestinationUnreachable {
                                return true;
                            }
                        },
                        _ => {},
                    }
                }
            }
        }
        if let Some(ipv6_header) = &ip_layer.ipv6 {
            if IpAddr::V6(ipv6_header.source) == setting.dst_ip {
                if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                    match probe_type {
                        FingerprintType::IcmpEcho => {
                            if icmpv6_header.icmpv6_type == icmpv6::Icmpv6Type::EchoReply {
                                return true;
                            }
                        },
                        _ => {},
                    }
                }
            }
        }
    }
    false
}

fn filter_tcp_packet(frame: &Frame, setting: &ProbeSetting, probe_type: &FingerprintType) -> bool {
    if let Some(ip_layer) = &frame.ip {
        if let Some(ipv4_header) = &ip_layer.ipv4 {
            if IpAddr::V4(ipv4_header.source) != setting.dst_ip {
                return false;
            }
        }
        if let Some(ipv6_header) = &ip_layer.ipv6 {
            if IpAddr::V6(ipv6_header.source) != setting.dst_ip {
                return false;
            }   
        }
    }
    if let Some(transport_layer) = &frame.transport {
        if let Some(tcp_header) = &transport_layer.tcp {
            match probe_type {
                FingerprintType::TcpSynAck => {
                    if tcp_header.flags == TcpFlags::SYN | TcpFlags::ACK && tcp_header.flags != TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE {
                        return true;
                    }
                },
                FingerprintType::TcpRstAck  => {
                    if tcp_header.flags == TcpFlags::RST | TcpFlags::ACK {
                        return true;
                    }
                },
                FingerprintType::TcpEcn => {
                    if tcp_header.flags == TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE {
                        return true;
                    }
                },
                _ => {},
            }
        }
    }
    false
}
