use std::time::Duration;
use std::net::IpAddr;
use xenet::net::mac::MacAddr;
use crate::setting::Protocol;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl PortStatus {
    pub fn id(&self) -> String {
        match *self {
            PortStatus::Open => String::from("open"),
            PortStatus::Closed => String::from("closed"),
            PortStatus::Filtered => String::from("filtered"),
            PortStatus::Unknown => String::from("unknown"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            PortStatus::Open => String::from("Open"),
            PortStatus::Closed => String::from("Closed"),
            PortStatus::Filtered => String::from("Filtered"),
            PortStatus::Unknown => String::from("Unknown"),
        }
    }
}

/// Node type
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NodeType {
    DefaultGateway,
    Relay,
    Destination,
}

impl NodeType {
    pub fn id(&self) -> String {
        match *self {
            NodeType::DefaultGateway => String::from("default_gateway"),
            NodeType::Relay => String::from("relay"),
            NodeType::Destination => String::from("destination"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            NodeType::DefaultGateway => String::from("DefaultGateway"),
            NodeType::Relay => String::from("Relay"),
            NodeType::Destination => String::from("Destination"),
        }
    }
}

/// Status of probe
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProbeStatusKind {
    /// Successfully completed
    Done,
    /// Interrupted by error
    Error,
    /// Execution time exceeds the configured timeout value
    Timeout,
}

impl ProbeStatusKind {
    pub fn name(&self) -> String {
        match *self {
            ProbeStatusKind::Done => String::from("Done"),
            ProbeStatusKind::Error => String::from("Error"),
            ProbeStatusKind::Timeout => String::from("Timeout"),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProbeStatus {
    pub kind: ProbeStatusKind,
    pub message: String,
}

impl ProbeStatus {
    pub fn new() -> ProbeStatus {
        ProbeStatus {
            kind: ProbeStatusKind::Done,
            message: String::new(),
        }
    }
    pub fn with_error_message(message: String) -> ProbeStatus {
        ProbeStatus {
            kind: ProbeStatusKind::Error,
            message: message,
        }
    }
    pub fn with_timeout_message(message: String) -> ProbeStatus {
        ProbeStatus {
            kind: ProbeStatusKind::Timeout,
            message: message,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProbeResult {
    /// Sequence number
    pub seq: u8,
    /// MAC address
    pub mac_addr: MacAddr,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// Port
    pub port_number: Option<u16>,
    /// Port Status
    pub port_status: Option<PortStatus>,
    /// Time To Live
    pub ttl: u8,
    /// Number of hops
    pub hop: u8,
    /// Round Trip Time (microsecond)
    pub rtt: Duration,
    /// Status
    pub probe_status: ProbeStatus,
    /// Protocol
    pub protocol: Protocol,
    /// Node type
    pub node_type: NodeType,
    /// Sent packet size
    pub sent_packet_size: usize,
    /// Received packet size
    pub received_packet_size: usize,   
}

impl ProbeResult {
    pub fn new() -> ProbeResult {
        ProbeResult {
            seq: 0,
            mac_addr: MacAddr::zero(),
            ip_addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            host_name: String::new(),
            port_number: None,
            port_status: None,
            ttl: 0,
            hop: 0,
            rtt: Duration::from_millis(0),
            probe_status: ProbeStatus::new(),
            protocol: Protocol::ICMP,
            node_type: NodeType::Destination,
            sent_packet_size: 0,
            received_packet_size: 0,
        }
    }
    pub fn timeout(seq: u8, ip_addr: IpAddr, host_name: String, protocol: Protocol, sent_packet_size: usize) -> ProbeResult {
        ProbeResult {
            seq: seq,
            mac_addr: MacAddr::zero(),
            ip_addr: ip_addr,
            host_name: host_name,
            port_number: None,
            port_status: None,
            ttl: 0,
            hop: 0,
            rtt: Duration::from_millis(0),
            probe_status: ProbeStatus::with_timeout_message(format!("Request timeout for seq {}", seq)),
            protocol: protocol,
            node_type: NodeType::Destination,
            sent_packet_size: sent_packet_size,
            received_packet_size: 0,
        }
    }
    pub fn trace_timeout(seq: u8, protocol: Protocol, sent_packet_size: usize, node_type: NodeType) -> ProbeResult {
        ProbeResult {
            seq: seq,
            mac_addr: MacAddr::zero(),
            ip_addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            host_name: String::new(),
            port_number: None,
            port_status: None,
            ttl: 0,
            hop: 0,
            rtt: Duration::from_millis(0),
            probe_status: ProbeStatus::with_timeout_message(format!("Request timeout for seq {}", seq)),
            protocol: protocol,
            node_type: node_type,
            sent_packet_size: sent_packet_size,
            received_packet_size: 0,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PingStat {
    /// Ping responses
    pub responses: Vec<ProbeResult>,
    /// The entire ping probe time
    pub probe_time: Duration,
    /// Transmitted packets
    pub transmitted_count: usize,
    /// Received packets
    pub received_count: usize,
    /// Minimum RTT
    pub min: Duration,
    /// Avarage RTT
    pub avg: Duration,
    /// Maximum RTT
    pub max: Duration,
}

impl PingStat {
    pub fn new() -> PingStat {
        PingStat {
            responses: Vec::new(),
            probe_time: Duration::from_millis(0),
            transmitted_count: 0,
            received_count: 0,
            min: Duration::from_millis(0),
            avg: Duration::from_millis(0),
            max: Duration::from_millis(0),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PingResult {
    pub stat: PingStat,
    pub probe_status: ProbeStatus,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time
    pub elapsed_time: Duration,
    pub protocol: Protocol,
}

impl PingResult {
    pub fn new() -> PingResult {
        PingResult {
            stat: PingStat::new(),
            probe_status: ProbeStatus::new(),
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: Duration::from_millis(0),
            protocol: Protocol::ICMP,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TracerouteResult {
    pub nodes: Vec<ProbeResult>,
    pub probe_status: ProbeStatus,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time
    pub elapsed_time: Duration,
    pub protocol: Protocol,
}

impl TracerouteResult {
    pub fn new() -> TracerouteResult {
        TracerouteResult {
            nodes: Vec::new(),
            probe_status: ProbeStatus::new(),
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: Duration::from_millis(0),
            protocol: Protocol::UDP,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceResolveResult {
    pub results: Vec<ProbeResult>,
    pub probe_status: ProbeStatus,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time
    pub elapsed_time: Duration,
    pub protocol: Protocol,
}

impl DeviceResolveResult {
    pub fn new() -> DeviceResolveResult {
        DeviceResolveResult {
            results: Vec::new(),
            probe_status: ProbeStatus::new(),
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: Duration::from_millis(0),
            protocol: Protocol::ARP,
        }
    }
}
