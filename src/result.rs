use std::time::Duration;
use std::net::IpAddr;
use xenet::packet::ip::IpNextLevelProtocol;

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
//#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProbeResult {
    /// Sequence number
    pub seq: u8,
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
    pub protocol: IpNextLevelProtocol,
    /// Node type
    pub node_type: NodeType,
    /// Sent packet size
    pub sent_packet_size: usize,
    /// Received packet size
    pub received_packet_size: usize,   
}

#[derive(Clone, Debug)]
//#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PingStat {
    /// Ping responses
    pub responses: Vec<ProbeResult>,
    /// The entire ping probe time (microsecond)
    pub probe_time: u64,
    /// Transmitted packets
    pub transmitted_count: usize,
    /// Received packets
    pub received_count: usize,
    /// Minimum RTT (microsecond)
    pub min: u64,
    /// Avarage RTT (microsecond)
    pub avg: u64,
    /// Maximum RTT (microsecond)
    pub max: u64,
}

impl PingStat {
    pub fn new() -> PingStat {
        PingStat {
            responses: Vec::new(),
            probe_time: 0,
            transmitted_count: 0,
            received_count: 0,
            min: 0,
            avg: 0,
            max: 0,
        }
    }
}

#[derive(Clone, Debug)]
//#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PingResult {
    pub probe_id: String,
    pub stat: PingStat,
    pub probe_status: ProbeStatusKind,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time in milliseconds
    pub elapsed_time: u64,
    pub protocol: IpNextLevelProtocol,
}

impl PingResult {
    pub fn new() -> PingResult {
        PingResult {
            probe_id: String::new(),
            stat: PingStat::new(),
            probe_status: ProbeStatusKind::Done,
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: 0,
            protocol: IpNextLevelProtocol::Icmp,
        }
    }
}

#[derive(Clone, Debug)]
//#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TracerouteResult {
    pub probe_id: String,
    pub nodes: Vec<ProbeResult>,
    pub probe_status: ProbeStatusKind,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time in milliseconds
    pub elapsed_time: u64,
    pub protocol: IpNextLevelProtocol,
}

impl TracerouteResult {
    pub fn new() -> TracerouteResult {
        TracerouteResult {
            probe_id: String::new(),
            nodes: Vec::new(),
            probe_status: ProbeStatusKind::Done,
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: 0,
            protocol: IpNextLevelProtocol::Udp,
        }
    }
}
