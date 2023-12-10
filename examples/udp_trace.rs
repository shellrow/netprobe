use std::net::{IpAddr, Ipv4Addr};
//use std::net::Ipv6Addr;
use netprobe::result::ProbeStatusKind;
use netprobe::setting::ProbeSetting;
use netprobe::trace::Tracer;
use std::{env, process, thread};
use xenet::net::interface::Interface;

// UDP traceroute to cloudflare's one.one.one.one (1.1.1.1)
fn main() {
    let interface: Interface = match env::args().nth(2) {
        Some(n) => {
            // Use interface specified by user
            let interfaces: Vec<Interface> = xenet::net::interface::get_interfaces();
            let interface: Interface = interfaces
                .into_iter()
                .find(|interface| interface.name == n)
                .expect("Failed to get interface information");
            interface
        }
        None => {
            // Use default interface
            match Interface::default() {
                Ok(interface) => interface,
                Err(e) => {
                    println!("Failed to get default interface: {}", e);
                    process::exit(1);
                }
            }
        }
    };
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    //let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    let setting: ProbeSetting = ProbeSetting::udp_trace(interface, dst_ip, 4).unwrap();
    let tracer: Tracer = Tracer::new(setting).unwrap();
    let rx = tracer.get_progress_receiver();
    let handle = thread::spawn(move || tracer.trace());
    for r in rx.lock().unwrap().iter() {
        match r.probe_status.kind {
            ProbeStatusKind::Done => {
                println!(
                    "{} [{:?}] {} Bytes from IP:{}, HOP:{}, TTL:{}, RTT:{:?}, NodeType: {:?}",
                    r.seq,
                    r.protocol,
                    r.received_packet_size,
                    r.ip_addr,
                    r.hop,
                    r.ttl,
                    r.rtt,
                    r.node_type
                );
            }
            ProbeStatusKind::Timeout => {
                println!("{} [{:?}] {}", r.seq, r.protocol, r.probe_status.message);
            }
            _ => {}
        }
    }
    match handle.join() {
        Ok(trace_result) => match trace_result {
            Ok(r) => {
                println!("Traceroute Result: {:?}", r);
            }
            Err(e) => println!("{:?}", e),
        },
        Err(e) => println!("{:?}", e),
    }
}
