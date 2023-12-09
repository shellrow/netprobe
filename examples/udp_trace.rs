use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use netprobe::trace::Tracer;
use netprobe::setting::ProbeSetting;
use netprobe::result::ProbeStatusKind;

fn main() {
    // ICMPv4 traceroute to cloudflare's one.one.one.one (1.1.1.1)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let setting : ProbeSetting = ProbeSetting::udp_trace_default(dst_ip, 4).unwrap();
    let tracer: Tracer = Tracer::new(setting).unwrap();
    let rx = tracer.get_progress_receiver();
    let handle = thread::spawn(move || {
        tracer.trace()
    });
    for r in rx.lock().unwrap().iter() {
        match r.probe_status.kind {
            ProbeStatusKind::Done => {
                println!("{} [{:?}] {} Bytes from IP:{}, HOP:{}, TTL:{}, RTT:{:?}, NodeType: {:?}", r.seq, r.protocol, r.received_packet_size, r.ip_addr,  r.hop, r.ttl, r.rtt, r.node_type);
            },
            ProbeStatusKind::Timeout => {
                println!("{} [{:?}] {}", r.seq, r.protocol, r.probe_status.message);
            },
            _ => {}
        }
    }
    match handle.join() {
        Ok(trace_result) => {
            match trace_result {
                Ok(r) => {
                    println!("Traceroute Result: {:?}", r);
                },
                Err(e) => println!("{:?}", e),
            }
        },
        Err(e) => println!("{:?}", e),
    }
}
