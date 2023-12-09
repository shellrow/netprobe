use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use netprobe::ping::Pinger;
use netprobe::setting::ProbeSetting;

fn main() {
    // ICMPv4 ping to cloudflare's one.one.one.one (1.1.1.1)
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let setting : ProbeSetting = ProbeSetting::udp_ping_default(dst_ip, 4).unwrap();
    let pinger: Pinger = Pinger::new(setting).unwrap();
    let rx = pinger.get_progress_receiver();
    let handle = thread::spawn(move || {
        pinger.ping()
    });
    for r in rx.lock().unwrap().iter() {
        println!("{} [{:?}] {} Bytes from IP:{}, HOP:{}, TTL:{}, RTT:{:?}", r.seq, r.protocol, r.received_packet_size, r.ip_addr, r.hop, r.ttl, r.rtt);
    }
    match handle.join() {
        Ok(ping_result) => {
            match ping_result {
                Ok(ping_result) => {
                    println!("Transmitted: {}, Received: {}, Loss: {}%", ping_result.stat.transmitted_count, ping_result.stat.received_count, 100.0 - ping_result.stat.transmitted_count as f64 / ping_result.stat.received_count as f64 * 100.0);
                    println!("MIN: {:?}, MAX:{:?}, AGV:{:?}", ping_result.stat.min, ping_result.stat.max, ping_result.stat.avg);
                },
                Err(e) => println!("{:?}", e),
            }
        },
        Err(e) => println!("{:?}", e),
    }
}
