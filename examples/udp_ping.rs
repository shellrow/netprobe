use std::net::{IpAddr, Ipv4Addr};
//use std::net::Ipv6Addr;
use std::{thread, env, process};
use netprobe::ping::Pinger;
use netprobe::setting::ProbeSetting;
use xenet::net::interface::Interface;

// UDP ping to cloudflare's one.one.one.one (1.1.1.1)
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
    let setting : ProbeSetting = ProbeSetting::udp_ping(interface, dst_ip, 4).unwrap();
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
