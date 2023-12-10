use netprobe::neighbor::DeviceResolver;
use netprobe::setting::ProbeSetting;
use std::net::{IpAddr, Ipv6Addr};
use std::{env, process, thread};
use xenet::net::interface::Interface;

const USAGE: &str = "USAGE: ndp <NETWORK INTERFACE> <TARGET IPv6 Addr>";

fn main() {
    let interface: Interface = match env::args().nth(1) {
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
            println!("Failed to get default interface");
            eprintln!("{USAGE}");
            process::exit(1);
        }
    };
    let dst_ip: Ipv6Addr = match env::args().nth(2) {
        Some(target_ip) => match target_ip.parse::<IpAddr>() {
            Ok(ip) => match ip {
                IpAddr::V4(_) => {
                    println!("IPv4 is not supported");
                    eprintln!("{USAGE}");
                    process::exit(1);
                }
                IpAddr::V6(ipv6) => ipv6,
            },
            Err(e) => {
                println!("Failed to parse target ip: {}", e);
                eprintln!("{USAGE}");
                process::exit(1);
            }
        },
        None => {
            println!("Failed to get target ip");
            eprintln!("{USAGE}");
            process::exit(1);
        }
    };
    let setting: ProbeSetting = ProbeSetting::ndp(interface, dst_ip, 4).unwrap();
    let resolver: DeviceResolver = DeviceResolver::new(setting).unwrap();
    let rx = resolver.get_progress_receiver();
    let handle = thread::spawn(move || resolver.resolve());
    for r in rx.lock().unwrap().iter() {
        println!(
            "{} [{:?}] {} Bytes from MAC Addr:{}, IP Addr:{}, RTT:{:?}",
            r.seq, r.protocol, r.received_packet_size, r.mac_addr, r.ip_addr, r.rtt
        );
    }
    match handle.join() {
        Ok(resolve_result) => match resolve_result {
            Ok(r) => {
                println!("NDP Result: {:?}", r);
            }
            Err(e) => println!("{:?}", e),
        },
        Err(e) => println!("{:?}", e),
    }
}
