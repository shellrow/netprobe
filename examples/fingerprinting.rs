use std::net::IpAddr;
use std::{env, process};
use default_net::Interface;
use netprobe::fp::{FingerprintType, Fingerprinter};
use netprobe::setting::ProbeSetting;

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
    let dst_ip: IpAddr = netprobe::dns::lookup_host_name(String::from("scanme.nmap.org")).unwrap();
    let setting: ProbeSetting = ProbeSetting::fingerprinting(interface, dst_ip, Some(80), FingerprintType::TcpSynAck).unwrap();
    let fingerprinter: Fingerprinter = Fingerprinter::new(setting, FingerprintType::TcpSynAck);
    let fingerprint = fingerprinter.probe();
    println!("Fingerprint: {:?}", fingerprint);
}
