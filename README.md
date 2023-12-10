[crates-badge]: https://img.shields.io/crates/v/netprobe.svg
[crates-url]: https://crates.io/crates/netprobe
[license-badge]: https://img.shields.io/crates/l/netprobe.svg

# netprobe [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-Platform Network Probe Library. Written in Rust.

## Features
- traceroute
    - [x] IPv4 UDP
    - [x] IPv6 UDP
- ping
    - [x] IPv4 ICMPv4
    - [x] IPv6 ICMPv6
    - [x] IPv4 UDP
    - [x] IPv6 UDP
    - [x] IPv4 TCP
    - [x] IPv6 TCP
- neighbor
    - [x] ARP
    - [x] NDP

## TODO
- [ ] Documentation
- [ ] More in-depth network investigations
- [ ] Support for higher-layer probes (e.g., DNS, HTTP, etc.)

## Usage
Add `netprobe` to your dependencies
```
[dependencies]
netprobe = "0.1"
```
