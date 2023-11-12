use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad{
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}


fn main() -> io::Result<()>{
    let mut connections: HashMap<Quad, tcp::State> = Default::default();


    let tun = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    let start_time = SystemTime::now();
    loop {
        // let now_time = SystemTime::now();
        // if now_time > start_time + Duration::new(10, 0) {
        //     break;
        // }
        let nbytes = tun.recv(&mut buf[..])?;
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != 0x0800{
            println!("ignore non-ipv4 packet. protocol: {:x}, flags: {:x}", eth_proto, eth_flags);
            continue;
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]){
            Ok(ip_packet) => {
                let src = ip_packet.source_addr();
                let dst = ip_packet.destination_addr();
                let proto = ip_packet.protocol();
                let src_ip = ip_packet.source_addr().to_string();
                let dst_ip = ip_packet.destination_addr().to_string();
                match proto {
                    1 => { println!("recv ICMP") }
                    6 => {
                        match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_packet.slice().len()..]) {
                            Ok(tcp_seg) => {
                                let src_port = tcp_seg.source_port();
                                let dst_port = tcp_seg.destination_port();
                                connections.entry(Quad{
                                    src: (ip_packet.source_addr(), src_port),
                                    dst: (ip_packet.destination_addr(), dst_port)
                                }).or_default().on_packet(&ip_packet, &tcp_seg, &buf[4 + ip_packet.slice().len() + tcp_seg.slice().len()..], &tun);
                                // println!("Tcp[{}:{} -> {}:{}]", src_ip, src_port, dst_ip, dst_port);
                            }
                            _ => {}
                        }

                    }
                    17 => { println!("recv UDP") }
                    _ => { println!("unhandled protocol in ipv4: {:x}", proto) }
                }

            }
            Err(e) => {
                println!("error parsing ipv4 header");
            }
        }
        // eprintln!("read {} bytes: {:x?}", nbytes, &buf[..nbytes]);
    }
    Ok(())
}
