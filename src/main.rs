use std::{mem::{MaybeUninit}};
use packed_struct::prelude::*;
use socket2::{Socket, Type, Domain, Protocol};

pub fn htons(u: u16) -> u16 {
    return u.to_be();
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PackedStruct)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct Ethhdr {
  h_dest: [u8; 6],
  h_source: [u8; 6],
  h_proto: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PackedStruct)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct Iphdr {
    #[cfg(target_endian = "little")]
    #[packed_field(bits="0..=3")]
    ihl: Integer<u8, packed_bits::Bits<4>>,
    #[cfg(target_endian = "little")]
    #[packed_field(bits="4..=7")]
    version: Integer<u8, packed_bits::Bits<4>>,
    #[cfg(target_endian = "big")]
    #[packed_field(bits="0..=3")]
    version: Integer<u8, packed_bits::Bits<4>>,
    #[cfg(target_endian = "big")]
    #[packed_field(bits="4..=7")]
    ihl: Integer<u8, packed_bits::Bits<4>>,
    #[packed_field(bits="8..=15")]
    tos: Integer<u8, packed_bits::Bits<8>>,
    #[packed_field(bits="16..=31")]
    tot_len: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="32..=47")]
    id: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="51..=63")]
    frag_off: Integer<u16, packed_bits::Bits<13>>,
    #[packed_field(bits="64..=71")]
    ttl: Integer<u8, packed_bits::Bits<8>>,
    #[packed_field(bits="72..=79")]
    protocol: Integer<u8, packed_bits::Bits<8>>,
    #[packed_field(bits="80..=95")]
    check: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="96..=127")]
    saddr: Integer<u32, packed_bits::Bits<32>>,
    #[packed_field(bits="128..=159")]
    daddr: Integer<u32, packed_bits::Bits<32>>
}

#[derive(PackedStruct, Clone, Copy)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct Icmphdr {
  #[packed_field(bits="0..=7")]
  pub icmp_type: Integer<u8, packed_bits::Bits<8>>,
  #[packed_field(bits="8..=15")]
  pub code: Integer<u8, packed_bits::Bits<8>>,
  #[packed_field(bits="16..=31")]
  pub checksum: Integer<u16, packed_bits::Bits<16>>,
}

#[derive(Debug, PackedStruct, Clone, Copy)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct Tcphdr {
    #[packed_field(bits="0..=15")]
    source_port:  Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="16..=31")]
    destination_port: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="32..=63")]
    sequence_number: Integer<u32, packed_bits::Bits<32>>,
    #[packed_field(bits="64..=95")]
    acknowledgement_number: Integer<u32, packed_bits::Bits<32>>,
    #[packed_field(bits="96..=99")]
    header_length: Integer<u8, packed_bits::Bits<4>>,
    #[packed_field(bits="100..=139")]
    options: Integer<u64, packed_bits::Bits<40>>,
}

#[derive(Debug, Clone, Copy, PackedStruct)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct Udphdr {
  #[packed_field(bits="0..=15")]
  src_port: u16,  // source port
  #[packed_field(bits="16..=31")]
  dest_port: u16, // destination port
  #[packed_field(bits="32..=47")]
  len: u16,       // length of the packet
  #[packed_field(bits="48..=63")]
  checksum: u16,  // checksum
}

fn parse_to_mac_address(bytes: &[u8; 6]) -> String {
    return bytes.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(":");
}

fn parse_to_ipv4_address(b: u32) -> String {
    return format!("{}.{}.{}.{}", b & 0xff, (b >> 8) & 0xff, (b >> 16) & 0xff, (b >> 24) & 0xff);
}

fn print_eth_header(eth_header: Ethhdr) {
    println!("ethernet header: {{ protocol: {}, source: {}, destination: {} }}", eth_header.h_proto, parse_to_mac_address(&eth_header.h_source), parse_to_mac_address(&eth_header.h_dest));
}

fn print_ipv4_header(ipv4_header: Iphdr) {
    let s_addr= parse_to_ipv4_address(u32::from(ipv4_header.saddr));
    let d_addr= parse_to_ipv4_address(u32::from(ipv4_header.daddr));
    println!("ipv4 header: {{ ihl: {}, version: {}, tos: {}, tot_len: {}, id: {}, frag_off: {}, ttl: {}, protocol: {}, check:{}, saddr: {}, daddr: {} }}", ipv4_header.ihl, ipv4_header.version, ipv4_header.tos, ipv4_header.tot_len, ipv4_header.id, ipv4_header.frag_off, ipv4_header.ttl, ipv4_header.protocol, ipv4_header.check, s_addr, d_addr);
}

fn main() {
    let protocol = Protocol::from(htons(3) as i32);
    let socket = Socket::new(Domain::PACKET, Type::RAW, Some(protocol)).expect("socket should work");
    loop {
        let mut buf: [MaybeUninit<u8>; 65565] = [MaybeUninit::<u8>::uninit(); 65565];
        let resp = socket.recv_from(&mut buf);
        match resp {
            Ok((size, _addr)) => {
                let message_size = size;
                let slice = &buf[0..message_size];
                let byte_vec = slice.iter().map(|x| unsafe { x.assume_init() }).collect::<Vec<u8>>();
                let eth_slice = &byte_vec[0..14].try_into().expect("should be 14 length u8 slice");
                let eth_header = Ethhdr::unpack(eth_slice).expect("should be able to unpack ethernet header");
                print_eth_header(eth_header);
                let ip_slice = &byte_vec[14..34].try_into().expect("should be 20 length u8 slice");
                let ip_header = Iphdr::unpack(&ip_slice).expect("should be able to unpack ip header");
                print_ipv4_header(ip_header);
                match u8::from(ip_header.protocol) {
                    1 => {
                        let icmp_slice: &[u8; 4] = &byte_vec[34..38].try_into().expect("should be 4 length u8 slice");
                        let icmp_header = Icmphdr::unpack(icmp_slice).expect("should be able to unpack icmp header");
                        println!("icmp header: {{ type: {}, code: {}, checksum: {} }}", icmp_header.icmp_type, icmp_header.code, icmp_header.checksum);
                    },
                    2 => println!("got igmp packet"),
                    6 => {
                        let tcp_slice = &byte_vec[34..52].try_into().expect("should be 18 length u8 slice");
                        let tcp_header = Tcphdr::unpack(tcp_slice).expect("should be able to unpack tcp header");
                        println!("tcp header: {:?}", tcp_header);
                        let tcp_header_length = u8::from(tcp_header.header_length) * 4;
                        let ip_header_length = u8::from(ip_header.ihl) * 4;
                        let header_size = (tcp_header_length + ip_header_length) as usize;
                        let tcp_payload = byte_vec[header_size..].to_vec();
                        let tcp_payload_clone = tcp_payload.clone();
                        let s = std::string::String::from_utf8(tcp_payload);
                        match s {
                            Ok(s) => println!("tcp payload: {}", s),
                            Err(_e) => println!("tcp payload: {:?}", tcp_payload_clone),
                        }
                    },
                    17 => {
                        let udp_slice = &byte_vec[34..42].try_into().expect("should be 8 length u8 slice");
                        let udp_header = Udphdr::unpack(udp_slice).expect("should be able to unpack udp header");
                        println!("udp header: {:?}", udp_header);
                        let udp_payload = byte_vec[42..].to_vec();
                        let udp_payload_clone = udp_payload.clone();
                        let s = std::string::String::from_utf8(udp_payload);
                        match s {
                            Ok(s) => println!("udp payload: {}", s),
                            Err(_e) => println!("udp payload: {:?}", udp_payload_clone),
                        }
                    },
                    _ => println!("{}", ip_header.protocol)
                }
                println!();
            }
            Err(e) => panic!("{}", e),
        }
    }

}