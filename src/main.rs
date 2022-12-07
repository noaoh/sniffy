use std::mem::{MaybeUninit};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use packed_struct::prelude::*;
use socket2::{Socket, Type, Domain, Protocol, SockAddr};

#[derive(Debug, PackedStruct)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct IPV4Header {
    #[packed_field(bits="0..=3")]
    version: Integer<u8, packed_bits::Bits<4>>,
    #[packed_field(bits="4..=7")]
    ihl: Integer<u8, packed_bits::Bits<4>>,
    #[packed_field(bits="8..=15")]
    dscp: Integer<u8, packed_bits::Bits<8>>,
    #[packed_field(bits="16..=31")]
    total_length: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="32..=47")]
    identification: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="48..=50")]
    flags: Integer<u8, packed_bits::Bits<3>>,
    #[packed_field(bits="51..=63")]
    fragment_offset: Integer<u16, packed_bits::Bits<13>>,
    #[packed_field(bits="64..=71")]
    ttl: Integer<u8, packed_bits::Bits<8>>,
    #[packed_field(bits="72..=79")]
    protocol: Integer<u8, packed_bits::Bits<8>>,
    #[packed_field(bits="80..=95")]
    header_checksum: Integer<u16, packed_bits::Bits<16>>,
    #[packed_field(bits="96..=127")]
    source_address: Integer<u32, packed_bits::Bits<32>>,
    #[packed_field(bits="128..=159")]
    destination_address: Integer<u32, packed_bits::Bits<32>>
}


#[derive(Debug, PackedStruct)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct TCPHeader {
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

fn main() {
    let socket = Socket::new(Domain::IPV4, Type::from(3), Some(Protocol::TCP)).expect("socket should work");
    loop {
        let mut buf: [MaybeUninit<u8>; 65565] = [MaybeUninit::<u8>::uninit(); 65565];
        let resp = socket.recv_from(&mut buf);
        match resp {
            Ok((size, _addr)) => {
                let message_size = size;
                println!("message size: {}", message_size);
                let slice = &buf[0..message_size];
                let byte_vec = slice.iter().map(|x| unsafe { x.assume_init() }).collect::<Vec<u8>>();
                let ipv4_byte_slice = &byte_vec[0..20].try_into().expect("should be 20 length u8 slice");
                let ipv4 = IPV4Header::unpack(ipv4_byte_slice).expect("should unpack");
                println!("{:?}", ipv4);                
                let source_address = Ipv4Addr::from(u32::from(ipv4.source_address));
                let destination_address = Ipv4Addr::from(u32::from(ipv4.destination_address));
                let source_addr_str = source_address.to_string();
                let destination_addr_str = destination_address.to_string();
                println!("source address: {}", source_addr_str);
                println!("destination address: {}", destination_addr_str);
                let tcp_byte_slice: &[u8; 18] = &byte_vec[20..38].try_into().expect("should be 18 length u8 slice");
                let tcp_header: TCPHeader = TCPHeader::unpack(tcp_byte_slice).expect("should unpack");
                let tcp_header_length = u8::from(tcp_header.header_length) * 4;
                let ip_header_length = u8::from(ipv4.ihl) * 4;
                let header_size = (tcp_header_length + ip_header_length) as usize;
                println!("{:?}", tcp_header);
                let tcp_payload = byte_vec[header_size..].to_vec();
                let tcp_payload_clone = tcp_payload.clone();
                let s = std::string::String::from_utf8(tcp_payload);
                match s {
                    Ok(s) => println!("payload: {}", s),
                    Err(_e) => println!("payload: {:?}", tcp_payload_clone),
                }
                println!();
            }
            Err(e) => panic!("{}", e),
        }
    }
}
