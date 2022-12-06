use std::mem::{MaybeUninit};

use socket2::{Socket, Type, Domain, Protocol, SockAddr};

fn main() {
    let socket = Socket::new(Domain::IPV4, Type::from(3), Some(Protocol::TCP)).expect("socket should work");
    loop {
        let mut buf: [MaybeUninit<u8>; 65565] = [MaybeUninit::<u8>::uninit(); 65565];
        let resp = socket.recv_from(&mut buf);
        match resp {
            Ok((size, addr)) => {
                let message_size = size;
                let remote_addr = addr.as_socket_ipv4().expect("should have a remote addres");
                let remote_addr_str = remote_addr.ip();
                println!("message size: {}", message_size);
                println!("message from: {:?}", remote_addr_str);
                let slice = &buf[0..message_size];
                let bytes = slice.iter().map(|x| unsafe { x.assume_init() }).collect::<Vec<u8>>();
                println!("message: {:?}", bytes);
                println!();                
            }
            Err(e) => panic!("{}", e),
        }
    }
}
