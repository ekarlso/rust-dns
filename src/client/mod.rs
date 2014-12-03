use std::default::Default;
use std::str::from_str;

use std::io::net::ip::{IpAddr,SocketAddr};
use std::io::net::udp::UdpSocket;
use std::io::{BufReader,BufWriter,IoResult};

use client::config::ClientConfig;
use io::DNSWriter;
use message::Message;


pub mod config;

pub struct Client {
    pub config: ClientConfig,
}

impl Client {
    pub fn exchange(&self, msg: &mut Message) -> IoResult<Message> {
        let saddr: SocketAddr = match self.config.bind {
            None        => {
                // TODO(ekarlso): Support ipv6?
                SocketAddr { ip: from_str::<IpAddr>("0.0.0.0").unwrap(), port: 0 }
            },
            Some(addr)  => { addr }
        };

        let mut buffer: [u8, ..512] = [0, ..512];
        let length: uint = self.write(&mut buffer, msg).unwrap() as uint;

        let mut sock = UdpSocket::bind(saddr).unwrap();

        let dst = self.config.servers[0];

        sock.send_to(buffer.slice_to(length), dst);

        match sock.recv_from(&mut buffer) {
            Ok((length, src)) => {
                self.read(&mut buffer, length)
            },
            Err(e) => return Err(e)
        }
    }

    fn write(&self, buffer: &mut [u8, ..512], message: &mut Message) -> IoResult<u64> {
        let mut writer: BufWriter = BufWriter::new(buffer.as_mut_slice());

        match message.write_to(&mut writer) {
            Err(e) => return Err(e),
            Ok(_) => ()
        };

        return writer.tell();
    }

    fn read(&self, buffer: &mut [u8, ..512], length: uint) -> IoResult<Message> {
        let mut reader = BufReader::new(buffer.slice_to(length));

        Message::from_reader(&mut reader)
    }

    pub fn new() -> Client {
        Client {..Default::default() }
    }
}

impl Default for Client {
    fn default() -> Client {
        let cfg = ClientConfig { ..Default::default() };

        Client {
            config: cfg
        }
    }
}