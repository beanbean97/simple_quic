mod assembler;
mod channel;
mod coding;
mod connect;
mod frame;
mod range_set;
mod space;
mod streams;
mod transport_error;
mod varint;

use std::net::{SocketAddrV4, SocketAddrV6};
pub use transport_error::Error as TransportError;

#[derive(Eq, PartialOrd, PartialEq, Ord, Debug, Clone)]
pub enum Address {
    IpV4(SocketAddrV4),
    IpV6(SocketAddrV6),
    Domain { addr: String, port: u16 },
}

impl Address {
    fn size(&self) -> usize {
        match self {
            Address::IpV4(_) => 6,
            Address::IpV6(_) => 18,
            Address::Domain { addr, port } => addr.len() + 2,
        }
    }
}
