use crate::{varint::VarInt, Address};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use bytes::{Buf, BufMut};
use err_derive::Error;

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
#[error(display = "unexpected end of buffer")]
pub struct UnexpectedEnd;

pub type Result<T> = ::std::result::Result<T, UnexpectedEnd>;

pub trait Codec: Sized {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self>;
    fn encode<B: BufMut>(&self, buf: &mut B);
}

impl Codec for u8 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u8> {
        if buf.remaining() < 1 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u8())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(*self);
    }
}

impl Codec for u16 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u16> {
        if buf.remaining() < 2 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u16())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(*self);
    }
}

impl Codec for u32 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u32> {
        if buf.remaining() < 4 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u32())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32(*self);
    }
}

impl Codec for u64 {
    fn decode<B: Buf>(buf: &mut B) -> Result<u64> {
        if buf.remaining() < 8 {
            return Err(UnexpectedEnd);
        }
        Ok(buf.get_u64())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u64(*self);
    }
}

impl Codec for Ipv4Addr {
    fn decode<B: Buf>(buf: &mut B) -> Result<Ipv4Addr> {
        if buf.remaining() < 4 {
            return Err(UnexpectedEnd);
        }
        let mut octets = [0; 4];
        buf.copy_to_slice(&mut octets);
        Ok(octets.into())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets());
    }
}

impl Codec for Ipv6Addr {
    fn decode<B: Buf>(buf: &mut B) -> Result<Ipv6Addr> {
        if buf.remaining() < 16 {
            return Err(UnexpectedEnd);
        }
        let mut octets = [0; 16];
        buf.copy_to_slice(&mut octets);
        Ok(octets.into())
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets());
    }
}

impl Codec for Address {
    fn decode<B: Buf>(buf: &mut B) -> Result<Address> {
        let addr_type: u8 = buf.get()?;
        Ok(match addr_type {
            len @ 0..=253 => {
                let mut addr: Vec<u8> = vec![0; len as usize];
                buf.copy_to_slice(&mut addr);
                Address::Domain {
                    addr: String::from_utf8(addr)?, //TODO
                    port: buf.get()?,
                }
            }
            254 => Address::IpV4(SocketAddrV4::new(buf.get()?, buf.get()?)),
            255 => Address::IpV6(SocketAddrV6::new(buf.get()?, buf.get()?, 0, 0)),
        })
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Address::Domain { addr, port } => {
                assert!(addr.len() <= 253);
                buf.write(addr.len() as u8);
                buf.put_slice(addr.as_bytes());
                buf.write(*port);
            }
            Address::IpV4(addr) => {
                buf.write(254 as u8);
                buf.write(*addr.ip());
                buf.write(addr.port());
            }
            Address::IpV6(addr) => {
                buf.write(255 as u8);
                buf.write(*addr.ip());
                buf.write(addr.port());
            }
        };
    }
}

pub trait BufExt {
    fn get<T: Codec>(&mut self) -> Result<T>;
    fn get_var(&mut self) -> Result<u64>;
}

impl<T: Buf> BufExt for T {
    fn get<U: Codec>(&mut self) -> Result<U> {
        U::decode(self)
    }

    fn get_var(&mut self) -> Result<u64> {
        Ok(VarInt::decode(self)?.into_inner())
    }
}

pub trait BufMutExt {
    fn write<T: Codec>(&mut self, x: T);
    fn write_var(&mut self, x: u64);
}

impl<T: BufMut> BufMutExt for T {
    fn write<U: Codec>(&mut self, x: U) {
        x.encode(self);
    }

    fn write_var(&mut self, x: u64) {
        VarInt::from_u64(x).unwrap().encode(self);
    }
}
