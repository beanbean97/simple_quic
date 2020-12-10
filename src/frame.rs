use crate::{
    coding::{BufExt, BufMutExt, Codec, UnexpectedEnd},
    range_set::RangeSet,
    varint::VarInt,
    Address,
};
use bytes::{Buf, BufMut, Bytes};
use either::Either;
use std::{fmt, io, mem, ops::RangeInclusive};

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Type(u64);

impl Type {
    fn stream(self) -> Option<StreamInfo> {
        if STREAM_TYS.contains(&self.0) {
            Some(StreamInfo(self.0 as u8))
        } else {
            None
        }
    }
    fn datagram(self) -> Option<DatagramInfo> {
        if DATAGRAM_TYS.contains(&self.0) {
            Some(DatagramInfo(self.0 as u8))
        } else {
            None
        }
    }
}

impl Codec for Type {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(Type(buf.get_var()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.0);
    }
}

pub trait FrameStruct {
    /// Smallest number of bytes this type of frame is guaranteed to fit within.
    const SIZE_BOUND: usize;
}

macro_rules! frame_types {
    {$($name:ident = $val:expr,)*} => {
        impl Type {
            $(pub const $name: Type = Type($val);)*
        }

        impl fmt::Debug for Type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str(stringify!($name)),)*
                    _ => write!(f, "Type({:02x})", self.0)
                }
            }
        }

        impl fmt::Display for Type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str(stringify!($name)),)*
                    x if STREAM_TYS.contains(&x) => f.write_str("STREAM"),
                    x if DATAGRAM_TYS.contains(&x) => f.write_str("DATAGRAM"),
                    _ => write!(f, "<unknown {:02x}>", self.0),
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct StreamInfo(u8);

impl StreamInfo {
    fn fin(self) -> bool {
        self.0 & 0x01 != 0
    }
    fn len(self) -> bool {
        self.0 & 0x02 != 0
    }
    fn off(self) -> bool {
        self.0 & 0x04 != 0
    }
    fn addr(self) -> bool {
        self.0 & 0x04 == 0
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct DatagramInfo(u8);

impl DatagramInfo {
    fn len(self) -> bool {
        self.0 & 0x01 != 0
    }
    fn addr(self) -> bool {
        self.0 & 0x02 != 0
    }
}

frame_types! {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,

    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05,
    // STREAM 0x08-0x0f len,off or addr,fin
    //！服务器方不需要addr字段
    MAX_DATA = 0x10,
    MAX_STREAM_DATA = 0x11,
    MAX_STREAMS = 0x12,
    DATA_BLOCKED = 0x14,
    STREAM_DATA_BLOCKED = 0x15,
    STREAMS_BLOCKED = 0x16,
    // DATAGRAM 0x30-0x33 len,addr
    MAX_DATAGRAMS = 0x34,
    DATAGRAM_CLOSED = 0x35,
    //can not add datagram id
    DATAGRAMS_BLOCKED = 0x36,
}

const STREAM_TYS: RangeInclusive<u64> = RangeInclusive::new(0x08, 0x0f);
const DATAGRAM_TYS: RangeInclusive<u64> = RangeInclusive::new(0x30, 0x33);

#[derive(Debug)]
pub enum Frame {
    Padding,
    Ping,
    Ack(Ack),
    ResetStream {
        id: u64,
        error_code: u64,
        final_offset: u64,
    },
    StopSending {
        id: u64,
        error_code: u64,
    },
    Stream(Stream),
    MaxData(u64),
    MaxStreamData {
        id: u64,
        offset: u64,
    },
    MaxStreams(u64),
    //Block occur offset
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        offset: u64,
    },
    //max stream id
    StreamsBlocked(u64),
    MaxDatagrams(u64),
    Datagram(Datagram),
    DatagramClosed {
        id: u64,
        error_code: u64,
    },
    //max datagram id
    DatagramsBlocked(u64),
    Invalid {
        ty: Type,
        reason: &'static str,
    },
}

impl Frame {
    pub fn ty(&self) -> Type {
        use self::Frame::*;
        match self {
            Padding => Type::PADDING,
            ResetStream { .. } => Type::RESET_STREAM,
            MaxData(_) => Type::MAX_DATA,
            MaxStreamData { .. } => Type::MAX_STREAM_DATA,
            MaxStreams { .. } => Type::MAX_STREAMS,
            Ping => Type::PING,
            DataBlocked { .. } => Type::DATA_BLOCKED,
            StreamDataBlocked { .. } => Type::STREAM_DATA_BLOCKED,
            StreamsBlocked { .. } => Type::STREAMS_BLOCKED,
            StopSending { .. } => Type::STOP_SENDING,
            Ack(_) => Type::ACK,
            Stream(stream) => {
                let mut ty = *STREAM_TYS.start();
                if stream.fin {
                    ty |= 0x01;
                }
                //0x02 len
                if stream.addr_off.is_left() {
                    ty |= 0x04;
                }
                Type(ty)
            }
            Datagram(datagram) => {
                let mut ty = *DATAGRAM_TYS.start();
                if datagram.addr.addr.is_some() {
                    ty |= 0x01;
                }
                //0x02 len
                Type(ty)
            }
            MaxDatagrams(_) => Type::MAX_DATAGRAMS,
            DatagramClosed { .. } => Type::DATAGRAM_CLOSED,
            DatagramsBlocked(_) => Type::DATAGRAMS_BLOCKED,
            Invalid { ty, .. } => ty,
        }
    }
    pub fn is_stream_frame(&self) -> bool {
        use self::Frame::*;
        match self {
            ResetStream { .. }
            | MaxData(_)
            | MaxStreamData { .. }
            | MaxStreams { .. }
            | DataBlocked { .. }
            | StreamDataBlocked { .. }
            | StreamsBlocked { .. }
            | StopSending { .. }
            | Stream(_) => true,
            _ => false,
        }
    }
    pub fn is_datagram_frame(&self) -> bool {
        use self::Frame::*;
        match self {
            DatagramClosed { .. } | DatagramsBlocked(_) | MaxDatagrams(_) | Datagram(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ack {
    pub largest: u64,
    pub delay: u64,
    pub additional: Bytes,
}

impl<'a> IntoIterator for &'a Ack {
    type Item = RangeInclusive<u64>;
    type IntoIter = AckIter<'a>;

    fn into_iter(self) -> AckIter<'a> {
        AckIter::new(self.largest, &self.additional[..])
    }
}

impl Ack {
    pub fn encode<W: BufMut>(delay: u64, ranges: &RangeSet, buf: &mut W) {
        let mut rest = ranges.iter().rev();
        let first = rest.next().unwrap();
        let largest = first.end - 1;
        let first_size = first.end - first.start;
        buf.write(Type::ACK);
        buf.write_var(largest);
        buf.write_var(delay);
        buf.write_var(ranges.len() as u64 - 1);
        buf.write_var(first_size - 1);
        let mut prev = first.start;
        for block in rest {
            let size = block.end - block.start;
            buf.write_var(prev - block.end - 1);
            buf.write_var(size - 1);
            prev = block.start;
        }
    }

    pub fn iter(&self) -> AckIter<'_> {
        self.into_iter()
    }
}

#[derive(Debug, Clone)]
pub struct PackAddr {
    addr_idx: u8,
    addr: Option<Address>,
}

impl PackAddr {
    fn size(&self) -> usize {
        1 + if let Some(addr) = self.addr {
            addr.size()
        } else {
            0
        }
    }
}

impl Codec for PackAddr {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        let fst_u8: u8 = buf.get()?;
        let contain_addr = fst_u8 & 0x80 == 1;
        let idx = fst_u8 & 0x7f;
        Ok(if contain_addr {
            let addr: Address = buf.get()?;
            PackAddr {
                addr_idx: idx,
                addr: Some(addr),
            }
        } else {
            PackAddr {
                addr_idx: idx,
                addr: None,
            }
        })
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self.addr {
            Some(addr) => {
                buf.write(self.addr_idx | 0x80);
                buf.write(addr);
            }
            None => {
                buf.write(self.addr_idx);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Stream {
    pub id: u64,
    pub addr_off: Either<u64, Address>,
    pub fin: bool,
    pub data: Bytes,
}

impl Stream {
    pub fn encode<W: BufMut>(&self, length: bool, out: &mut W) {
        let mut ty = *STREAM_TYS.start();
        if self.addr_off.is_left() {
            ty |= 0x04;
        }
        if length {
            ty |= 0x02;
        }
        if self.fin {
            ty |= 0x01;
        }
        out.write_var(ty);
        out.write_var(self.id);
        if let Some(off) = self.addr_off.left() {
            if off != 0 {
                out.write_var(off);
            }
        } else if let Some(addr) = self.addr_off.right() {
            out.write(addr);
        }
        if length {
            out.write_var(self.data.len() as u64); // <=8 bytes
        }
        out.put_slice(&self.data);
    }
    pub fn get_addr_off(addr: &Address, offset: u64, is_client: bool) -> Either<u64, Address> {
        if offset == 0 {
            Either::Right(addr.clone())
        } else {
            Either::Left(offset)
        }
    }
}

pub struct Iter {
    // TODO: ditch io::Cursor after bytes 0.5
    bytes: io::Cursor<Bytes>,
    last_ty: Option<Type>,
}

enum IterErr {
    UnexpectedEnd,
    InvalidFrameId,
    Malformed,
}

impl IterErr {
    fn reason(&self) -> &'static str {
        use self::IterErr::*;
        match *self {
            UnexpectedEnd => "unexpected end",
            InvalidFrameId => "invalid frame ID",
            Malformed => "malformed",
        }
    }
}

impl From<UnexpectedEnd> for IterErr {
    fn from(_: UnexpectedEnd) -> Self {
        IterErr::UnexpectedEnd
    }
}

impl Iter {
    pub fn new(payload: Bytes) -> Self {
        Iter {
            bytes: io::Cursor::new(payload),
            last_ty: None,
        }
    }

    fn take_len(&mut self) -> Result<Bytes, UnexpectedEnd> {
        let len = self.bytes.get_var()?;
        if len > self.bytes.remaining() as u64 {
            return Err(UnexpectedEnd);
        }
        let start = self.bytes.position() as usize;
        self.bytes.advance(len as usize);
        Ok(self.bytes.get_ref().slice(start..(start + len as usize)))
    }
    ///decode place
    fn try_next(&mut self) -> Result<Frame, IterErr> {
        let ty = self.bytes.get::<Type>()?;
        self.last_ty = Some(ty);
        Ok(match ty {
            Type::PADDING => Frame::Padding,
            Type::RESET_STREAM => Frame::ResetStream {
                id: self.bytes.get_var()?,
                error_code: self.bytes.get_var()?,
                final_offset: self.bytes.get_var()?,
            },
            Type::MAX_DATA => Frame::MaxData(self.bytes.get_var()?),
            Type::MAX_STREAM_DATA => Frame::MaxStreamData {
                id: self.bytes.get_var()?,
                offset: self.bytes.get_var()?,
            },
            Type::MAX_STREAMS => Frame::MaxStreams(self.bytes.get_var()?),
            Type::PING => Frame::Ping,
            Type::DATA_BLOCKED => Frame::DataBlocked(self.bytes.get_var()?),
            Type::STREAM_DATA_BLOCKED => Frame::StreamDataBlocked {
                id: self.bytes.get_var()?,
                offset: self.bytes.get_var()?,
            },
            Type::STREAMS_BLOCKED => Frame::StreamsBlocked(self.bytes.get_var()?),
            Type::STOP_SENDING => Frame::StopSending {
                id: self.bytes.get_var()?,
                error_code: self.bytes.get_var()?,
            },
            Type::ACK => {
                let largest = self.bytes.get_var()?;
                let delay = self.bytes.get_var()?;
                let extra_blocks = self.bytes.get_var()? as usize;
                let start = self.bytes.position() as usize;
                let len = scan_ack_blocks(&self.bytes.bytes()[..], largest, extra_blocks)
                    .ok_or(UnexpectedEnd)?;
                self.bytes.advance(len);
                Frame::Ack(Ack {
                    delay,
                    largest,
                    additional: self.bytes.get_ref().slice(start..(start + len)),
                })
            }
            Type::MAX_DATAGRAMS => Frame::MaxDatagrams(self.bytes.get_var()?),
            Type::DATAGRAM_CLOSED => Frame::DatagramClosed {
                id: self.bytes.get_var()?,
                error_code: self.bytes.get_var()?,
            },
            //can not add datagram id
            Type::DATAGRAMS_BLOCKED => Frame::DatagramsBlocked(self.bytes.get_var()?),
        })
    }

    fn take_remaining(&mut self) -> Bytes {
        let mut x = mem::replace(self.bytes.get_mut(), Bytes::new());
        x.advance(self.bytes.position() as usize);
        self.bytes.set_position(0);
        x
    }
}

impl Iterator for Iter {
    type Item = Frame;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.bytes.has_remaining() {
            return None;
        }
        match self.try_next() {
            Ok(x) => Some(x),
            Err(e) => {
                // Corrupt frame, skip it and everything that follows
                self.bytes = io::Cursor::new(Bytes::new());
                Some(Frame::Invalid {
                    ty: self.last_ty.unwrap(),
                    reason: e.reason(),
                })
            }
        }
    }
}

fn scan_ack_blocks(packet: &[u8], largest: u64, n: usize) -> Option<usize> {
    let mut buf = io::Cursor::new(packet);
    let first_block = buf.get_var().ok()?;
    let mut smallest = largest.checked_sub(first_block)?;
    for _ in 0..n {
        let gap = buf.get_var().ok()?;
        smallest = smallest.checked_sub(gap + 2)?;
        let block = buf.get_var().ok()?;
        smallest = smallest.checked_sub(block)?;
    }
    Some(buf.position() as usize)
}

#[derive(Debug, Clone)]
pub struct AckIter<'a> {
    largest: u64,
    data: io::Cursor<&'a [u8]>,
}

impl<'a> AckIter<'a> {
    fn new(largest: u64, payload: &'a [u8]) -> Self {
        let data = io::Cursor::new(payload);
        Self { largest, data }
    }
}

impl<'a> Iterator for AckIter<'a> {
    type Item = RangeInclusive<u64>;
    fn next(&mut self) -> Option<RangeInclusive<u64>> {
        if !self.data.has_remaining() {
            return None;
        }
        let block = self.data.get_var().unwrap();
        let largest = self.largest;
        if let Ok(gap) = self.data.get_var() {
            self.largest -= block + gap + 2;
        }
        Some(largest - block..=largest)
    }
}

/// An unreliable datagram
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Payload
    id: u64,
    addr: PackAddr,
    data: Bytes,
}

impl Datagram {
    fn encode<W: BufMut>(&self, length: bool, out: &mut W) {
        let mut ty = *DATAGRAM_TYS.start();
        if !(self.addr.addr_idx == 0 && self.addr.addr.is_none()) {
            ty |= 0x03;
        }
        if length {
            ty |= 0x01;
        }
        out.write_var(ty);
        out.write_var(self.id);
        out.write(self.addr);
        if length {
            out.write_var(self.data.len() as u64)
        }
        out.put_slice(&self.data);
    }

    fn size(&self, length: bool) -> usize {
        let len_field_len: usize = if length {
            VarInt::from_u64(self.data.len() as u64).unwrap().size()
        } else {
            0
        };
        let id_field_len = VarInt::from_u64(self.id).unwrap().size();
        let addr_field_len: usize = if self.addr.addr_idx == 0 && self.addr.addr.is_none() {
            0
        } else {
            self.addr.size()
        };
        1 + addr_field_len + len_field_len + id_field_len + self.data.len()
    }
}
