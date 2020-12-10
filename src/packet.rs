use std::{cmp::Ordering, io, ops::Range, str};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use err_derive::Error;

use crate::{
    coding::{self, BufExt, BufMutExt},
    crypto,
    shared::ConnectionId,
    MAX_CID_SIZE, VERSION,
};

// Due to packet number encryption, it is impossible to fully decode a header
// (which includes a variable-length packet number) without crypto context.
// The crypto context (represented by the `Crypto` type in Quinn) is usually
// part of the `Connection`, or can be derived from the destination CID for
// Initial packets.
//
// To cope with this, we decode the invariant header (which should be stable
// across QUIC versions), which gives us the destination CID and allows us
// to inspect the version and packet type (which depends on the version).
// This information allows us to fully decode and decrypt the packet.

/// Represents one or more packets subject to retransmission
#[derive(Debug, Clone)]
pub struct SentPacket {
    time_sent: Instant,
    size: u16,
    ack_eliciting: bool,
    acks: RangeSet,
    max_data: bool,
    max_stream_id: bool,
    stream: VecDeque<frame::Stream>,
    reset_stream: Vec<(u64, u64, u64)>,
    stop_sending: Vec<(u64, u64)>,
    max_stream_data: HashSet<u64>,
    datagram: Vec<(u64, u8)>,
    datagram_closed: HashSet<u64>,
    max_datagram_id: bool,
}

pub struct Packet {
    header: Bytes,
    payload: Bytes,
}

// An encoded packet number
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum PacketNumber {
    U8(u8),
    U16(u16),
    U24(u32),
    U32(u32),
}

impl PacketNumber {
    pub(crate) fn new(n: u64, largest_acked: u64) -> Self {
        let range = (n - largest_acked) * 2;
        if range < 1 << 8 {
            PacketNumber::U8(n as u8)
        } else if range < 1 << 16 {
            PacketNumber::U16(n as u16)
        } else if range < 1 << 24 {
            PacketNumber::U24(n as u32)
        } else if range < 1 << 32 {
            PacketNumber::U32(n as u32)
        } else {
            panic!("packet number too large to encode")
        }
    }

    pub(crate) fn len(self) -> usize {
        use self::PacketNumber::*;
        match self {
            U8(_) => 1,
            U16(_) => 2,
            U24(_) => 3,
            U32(_) => 4,
        }
    }

    pub(crate) fn encode<W: BufMut>(self, w: &mut W) {
        use self::PacketNumber::*;
        match self {
            U8(x) => w.write(x),
            U16(x) => w.write(x),
            U24(x) => w.put_uint(u64::from(x), 3),
            U32(x) => w.write(x),
        }
    }

    pub(crate) fn decode<R: Buf>(len: usize, r: &mut R) -> Result<PacketNumber, PacketDecodeError> {
        use self::PacketNumber::*;
        let pn = match len {
            1 => U8(r.get()?),
            2 => U16(r.get()?),
            3 => U24(r.get_uint(3) as u32),
            4 => U32(r.get()?),
            _ => unreachable!(),
        };
        Ok(pn)
    }

    pub(crate) fn decode_len(tag: u8) -> usize {
        1 + (tag & 0x03) as usize
    }

    fn tag(self) -> u8 {
        use self::PacketNumber::*;
        match self {
            U8(_) => 0b00,
            U16(_) => 0b01,
            U24(_) => 0b10,
            U32(_) => 0b11,
        }
    }

    pub(crate) fn expand(self, expected: u64) -> u64 {
        // From Appendix A
        use self::PacketNumber::*;
        let truncated = match self {
            U8(x) => u64::from(x),
            U16(x) => u64::from(x),
            U24(x) => u64::from(x),
            U32(x) => u64::from(x),
        };
        let nbits = self.len() * 8;
        let win = 1 << nbits;
        let hwin = win / 2;
        let mask = win - 1;
        // The incoming packet number should be greater than expected - hwin and less than or equal
        // to expected + hwin
        //
        // This means we can't just strip the trailing bits from expected and add the truncated
        // because that might yield a value outside the window.
        //
        // The following code calculates a candidate value and makes sure it's within the packet
        // number window.
        let candidate = (expected & !mask) | truncated;
        if expected.checked_sub(hwin).map_or(false, |x| candidate <= x) {
            candidate + win
        } else if candidate > expected + hwin && candidate > win {
            candidate - win
        } else {
            candidate
        }
    }
}

pub(crate) const LONG_HEADER_FORM: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
pub(crate) const SPIN_BIT: u8 = 0x20;
const SHORT_RESERVED_BITS: u8 = 0x18;
const LONG_RESERVED_BITS: u8 = 0x0c;
const KEY_PHASE_BIT: u8 = 0x04;
