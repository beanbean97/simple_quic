use std::{
  cmp,
  collections::{BTreeMap, HashSet, VecDeque},
  mem,
  time::Instant,
};

use super::{frame, range_set::RangeSet};
use bytes::Bytes;

pub struct Dedup {
  window: Window,
  next: u64,
}

type Window = u128;

const WINDOW_SIZE: u64 = 1 + mem::size_of::<Window>() as u64 * 8;

impl Dedup {
  /// Construct an empty window positioned at the start.
  pub fn new() -> Self {
    Self { window: 0, next: 0 }
  }

  /// Highest packet number authenticated.
  fn highest(&self) -> u64 {
    self.next - 1
  }

  /// Record a newly authenticated packet number.
  ///
  /// Returns whether the packet might be a duplicate.
  pub fn insert(&mut self, packet: u64) -> bool {
    if let Some(diff) = packet.checked_sub(self.next) {
      // Right of window
      self.window = (self.window << 1 | 1)
        .checked_shl(cmp::min(diff, u64::from(u32::max_value())) as u32)
        .unwrap_or(0);
      self.next = packet + 1;
      false
    } else if self.highest() - packet < WINDOW_SIZE {
      // Within window
      if let Some(bit) = (self.highest() - packet).checked_sub(1) {
        // < highest
        let mask = 1 << bit;
        let duplicate = self.window & mask != 0;
        self.window |= mask;
        duplicate
      } else {
        // == highest
        true
      }
    } else {
      // Left of window
      true
    }
  }
}
