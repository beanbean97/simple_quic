use std::{
  cmp,
  collections::{BTreeMap, HashSet, VecDeque},
  fmt, io, mem,
  net::SocketAddr,
  sync::Arc,
  time::{Duration, Instant},
};

use super::{share::TransportConfig,timer::{Timer, TimerTable},space::{PacketSpace, Retransmits, SentPacket}};
use bytes::{Bytes, BytesMut};

pub struct Config{
    datagram:Arc<DatagramConfig>,
    stream:Arc<StreamConfig>,
    
}


pub struct ClientConnection {
  config: Arc<Config>,
  path: PathData,
  space: PackageSpace,
  streams: ClientStreams,
  datagrams: ClientDatagrams,
  timers: TimerTable,
  events: VecDeque<Event>,
  in_flight: InFlight,
  dedup: Dedup,
  largest_rev_package: u64,
  largest_rev_package_time: Instant,
  pending: Pending,
  
  next_packet_number: u64,
  largest_acked_packet: Option<u64>,
  largest_acked_packet_sent: Instant,
  sent_packets: BTreeMap<u64, SentPacket>,
  time_of_last_sent_ack_eliciting_packet: Option<Instant>,
  /// The time at which the earliest sent packet in this space will be considered lost based on
  /// exceeding the reordering window in time. Only set for packets numbered prior to a packet
  /// that has been acknowledged.
  loss_time: Option<Instant>,
  loss_probes: u32,
  pto_count: u32,
}

impl ClientConnection
{

    fn get_tx_number(&mut self) -> u64 {
        let x = self.next_packet_number;
        self.next_packet_number += 1;
        x
      }
      fn can_send(&self) -> bool {
        self.pending.ping || (self.permit_ack_only && !self.pending.acks.is_empty())
      }
    fn on_packet_sent(
        &mut self,
        now: Instant,
        packet_number: u64,
        packet: SentPacket,
    ) {
        let SentPacket {
            size,
            ack_eliciting,
            ..
        } = packet;

        self.in_flight.insert(&packet);
        self.space
            .sent_packets
            .insert(packet_number, packet);
        if size != 0 {
            if ack_eliciting {
              self.package_space.time_of_last_sent_ack_eliciting_packet = Some(now);
            }
            self.set_loss_detection_timer();
        }
    }

    fn on_ack_received(
        &mut self,
        now: Instant,
        ack: frame::Ack,
    ) -> Result<(), TransportError> {
        if ack.largest >= self.package_space.next_packet_number {
            return Err(TransportError::PROTOCOL_VIOLATION("unsent packet acked"));
        }
        let new_largest = {
            if self.space.largest_acked_packet.map_or(true, |pn| ack.largest > pn)
            {
                self.space.largest_acked_packet = Some(ack.largest);
                if let Some(sent_packet) = self.space.sent_packets.get(&ack.largest) {
                    // This should always succeed, but a misbehaving peer might ACK a packet we
                    // haven't sent. At worst, that will result in us spuriously reducing the
                    // congestion window.
                    self.space.largest_acked_packet_sent = sent_packet.time_sent;
                }
                true
            } else {
                false
            }
        };

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let newly_acked = ack
            .iter()
            .flat_map(|range| self.space.sent_packets.range(range).map(|(&n, _)| n))
            .collect::<Vec<_>>();
        if newly_acked.is_empty() {
            return Ok(());
        }

        let mut ack_eliciting_acked = false;
        for &packet in &newly_acked {
            if let Some(package) = self.space.sent_packets.remove(&packet) {
                self.space.pending.acks.subtract(&package.acks);
                ack_eliciting_acked |= package.ack_eliciting;
                self.in_flight.remove(&package);
                for (id, _) in package.retransmits.reset_stream {
                }
                for frame in package.retransmits.stream {
                }
                for frame in package.datagram {
                }
            }
        }

        if new_largest && ack_eliciting_acked {
            let ack_delay = cmp::min(
              self.max_ack_delay(),
              Duration::from_micros(ack.delay << self.params.ack_delay_exponent),
            );
            let rtt = instant_saturating_sub(now, self.space.largest_acked_packet_sent);
            self.path.rtt.update(ack_delay, rtt);
        }

        // Must be called before pto_count are clobbered
        self.detect_lost_packets(now);//!IMPO

        self.pto_count = 0;

        self.set_loss_detection_timer();//!IMPO
        Ok(())
    }


    /// Process timer expirations
    ///
    /// Executes protocol logic, potentially preparing signals (including application `Event`s,
    /// `EndpointEvent`s and outgoing datagrams) that should be extracted through the relevant
    /// methods.
    pub fn handle_timeout(&mut self, now: Instant) {
        for &timer in &Timer::VALUES {
            if !self.timers.is_expired(timer, now) {
                continue;
            }
            self.timers.stop(timer);
            trace!(timer = ?timer, "timeout");
            match timer {
                Timer::LossDetection => {
                    self.on_loss_detection_timeout(now);
                }
            }
        }
    }

    fn on_loss_detection_timeout(&mut self, now: Instant) {
        if let Some((_, pn_space)) = self.earliest_time_and_space(|x| x.loss_time) {
            // Time threshold loss Detection
            self.detect_lost_packets(now, pn_space);
            self.set_loss_detection_timer();
            return;
        }

        // Send two probes to improve odds of getting through under lossy conditions
        let space = self
            .earliest_time_and_space(|x| x.time_of_last_sent_ack_eliciting_packet)
            .map(|(_, space)| space)
            .unwrap_or_else(|| {
                // PTO expired with no sent ack-eliciting packets! This should only happen on a
                // client that's discarded the initial packet space but hasn't received enough data
                // from the server to send an ack-eliciting handshake packet
                // yet. https://github.com/quicwg/base-drafts/pull/3162 will change the behavior
                // here, but for now we generate an anti-amplification packet at handshake level.
                debug_assert!(self.side.is_client() && self.highest_space == SpaceId::Handshake);
                SpaceId::Handshake
            });
        trace!(
            in_flight = self.in_flight.bytes,
            count = self.pto_count,
            ?space,
            "PTO fired"
        );
        self.space_mut(space).loss_probes = self.space(space).loss_probes.saturating_add(2);
        self.pto_count = self.pto_count.saturating_add(1);
        self.set_loss_detection_timer();
    }

    fn ensure_probe_queued(&mut self) {
        // Retransmit the data of the oldest in-flight packet
        if !self.space.pending.is_empty() {
            // There's real data to send here, no need to make something up
            return;
        }
        for packet in self.space.sent_packets.values_mut() {
            if !packet.retransmits.is_empty() {
                // Remove retransmitted data from the old packet so we don't end up retransmitting
                // it *again* even if the copy we're sending now gets acknowledged.
                self.space.pending += mem::take(&mut packet.retransmits);
                return;
            }
        }
        // Nothing new to send and nothing to retransmit, so fall back on a ping. This should only
        // happen in rare cases during the handshake when the server becomes blocked by
        // anti-amplification.
        self.space.ping_pending = true;
    }

    fn detect_lost_packets(&mut self, now: Instant) {
        let mut lost_packets = Vec::<u64>::new();
        let rtt = self
            .path
            .rtt
            .smoothed
            .map_or(self.path.rtt.latest, |x| cmp::max(x, self.path.rtt.latest));
        let loss_delay = cmp::max(rtt.mul_f32(self.config.time_threshold), TIMER_GRANULARITY);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now - loss_delay;
        let largest_acked_packet = self.space.largest_acked_packet.unwrap();
        let packet_threshold = self.config.packet_threshold as u64;

        self.space.loss_time = None;
        for (&packet, info) in self.space.sent_packets.range(0..largest_acked_packet) {
            //？？&&
            if info.time_sent <= lost_send_time || largest_acked_packet >= packet + packet_threshold
            {
                lost_packets.push(packet);
            } else {
                let next_loss_time = info.time_sent + loss_delay;
                self.space.loss_time = Some(
                    space
                        .loss_time
                        .map_or(next_loss_time, |x| cmp::min(x, next_loss_time)),
                );
            }
        }

        // OnPacketsLost
        if let Some(largest_lost) = lost_packets.last().cloned() {
            let old_bytes_in_flight = self.in_flight.bytes;
            let largest_lost_sent = self.space.sent_packets[&largest_lost].time_sent;
            //丢包统计
            self.path.lost_packets += lost_packets.len() as u64;
            trace!("packets lost: {:?}", lost_packets);
            for packet in &lost_packets {
                let info = self.sapce.
                    .sent_packets
                    .remove(&packet)
                    .unwrap(); // safe: lost_packets is populated just above
                self.in_flight.remove(&info);
                //重传
                self.sapce.pending += info.retransmits;
            }
        }
    }

    fn set_loss_detection_timer(&mut self) {
        if let Some(loss_time) = self.space.loss_time{
            // Time threshold loss detection.
            self.timers.set(Timer::LossDetection, loss_time);
            return;
        }
        // Don't arm timer if there are no ack-eliciting packets
        // in flight and the handshake is complete.
        if self.in_flight.ack_eliciting == 0 {
            self.timers.stop(Timer::LossDetection);
            return;
        }
        // Calculate PTO duration
        if let Some(sent_time) =  self.space.time_of_last_sent_ack_eliciting_packet        {
            /// Probe Timeout
            let pto =  match self.path.rtt.smoothed {
                None => 2 * self.config.initial_rtt,
                Some(srtt) => {
                    srtt + cmp::max(4 * self.path.rtt.var, TIMER_GRANULARITY) + self.max_ack_delay()
                }
            }
            let timeout = pto * 2u32.pow(cmp::min(self.pto_count, MAX_BACKOFF_EXPONENT));
            self.timers.set(Timer::LossDetection, sent_time + timeout);
        } else {
            // Arises at least due to https://github.com/quicwg/base-drafts/issues/3502
            self.timers.stop(Timer::LossDetection);
        }
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        mut packet: Packet,
    ) {
        if self.space.dedup.insert(packet.pkg_number){
            //重复Pkg num
        }  
        let space = &mut self.space;
        space.pending_acks.insert_one(packet);
        if space.pending_acks.len() > MAX_ACK_BLOCKS {
            space.pending_acks.pop_min();
        }
        if packet >= space.rx_packet {
            space.largest_rev_package = packet;
            space.largest_rev_package_time = now;
        }
        for frame in frame::Iter::new(packet.payload) {
            // Check for ack-eliciting frames
            match frame {
                //TODO 检查DATAGRAM 是否包含非idx addr
                Frame::Ack(_) | Frame::Padding => {}
                _ => {
                    &mut self.space.permit_ack_only = true;
                }
            }
            match frame {
                Frame::Ack(ack) => {
                    self.on_ack_received(now, SpaceId::Data, ack)?;
                }
                //TODO 添加其他类型
            }

        }
    }

    /// Returns packets to transmit
    ///
    /// Connections should be polled for transmit after:
    /// - the application performed some I/O on the connection
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    fn poll_transmit(&mut self, now: Instant) -> Option<Package> {

        // If we need to send a probe, make sure we have something to send.
        if self.space.loss_probes != 0 {
            self.ensure_probe_queued();
        }

        // Select the set of spaces that have data to send so we can try to coalesce them
        let can_send = self.space.can_send();

        let mut buf = Vec::with_capacity(self.mtu as usize);
        let mut coalesce = spaces.len() > 1;//!do not need we only have one spaces

        let buf_start = buf.len();

        let mut ack_eliciting = !self.space.pending.is_empty() || self.space.ping_pending;
        // Tail loss probes must not be blocked by congestion, or a deadlock could arise
        if ack_eliciting && self.space.loss_probes == 0
        {
            return;
        }

        //
        // From here on, we've determined that a packet will definitely be sent.
        //
        self.space.loss_probes = self.space.loss_probes.saturating_sub(1);
        let exact_number = self.space.get_tx_number();
        let number = PacketNumber::new(exact_number, self.space.largest_acked_packet.unwrap_or(0));
        let sent = Some(self.populate_packet(&mut buf));

        let pn_len = number.len();//!always 16

        if let Some((sent, acks)) = sent {
            // If we sent any acks, don't immediately resend them. Setting this even if ack_only is
            // false needlessly prevents us from ACKing the next packet if it's ACK-only, but saves
            // the need for subtler logic to avoid double-transmitting acks all the time.
            space.permit_ack_only &= acks.is_empty();

            self.on_packet_sent(
                now,
                exact_number,
                SentPacket {
                    acks,
                    time_sent: now,
                    size: if padded || ack_eliciting {
                        buf.len() as u16
                    } else {
                        0
                    },
                    ack_eliciting,
                    retransmits: sent,
                },
            );
        }

        if buf.is_empty() {
            return None;
        }

        trace!("sending {} byte datagram", buf.len());

    }

    fn populate_packet(&mut self, buf: &mut Vec<u8>) -> (Retransmits, RangeSet) {
        let mut sent = SentPacket::default();
        if mem::replace(&mut space.ping_pending, false) {
            trace!("PING");
            buf.write(frame::Type::PING);
        }
        // ACK
        let acks = if !space.pending_acks.is_empty() {
            trace!("ACK");
            frame::Ack::encode(0, &space.pending_acks, buf);
            space.pending_acks.clone()
        } else {
            RangeSet::new()
        };

        // RESET_STREAM
        while buf.len() + frame::ResetStream::SIZE_BOUND < max_size {
            let (id, error_code) = match space.pending.reset_stream.pop() {
                Some(x) => x,
                None => break,
            };
            let stream = match self.streams.send_mut(id) {
                Some(x) => x,
                None => continue,
            };
            trace!(stream = %id, "RESET_STREAM");
            sent.reset_stream.push((id, error_code));
            frame::ResetStream {
                id,
                error_code,
                final_offset: stream.offset,
            }
            .encode(buf);
        }

        // STOP_SENDING
        while buf.len() + frame::StopSending::SIZE_BOUND < max_size {
            let frame = match space.pending.stop_sending.pop() {
                Some(x) => x,
                None => break,
            };
            let stream = match self.streams.recv_mut(frame.id) {
                Some(x) => x,
                None => continue,
            };
            if stream.is_finished() {
                continue;
            }
            trace!(stream = %frame.id, "STOP_SENDING");
            frame.encode(buf);
            sent.stop_sending.push(frame);
        }

        // MAX_DATA
        if space.pending.max_data && buf.len() + 9 < max_size {
            trace!(value = self.local_max_data, "MAX_DATA");
            space.pending.max_data = false;
            sent.max_data = true;
            buf.write(frame::Type::MAX_DATA);
            buf.write_var(self.local_max_data);
        }

        // MAX_STREAM_DATA
        while buf.len() + 17 < max_size {
            let id = match space.pending.max_stream_data.iter().next() {
                Some(x) => *x,
                None => break,
            };
            space.pending.max_stream_data.remove(&id);
            let rs = match self.streams.recv_mut(id) {
                Some(x) => x,
                None => continue,
            };
            if rs.is_finished() {
                continue;
            }
            sent.max_stream_data.insert(id);
            let max = rs.bytes_read + self.config.stream_receive_window;
            trace!(stream = %id, max = max, "MAX_STREAM_DATA");
            buf.write(frame::Type::MAX_STREAM_DATA);
            buf.write(id);
            buf.write_var(max);
        }


        // MAX_STREAMS_BIDI
        if space.pending.max_bi_stream_id && buf.len() + 9 < max_size {
            space.pending.max_bi_stream_id = false;
            sent.max_bi_stream_id = true;
            trace!(
                value = self.streams.max_remote[Dir::Bi as usize],
                "MAX_STREAMS (bidirectional)"
            );
            buf.write(frame::Type::MAX_STREAMS_BIDI);
            buf.write_var(self.streams.max_remote[Dir::Bi as usize]);
        }

        // DATAGRAM
        while buf.len() + Datagram::SIZE_BOUND < max_size {
            let datagram = match self.datagrams.outgoing.pop_front() {
                Some(x) => x,
                None => break,
            };
            if buf.len() + datagram.size(true) > max_size {
                // Future work: we could be more clever about cramming small datagrams into
                // mostly-full packets when a larger one is queued first
                self.datagrams.outgoing.push_front(datagram);
                break;
            }
            self.datagrams.outgoing_total -= datagram.data.len();
            datagram.encode(true, buf);
        }

        // STREAM
        while buf.len() + frame::Stream::SIZE_BOUND < max_size {
            let mut stream = match space.pending.stream.pop_front() {
                Some(x) => x,
                None => break,
            };
            if self
                .streams
                .send_mut(stream.id)
                .map_or(true, |s| s.state.was_reset())
            {
                self.unacked_data -= stream.data.len() as u64;
                continue;
            }
            let len = cmp::min(
                stream.data.len(),
                max_size as usize - buf.len() - frame::Stream::SIZE_BOUND,
            );
            let data = stream.data.split_to(len);
            let fin = stream.fin && stream.data.is_empty();
            trace!(id = %stream.id, off = stream.offset, len, fin, "STREAM");
            let frame = frame::Stream {
                id: stream.id,
                offset: stream.offset,
                fin,
                data,
            };
            frame.encode(true, buf);
            sent.stream.push_back(frame);
            if !stream.data.is_empty() {
                stream.offset += len as u64;
                space.pending.stream.push_front(stream);
            }
        }

        (sent, acks)
    }

}

pub struct Pending {
    ping: bool,
    acks: RangeSet,
    permit_ack_only: bool,
  }
  
  impl Pending {
    fn new() -> Self {
      Self {
        ping: false,
        acks: RangeSet::new(),
      }
    }
    fn is_empty() -> bool {}
  }
  

struct PlrEstimator {
  /// Total number of outgoing packets that have been deemed lost
  lost: u64,
  total: u64,
  recent: f32,
  smoothed: f32,
}

#[derive(Copy, Clone)]
struct RttEstimator {
    /// The most recent RTT measurement made when receiving an ack for a previously unacked packet
    latest: Duration,
    /// The smoothed RTT of the connection, computed as described in RFC6298
    smoothed: Option<Duration>,
    /// The RTT variance, computed as described in RFC6298
    var: Duration,
    /// The minimum RTT seen in the connection, ignoring ack delay.
    min: Duration,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            latest: Duration::new(0, 0),
            smoothed: None,
            var: Duration::new(0, 0),
            min: Duration::new(u64::max_value(), 0),
        }
    }

    fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.latest = rtt;
        // min_rtt ignores ack delay.
        self.min = cmp::min(self.min, self.latest);
        // Adjust for ack delay if it's plausible.
        if self.latest - self.min > ack_delay {
            self.latest -= ack_delay;
        }
        // Based on RFC6298.
        if let Some(smoothed) = self.smoothed {
            let var_sample = if smoothed > self.latest {
                smoothed - self.latest
            } else {
                self.latest - smoothed
            };
            self.var = (3 * self.var + var_sample) / 4;
            self.smoothed = Some((7 * smoothed + self.latest) / 8);
        } else {
            self.smoothed = Some(self.latest);
            self.var = self.latest / 2;
        }
    }
}

struct InFlight {
  /// Sum of the sizes of all sent packets considered "in flight" by congestion control
  ///
  /// The size does not include IP or UDP overhead. Packets only containing ACK frames do not
  /// count towards this to ensure congestion control does not impede congestion feedback.
  bytes: u64,
  /// Number of packets in flight containing frames other than ACK and PADDING
  ///
  /// This can be 0 even when bytes is not 0 because PADDING frames cause a packet to be
  /// considered "in flight" by congestion control. However, if this is nonzero, bytes will always
  /// also be nonzero.
  ack_eliciting: u64,
}

impl InFlight {
  pub fn new() -> Self {
      Self {
          bytes: 0,
          ack_eliciting: 0,
      }
  }

  fn insert(&mut self, packet: &SentPacket) {
      self.bytes += u64::from(packet.size);
      self.ack_eliciting += u64::from(packet.ack_eliciting);
  }

  /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
  fn remove(&mut self, packet: &SentPacket) {
      self.bytes -= u64::from(packet.size);
      self.ack_eliciting -= u64::from(packet.ack_eliciting);
  }
}


struct PathData {
  ///round-trip time
  rtt: RttEstimator,
  ///package loss rate
  plr: PlrEstimator,
  mtu:u16,
  in_flight:InFlight,
  //抖动，带宽
}
  

/// Events of interest to the application
#[derive(Debug)]
pub enum Event {
    /// One or more new streams has been opened
    StreamOpened(u64),
    /// A currently open stream has data or errors waiting to be read
    StreamReadable(u64),
    /// A formerly write-blocked stream might be ready for a write or have been stopped
    ///
    /// Only generated for streams that are currently open.
    StreamWritable(u64),
    /// A finished stream has been fully acknowledged or stopped
    StreamFinished {
        /// Which stream has been finished
        id: u64,
        /// Error code supplied by the peer if the stream was stopped
        stop_reason: Option<u64>,
    },
    /// At least one new stream of a certain directionality may be opened
    StreamAvailable,
    /// One or more application datagrams have been received
    DatagramOpened(u64),
    DatagramReceived(u64),
    DatagramAvailable,
}