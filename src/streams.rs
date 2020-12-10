use crate::{
  assembler::Assembler, channel::Sender, connect::Event, frame, range_set::RangeSet, Address,
  TransportError,
};
use bytes::Bytes;
use err_derive::Error;
use std::{
  cmp,
  collections::{hash_map, HashMap, HashSet, VecDeque},
  sync::Arc,
};
use tracing::{debug, trace};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SendState {
  Ready,
  DataSent { finish_acked: bool },
  ResetSent { stop_reason: Option<u64> },
  DataRecvd,
  ResetRecvd { stop_reason: Option<u64> },
}

pub struct Send {
  pub offset: u64,
  pub max_data: u64,
  pub state: SendState,
  /// Number of bytes sent but unacked
  pub bytes_in_flight: u64,
}

impl Send {
  pub fn new(max_data: u64) -> Self {
    Self {
      offset: 0,
      max_data,
      state: SendState::Ready,
      bytes_in_flight: 0,
    }
  }

  pub fn write_budget(&mut self) -> Result<u64, WriteError> {
    if let Some(error_code) = self.take_stop_reason() {
      return Err(WriteError::Stopped(error_code));
    }
    let budget = self.max_data - self.offset;
    if budget == 0 {
      Err(WriteError::Blocked)
    } else {
      Ok(budget)
    }
  }

  /// All data acknowledged and STOP_SENDING error code, if any, processed by application
  pub fn is_closed(&self) -> bool {
    use self::SendState::*;
    match self.state {
      DataRecvd | ResetRecvd { stop_reason: None } => true,
      _ => false,
    }
  }

  pub fn finish(&mut self) -> Result<(), FinishError> {
    if self.state == SendState::Ready {
      self.state = SendState::DataSent {
        finish_acked: false,
      };
      Ok(())
    } else if let Some(error_code) = self.take_stop_reason() {
      Err(FinishError::Stopped(error_code))
    } else {
      Err(FinishError::UnknownStream)
    }
  }

  fn take_stop_reason(&mut self) -> Option<u64> {
    match self.state {
      SendState::ResetSent {
        ref mut stop_reason,
      }
      | SendState::ResetRecvd {
        ref mut stop_reason,
      } => Some(stop_reason),
      _ => None,
    }
  }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RecvState {
  //size is final offset
  Recv { size: Option<u64> },
  DataRecvd { size: u64 },
  ResetRecvd { size: u64, error_code: u64 },
  Closed,
}
pub struct Recv {
  state: RecvState,
  recvd: RangeSet,
  assembler: Assembler,
}

impl Recv {
  pub fn new() -> Self {
    Self {
      state: RecvState::Recv { size: None },
      recvd: RangeSet::new(),
      assembler: Assembler::new(),
    }
  }

  pub fn ingest(
    &mut self,
    frame: frame::Stream,
    received: u64,
    //全局
    max_data: u64,
    //局部
    receive_window: u64,
  ) -> Result<u64, TransportError> {
    let end = frame.offset + frame.data.len() as u64;
    if end >= 2u64.pow(62) {
      return Err(TransportError::FLOW_CONTROL_ERROR(
        "maximum stream offset too large",
      ));
    }
    if let Some(final_offset) = self.final_offset() {
      if end > final_offset || (frame.fin && end != final_offset) {
        debug!(end, final_offset, "final size error");
        return Err(TransportError::FINAL_SIZE_ERROR(""));
      }
    }

    let prev_end = self.limit();
    let new_bytes = end.saturating_sub(prev_end);
    let stream_max_data = self.assembler.offset + receive_window;
    if end > stream_max_data || received + new_bytes > max_data {
      debug!(stream = %frame.id, received, new_bytes, max_data, end, stream_max_data, "flow control error");
      return Err(TransportError::FLOW_CONTROL_ERROR(""));
    }

    if frame.fin {
      if let RecvState::Recv { ref mut size } = self.state {
        *size = Some(end);
      }
    }

    self.recvd.insert(frame.offset..end);
    if !frame.data.is_empty() {
      self.assembler.insert(frame.offset, frame.data);
    }

    if let RecvState::Recv { size: Some(size) } = self.state {
      if self.recvd.len() == 1 && self.recvd.iter().next().unwrap() == (0..size) {
        self.state = RecvState::DataRecvd { size };
      }
    }

    Ok(new_bytes)
  }

  pub fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
    let read = self.assembler.read(buf);
    if read > 0 {
      Ok(Some(read))
    } else {
      self.read_blocked().map(|()| None)
    }
  }

  fn read_blocked(&mut self) -> Result<(), ReadError> {
    match self.state {
      RecvState::ResetRecvd { error_code, .. } => {
        self.state = RecvState::Closed;
        Err(ReadError::Reset(error_code))
      }
      RecvState::Closed => panic!("tried to read from a closed stream"),
      RecvState::Recv { .. } => Err(ReadError::Blocked),
      RecvState::DataRecvd { .. } => {
        self.state = RecvState::Closed;
        Ok(())
      }
    }
  }

  pub fn receiving_unknown_size(&self) -> bool {
    match self.state {
      RecvState::Recv { size: None } => true,
      _ => false,
    }
  }

  /// No more data expected from peer
  pub fn is_finished(&self) -> bool {
    match self.state {
      RecvState::Recv { .. } => false,
      _ => true,
    }
  }

  /// All data read by application
  pub fn is_closed(&self) -> bool {
    self.state == self::RecvState::Closed
  }

  /// Offset after the largest byte received
  pub fn limit(&self) -> u64 {
    self.recvd.max().map_or(0, |x| x + 1)
  }

  pub fn final_offset(&self) -> Option<u64> {
    match self.state {
      RecvState::Recv { size } => size,
      RecvState::ResetRecvd { size, .. } => Some(size),
      RecvState::DataRecvd { size } => Some(size),
      _ => None,
    }
  }

  pub fn reset(&mut self, error_code: u64, final_offset: u64) {
    if self.is_closed() {
      return;
    }
    self.state = RecvState::ResetRecvd {
      size: final_offset,
      error_code,
    };
    // Nuke buffers so that future reads fail immediately, which ensures future reads don't
    // issue flow control credit redundant to that already issued. We could instead special-case
    // reset streams during read, but it's unclear if there's any benefit to retaining data for
    // reset streams.
    self.assembler.clear();
  }
}

#[derive(Debug, Clone)]
pub struct Pending {
  max_data: bool,
  max_stream_id: bool,
  stream: VecDeque<frame::Stream>,
  ///id error_code
  reset_stream: Vec<(u64, u64)>,
  ///id error_code
  stop_sending: Vec<(u64, u64)>,
  max_stream_data: HashSet<u64>,
}

impl Pending {
  fn new() -> Self {}
}

pub struct Stream {
  //客户端必然存在addr 服务器是option 有可能丢失offset 0
  proxy_addr: Option<Address>,
  recv: Recv,
  send: Send,
}

pub struct Config {}

pub struct Streams {
  streams: HashMap<u64, Stream>,
  config: Arc<Config>,
  ///connection level flow control blocked
  blocked_streams: HashSet<u64>,
  is_client: bool,
  //only valid in client
  max: u64,
  next: u64,
  //only valid in server
  next_remote: u64,
  max_remote: u64,
  next_reported_remote: u64,
  pending: Pending,
  /// Limit on outgoing data, dictated by peer
  max_data: u64,
  /// Sum of current offsets of all send streams.
  data_sent: u64,
  /// Sum of end offsets of all receive streams. Includes gaps, so it's an upper bound.
  data_recvd: u64,
  /// Limit on incoming data
  local_max_data: u64,
  /// Stream data we're sending that hasn't been acknowledged or reset yet
  unacked_data: u64,
  event_sender: Sender<Event>,
}

impl Streams {
  pub fn new(event_sender: Sender<Event>) -> Self {
    Self {
      streams: HashMap::default(),
      blocked_streams: HashSet::default(),
      next: 0,
      max: 0,
      max_data: 0,
      data_sent: 0,
      data_recvd: 0,
      local_max_data: 0,
      unacked_data: 0,
      next_remote: 0,
      next_reported_remote: 0,
      max_remote: 0,
      event_sender,
      pending: Pending::new(),
    }
  }
  pub fn open(&mut self, proxy_addr: Address) -> Option<u64> {
    // TODO: Queue STREAM_ID_BLOCKED if this fails
    if self.next >= self.max {
      return None;
    }
    let id = self.next;
    self.streams.insert(
      id,
      ClientStream {
        proxy_addr,
        send: Send::new(0), //TODO需要参数设置此max_data
        recv: Recv::new(),
      },
    );
    self.next += 1;
    self.active_streams += 1;
    Some(id)
  }
  pub fn maybe_cleanup(&mut self, id: u64) {
    match self.streams.entry(id) {
      hash_map::Entry::Vacant(_) => {}
      hash_map::Entry::Occupied(stream) => {
        if stream.get().recv.is_closed() && stream.get().send.is_closed() {
          self.active_streams -= 1;
          stream.remove_entry();
        }
      }
    }
  }
  pub fn finish(&mut self, id: u64) -> Result<(), FinishError> {
    let stream = self
      .streams
      .get_mut(&id)
      .ok_or(FinishError::UnknownStream)?;
    stream.send.finish()?;
    let modify_fin = false;
    for frame in &mut self.pending.stream {
      if frame.id == id
        && frame.addr_off.left().map_or(0, |v| v) + frame.data.len() as u64 == stream.send.offset
      {
        frame.fin = true;
        modify_fin = true;
        break;
      }
    }
    if !modify_fin {
      self.pending.stream.push_back(frame::Stream {
        id,
        data: Bytes::new(),
        addr_off: frame::Stream::get_addr_off(&stream.proxy_addr, stream.send.offset, true),
        fin: true,
      });
    }
    // We no longer need to notify the application of capacity for additional writes.
    self.blocked_streams.remove(&id);
    Ok(())
  }

  pub fn read(&mut self, id: u64, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
    let recv = self
      .streams
      .get_mut(&id)
      .ok_or(ReadError::UnknownStream)?
      .recv;
    let read_result = recv.read(buf);
    if let Err(ReadError::Reset { .. }) = read_result {
      self.maybe_cleanup(id);
    }
    Ok(match read_result? {
      Some(len) => {
        self.local_max_data += len as u64;
        self.pending.max_data = true;
        if recv.receiving_unknown_size() {
          // Only bother issuing stream credit if the peer wants to send more
          self.pending.max_stream_data.insert(id);
        }
        Some(len)
      }
      None => {
        self.maybe_cleanup(id);
        None
      }
    })
  }

  fn blocked(&self) -> bool {
    self.data_sent >= self.max_data || self.unacked_data >= self.config.send_window
  }

  fn queue_stream_data(&mut self, id: u64, data: Bytes) -> Result<(), WriteError> {
    let stream = self.streams.get_mut(&id).ok_or(WriteError::UnknownStream)?;
    let send = stream.send;
    assert_eq!(send.state, SendState::Ready);
    let old_offset = send.offset;
    send.offset += data.len() as u64;
    send.bytes_in_flight += data.len() as u64;
    self.data_sent += data.len() as u64;
    self.unacked_data += data.len() as u64;
    self.pending.stream.push_back(frame::Stream {
      addr_off: frame::Stream::get_addr_off(&stream.proxy_addr, old_offset, true),
      fin: false,
      data,
      id,
    });
    Ok(())
  }

  pub fn write(&mut self, id: u64, data: &[u8]) -> Result<usize, WriteError> {
    if self.blocked() {
      trace!(%id, "write blocked by connection-level flow control");
      self.blocked_streams.insert(id);
      return Err(WriteError::Blocked);
    }

    let budget_res = self
      .streams
      .get_mut(&id)
      .ok_or(WriteError::UnknownStream)?
      .send
      .write_budget();

    let stream_budget = match budget_res {
      Ok(budget) => budget,
      Err(e @ WriteError::Stopped { .. }) => {
        self.maybe_cleanup(id);
        return Err(e);
      }
      Err(e @ WriteError::Blocked) => {
        trace!(%id, "write blocked by flow control");
        return Err(e);
      }
      Err(WriteError::UnknownStream) => unreachable!("not returned here"),
    };

    let conn_budget = cmp::min(
      self.max_data - self.data_sent,
      self.config.send_window - self.unacked_data,
    );
    let n = conn_budget.min(stream_budget).min(data.len() as u64) as usize;
    self.queue_stream_data(id, Bytes::copy_from_slice(&data[0..n]))?;
    trace!(%id, "wrote {} bytes", n);
    Ok(n)
  }
  pub fn stop_sending(&mut self, id: u64, error_code: u64) -> Result<(), UnknownStream> {
    let recv = self
      .streams
      .get_mut(&id)
      .ok_or(UnknownStream { _private: () })?
      .recv;
    // Only bother if there's data we haven't received yet
    if !recv.is_finished() {
      self.pending.stop_sending.push((id, error_code));
    }
    Ok(())
  }
  fn add_read_credits(&mut self, id: u64, len: u64, more: bool) {
    self.local_max_data += len;
    self.pending.max_data = true;
    if more {
      // Only bother issuing stream credit if the peer wants to send more
      self.pending.max_stream_data.insert(id);
    }
  }
  ///recv_stream 参考
  fn stream_id_verify(&self, id: u64) {}
  
  ///返回是否是新打开的连接 包含stream_id_verify
  fn id_new_opened(&mut self,id:u64)->Result<bool,Error>{
    //TODO 同时连接限制
    if self.is_client || id < self.next_remote {
      self.stream_id_verify(id).map(|()| false)?
    }else{
      //TODO open stream here 错误检查
      let old_next = mem::replace( self.next_remote,id+1);
      for old_next .. self.next_remote{
        self.streams.insert(
          id,
          Stream {
            proxy_addr: None,
            send: Send::new(0), //TODO需要参数设置此max_data
            recv: Recv::new(),
          },
        );
      }
      Ok(true)
    }
  }

  pub fn on_recv_frame(&mut self, frame: frame::Frame) -> Result<(), Error> {
    use frame::Frame;
    match frame {
      Frame::Stream(frame) => {
        let id = frame.id;
        self.stream_id_verify(id)?;
        let is_new_opened = if !self.is_client && id >= self.next_remote {true} else {false}; 
        //TODO open stream add proxy addr
        let recv = self.streams.get_mut(&id).unwrap().recv;
        if recv.is_finished() {
          trace!("dropping frame for finished stream");
          return Ok(());
        }
        self.data_recvd += recv.ingest(
          frame,
          self.data_recvd,
          self.local_max_data,
          self.config.stream_receive_window,
        )?;
        if !is_new_opened {
          //TODO 修改实现 原实现考虑unorder data 这里不需要考虑
          self.event_sender.send(Event::StreamReadable(id));
        }
      }
      Frame::MaxData(bytes) => {
        let was_blocked = self.blocked();
        self.max_data = cmp::max(bytes, self.max_data);
        if was_blocked && !self.blocked() {
          for id in self.blocked_streams.drain() {
            self.event_sender.send(Event::StreamWritable(id));
          }
        }
      }
      Frame::MaxStreamData { id, offset } => {
        self.stream_id_verify(id)?;
        //TODO new id opened test
        let send = self.streams.get_mut(&id).unwrap().send;
        // We only care about budget *increases* for *live* streams
        if offset > send.max_data && send.state == SendState::Ready {
          trace!(stream = %id, old = send.max_data, new = offset, current_offset = send.offset, "stream limit increased");
          if send.offset == send.max_data {
            self.event_sender.send(Event::StreamWritable(id));
          }
          send.max_data = offset;
        }
      }
      Frame::MaxStreams(count) => {
        if count > self.max {
          self.max = count;
          self.event_sender.send(Event::StreamAvailable);
        }
      }
      Frame::ResetStream {
        id,
        error_code,
        final_offset,
      } => {
        self.stream_id_verify(id)?;
        //TODO new id opened test
        let recv = self.streams.get_mut(&id).unwrap().recv;
        let limit = recv.limit();

        // Validate final_offset
        if let Some(offset) = recv.final_offset() {
          if offset != final_offset {
            return Err(TransportError::FINAL_SIZE_ERROR("inconsistent value"));
          }
        } else if limit > final_offset {
          return Err(TransportError::FINAL_SIZE_ERROR(
            "lower than high water mark",
          ));
        }

        // State transition
        recv.reset(error_code, final_offset);

        // Update flow control
        if recv.assembler.offset != final_offset {
          self.data_recvd += final_offset - limit;
          // bytes_read is always <= limit, so this won't underflow.
          self.local_max_data += final_offset - recv.assembler.offset;
          self.pending.max_data = true;
        }

        // Notify application 通过读取来了解错误 然后清理！！！！
        self.event_sender.send(Event::StreamReadable(id));
      }
      Frame::DataBlocked(offset) => {
        debug!(offset, "peer claims to be blocked at connection level");
      }
      Frame::StreamDataBlocked { id, offset } => {
        debug!(
            stream = %id,
            offset, "peer claims to be blocked at stream level"
        );
      }
      Frame::StreamsBlocked(limit) => {
        debug!(
          "peer claims to be blocked opening more than {}  streams",
          limit
        );
      }
      Frame::StopSending { id, error_code } => {
        self.stream_id_verify(id)?;
        //TODO new id opened test
        self.reset_inner(id, error_code, true);
        // We might have already closed this stream
        let send = self.streams.get_mut(&id).unwrap().send;
        if !send.is_closed() {
          self.on_stream_frame(false, id);
        }
      }
      _ => {}
    }
  }

  pub fn on_frame_acked(&mut self, frame: &frame::Frame) -> Result<(), Error> {
    use frame::Frame;
    match frame {
      Frame::Stream(frame::Stream {
        id,
        addr_off,
        fin,
        data,
      }) => {
        self.stream_id_verify(id)?;
        let send = self.streams.get_mut(&id).unwrap().send;
        send.bytes_in_flight -= data.len() as u64;
        self.unacked_data -= data.len() as u64;
        if let SendState::DataSent {
          ref mut finish_acked,
        } = send.state
        {
          if *fin {
            *finish_acked = true;
          }
          if *finish_acked && send.bytes_in_flight == 0 {
            send.state = SendState::DataRecvd;
            self.maybe_cleanup(*id);
            self.event_sender.send(Event::StreamFinished {
              id: *id,
              stop_reason: None,
            });
          }
        }
      }
      frame::Frame::ResetStream {
        id,
        error_code,
        final_offset,
      } => {
        self.stream_id_verify(id)?;
        let send = self.streams.get_mut(&id).unwrap().send;
        if let SendState::ResetSent { stop_reason } = send.state {
          send.state = SendState::ResetRecvd { stop_reason };
          if stop_reason.is_none() {
            self.maybe_cleanup(*id);
          }
        }
      }
      _ => {}
    };
  }

  pub fn reset(&mut self, id: u64, error_code: u64) {
    self.reset_inner(id, error_code, false);
  }
  /// `stopped` should be set iff this is an internal implicit reset due to `STOP_SENDING`
  fn reset_inner(&mut self, id: u64, error_code: u64, stopped: bool) {
    // reset is a noop on a closed stream
    let send = self.streams.get_mut(&id).unwrap().send;

    let stop_reason = if stopped { Some(error_code) } else { None };

    use SendState::*;
    match send.state {
      DataRecvd | ResetSent { .. } | ResetRecvd { .. } => {
        // Nothing to do
        return;
      }
      DataSent { .. } => {
        self
          .event_sender
          .send(Event::StreamFinished { id, stop_reason });
        // No need to hold on to the stop_reason since it's propagated above
        send.state = ResetSent { stop_reason: None };
      }
      _ => {
        // After we finish up here, we no longer care whether a reset stream was blocked.
        let was_blocked = self.blocked_streams.remove(&id);
        // If this is an implicit reset due to `STOP_SENDING` and the caller might have a
        // blocked write task, notify the caller to try writing again so they'll receive the
        // `WriteError::Stopped` and the stream can be disposed of.
        if stopped && (was_blocked || send.offset == send.max_data) {
          self.event_sender.send(Event::StreamWritable(id));
        }
        send.state = ResetSent { stop_reason };
      }
    }
    self.pending.reset_stream.push((id, error_code));
  }

  fn accept(&mut self) -> Option<u64> {
    assert!(!self.is_client);
    if self.next_remote == self.next_reported_remote {
      return None;
    }
    let id = self.next_reported_remote;
    self.next_reported_remote = id + 1;
    self.pending.max_stream_id = true;
    self.max_remote += 1;
    //! 原实现好像直接开到max_remote 待查通知机制
    self.streams.insert(
      id,
      Stream {
        proxy_addr: None,
        send: Send::new(0), //TODO需要参数设置此max_data
        recv: Recv::new(),
      },
    );
    Some(id)
  }
}

/// Errors triggered when reading from a recv stream
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReadError {
  /// No more data is currently available on this stream.
  ///
  /// If more data on this stream is received from the peer, an `Event::StreamReadable` will be
  /// generated for this stream, indicating that retrying the read might succeed.
  #[error(display = "blocked")]
  Blocked,
  /// The peer abandoned transmitting data on this stream.
  ///
  /// Carries an application-defined error code.
  #[error(display = "reset by peer: code {}", 0)]
  Reset(u64),
  /// Unknown stream
  ///
  /// Occurs when attempting to access a stream after observing that it has been finished or
  /// reset.
  #[error(display = "unknown stream")]
  UnknownStream,
}

/// Errors triggered while writing to a send stream
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WriteError {
  /// The peer is not able to accept additional data, or the connection is congested.
  ///
  /// If the peer issues additional flow control credit, a [`StreamWritable`] event will be
  /// generated, indicating that retrying the write might succeed.
  ///
  /// [`StreamWritable`]: crate::Event::StreamWritable
  #[error(display = "unable to accept further writes")]
  Blocked,
  /// The peer is no longer accepting data on this stream, and it has been implicitly reset. The
  /// stream cannot be finished or further written to.
  ///
  /// Carries an application-defined error code.
  ///
  /// [`StreamFinished`]: crate::Event::StreamFinished
  #[error(display = "stopped by peer: code {}", 0)]
  Stopped(u64),
  /// Unknown stream
  ///
  /// Occurs when attempting to access a stream after finishing it or observing that it has been
  /// stopped.
  #[error(display = "unknown stream")]
  UnknownStream,
}

/// Reasons why attempting to finish a stream might fail
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FinishError {
  /// The peer is no longer accepting data on this stream. No
  /// [`StreamFinished`](crate::Event::StreamFinished) event will be emitted for this stream.
  ///
  /// Carries an application-defined error code.
  #[error(display = "stopped by peer: code {}", 0)]
  Stopped(u64),
  /// The stream has not yet been created or was already finished or stopped.
  #[error(display = "unknown stream")]
  UnknownStream,
}

/// Unknown stream ID
#[derive(Debug)]
pub struct UnknownStream {
  pub(crate) _private: (),
}
