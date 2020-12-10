use crate::{frame, Address};
use bimap::BiMap;
use bytes::Bytes;
use either::Either;
use err_derive::Error;
use std::{
  collections::{HashSet, VecDeque},
  rc::Rc,sync::Arc,
};

pub enum State {
  Active,
  //left closed by me,right closed by peer
  RecvClosed(u64),

  ClosedSent(u64),
  ClosedAcked(u64),
}

pub struct ClientDatagram {
  proxy_addr_map: BiMap<u8, Rc<Address>>,
  acked_addr: HashSet<u8>,
  recv_buf: VecDeque<(Rc<Address>, Bytes)>,
  buf_size:usize,
  state: State,
}
pub struct Pending {
  //VecDeque 即超限丢弃
  datagram: VecDeque<frame::Datagram>,
  //可能 超时 等理由 此包是ack elicted
  datagram_closed: HashSet<(u64, u64)>,
  max_datagram_id: bool,
}

pub struct ClientDatagrams {
  datagrams: HashMap<u64, ClientDatagram>,
  pending: Pending,
  next: u64,
  max: u64,
  //其实不需要 通过datagrams.size 即可知道  active_datagrams: usize,
  data_sent: u64,
  data_recvd: u64,
  event_sender: Sender<Event>,
  config:Arc<Config>,
}

pub struct Config{
  recv_buf_size:usize;//应该至少能容纳一个mtu
  send_buf_size:usize;//应该至少能容纳一个mtu 全
}


//客户端不会超时错误 ，避免同步
impl ClientDatagrams {
  pub fn new() -> Self {}

  pub fn open(&mut self, addr: Address) -> Option<u64> {
        // TODO: Queue STREAM_ID_BLOCKED if this fails
        if self.next >= self.max {
          return None;
        }
        let id = self.next;
        self.datagrams.insert(
          id,
          ClientDatagram {
            proxy_addr,
            send: Send::new(0), //TODO需要参数设置此max_data
            recv: Recv::new(),
          },
        );
        self.next += 1;
        Some(id)
  }
  pub fn close(&mut self, id: u64,error_code:u64) -> Result<(), FinishError>{
    let datagram = self
      .datagrams
      .get_mut(&id)
      .ok_or(FinishError::UnknownStream)?;
    if datagram.state != State::Active{
      Err()
    }else{
      datagram.state = State::ClosedSent(error_code);
      self.pending.datagram_closed.add(id,error_code);
      Ok(())
    }
  }
  pub fn recv_from(&mut self, id: u64) -> Option<(Rc<Address>, Bytes)> {
    let x = self.datagrams.incoming.pop_front()?.data;
    self.datagrams.recv_buffered -= x.len();
    Some(x)
  }
  pub fn send(&mut self, id: u64, data: Bytes) -> Result<(), SendDatagramError> {
    let max_size = self.max_datagram_size();
    while self.datagrams.outgoing_total > self.config.datagram_send_buffer_size {
      let prev = self
        .datagrams
        .outgoing
        .pop_front()
        .expect("datagrams.outgoing_total desynchronized");
      trace!(len = prev.data.len(), "dropping outgoing datagram");
      self.datagrams.outgoing_total -= prev.data.len();
    }
    if data.len() > max {
      return Err(SendDatagramError::TooLarge);
    }
    self.datagrams.outgoing_total += data.len();
    self.datagrams.outgoing.push_back(Datagram { data });
    Ok(())
  }

  pub fn max_datagram_size(&self) -> Option<usize> {
    // This is usually 1182 bytes, but we shouldn't document that without a doctest.
    let max_size = self.mtu as usize
        - 1                 // flags byte
        - self.rem_cid.len()
        - 4                 // worst-case packet number size
        - self.space(SpaceId::Data).crypto.as_ref().or_else(|| self.zero_rtt_crypto.as_ref()).unwrap().packet.tag_len()
        - Datagram::SIZE_BOUND;
    self.config.datagram_receive_buffer_size?;
    let limit = self.params.max_datagram_frame_size?.into_inner();
    Some(limit.min(max_size as u64) as usize)
  }

  fn maybe_cleanup(&mut self,id:u64){}

  pub fn datagram_id_verify(&self,id:u64){}

  pub fn on_frame_ack(&mut self, frame: &frame::Frame) {
    use frame::Frame;
    match frame {
      //TODO 只有含有addr的包裹会放入sent package
      Frame::SentDatagram {
        id,
        addr_idx,
      } => {
        self.datagram_id_verify(id)?;
        let datagram = self.datagrams.get_mut(&id).unwrap();
        datagram.acked_addr.add(addr_idx);
      }
      frame::Frame::DatagramClosed{id,error_code} => {
        self.datagram_id_verify(id)?;
        let datagram = self.datagrams.get_mut(&id).unwrap();
        if let State::ClosedSent(_) =datagram.state {
          datagram.state = State::ClosedSent(*error_code);
          self.maybe_cleanup(*id);
        }
      }
      _ => {}
    };
  }

  pub fn on_recv_frame(&mut self，frame: frame::Frame) {
    use frame::Frame;
    match frame {
      Frame::Datagram(frame) =>{
        let id = frame.id;
        self.datagram_id_verify(id)?;
        if self.datagrams.buf_size == 0 {
          self.event_sender.send(Event::DatagramReceived(id));
        }
        let datagram = self.datagrams.get_mut(&id).unwrap();
        while datagram.data.len() + datagram.buf_size > window {
          debug!("dropping stale datagram");
          let stale_pkg = datagram.recv_buf.pop_front()?.data;
          datagram.buf_size -= x.len();
        }
        datagram.buf_size += datagram.data.len();
        datagram.recv_buf.push_back(datagram);
      }
      Frame::DatagramClosed{id,error_code}=>{
        self.datagram_id_verify(id)?;
        let datagram = self.datagrams.get_mut(&id).unwrap();
        if let State::Active = datagram.state{
          datagram.state=State::RecvClosed(error_code);
          // Notify application 通过读取来了解错误 然后清理！！！！
          if self.datagrams.buf_size == 0 {
            self.event_sender.send(Event::DatagramReceived(id));
          }
        }
      }
      Frame::MaxDatagrams(count)=>{
        if count > self.max {
          self.max = count;
          self.event_sender.send(Event::DatagramAvailable);
        }
      }
      Frame::DatagramsBlocked(limit)=>{
        debug!(
          "peer claims to be blocked opening more than {}  datagrams",
          limit
        );
      }

    }
  }
}

#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendError {
  #[error(display = "This datagram is closed")]
  Closed(u64),
  #[error(display = "datagram too large")]
  TooLarge,
  #[error(display = "unknown datagram")]
  UnknownDatagram,
}

#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RecvError {
  #[error(display = "This datagram is closed")]
  Closed(u64),
  #[error(display = "unknown datagram")]
  UnknownDatagram,
}

/// Reasons why attempting to finish a stream might fail
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FinishError {
  #[error(display = "This datagram is closed")]
  Closed(u64),
  #[error(display = "unknown datagram")]
  UnknownDatagram,
}