use std::{cell::RefCell, collections::VecDeque, rc::Rc};

#[derive(Clone)]
pub struct Sender<T>(Rc<RefCell<VecDeque<T>>>);

impl<T> Sender<T> {
  pub fn send(&self, t: T) {
    self.0.borrow_mut().push_back(t);
  }
}

pub struct Reciver<T>(Rc<RefCell<VecDeque<T>>>);

impl<T> Reciver<T> {
  pub fn recv(&self) -> Option<T> {
    self.0.borrow_mut().pop_front()
  }
}

pub fn channel<T>() -> (Sender<T>, Reciver<T>) {
  let vec = Rc::new(RefCell::new(VecDeque::<T>::new()));
  (Sender(vec.clone()), Reciver(vec))
}
