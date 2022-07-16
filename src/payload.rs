use std::net::Ipv4Addr;
use L4Checksum;

impl <'p>L4Checksum for PayloadData<'p> {
  fn checksum_ipv4(&mut self, _source: &Ipv4Addr, _destination: &Ipv4Addr) -> () {
    // The payload has no checksum we just need to implement the trait.
  }
}

pub struct PayloadData<'p> {
  pub data: &'p mut[u8],
}

// Implement the pnet Packet trait so we can use the same interface in the macro for getting the
// data.
impl <'p>pnet::packet::Packet for PayloadData<'p> {
    fn packet(& self) -> & [u8] { &self.data[..] }
    fn payload(& self) -> & [u8] { &self.data[..] }
}

#[macro_export]
macro_rules! payload {
   ($value:expr, $buf:expr) => {{
     let buf_len = $buf.len();
     let pdata =  PayloadData {
       data : &mut$buf[buf_len - $value.len()..],
     };
     for i in 0..$value.len() {
      pdata.data[i] = $value[i];
     }
     (pdata, None as Option<&u16>)
   }};
}

