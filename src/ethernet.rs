
#[macro_export]
macro_rules! ether {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr, $buf:expr ) => {{
      const ETHERNET_HEADER_LEN: usize = 14;
      let total_len = ETHERNET_HEADER_LEN + $payload_pkt.packet().len();
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::ethernet::MutableEthernetPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_ethertype($protocol);       
      $(
        pkt.$func($value);
      )*
      // The protocol element of the tuple is not actually used but the compiler requires us to
      // provide a type.
     (pkt, None as Option<&u16>)
   }};
   ({$($func:ident => $value:expr), *}, $buf:expr) => {{
      const ETHERNET_HEADER_LEN: usize = 14;
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::ethernet::MutableEthernetPacket::new(&mut $buf[buf_len - ETHERNET_HEADER_LEN..]).unwrap();
      $(
        pkt.$func($value);
      )*
      // The protocol element of the tuple is not actually used but the compiler requires us to
      // provide a type.
     (pkt, None as Option<&u16>)
   }};
}


#[cfg(test)]
mod tests {
   use pnet::packet::Packet;

   #[test]
   fn macro_ether_basic() {
      let mut buf = vec![0; 14];
      let (pkt, proto) = ether!({set_destination =>  pnet::util::MacAddr(10,1,3,1,1,2), set_source => pnet::util::MacAddr(10,1,1,1,1,1)}, buf); 
      assert_eq!(proto, None);
      let buf_expected = vec![0; 14];
      let mut pkt_expected = pnet::packet::ethernet::MutableEthernetPacket::owned(buf_expected).unwrap();
      pkt_expected.set_destination(pnet::util::MacAddr(10,1,3,1,1,2)); 
      pkt_expected.set_source(pnet::util::MacAddr(10,1,1,1,1,1)); 
      assert_eq!(pkt_expected.packet(), pkt.packet());
   }
}
