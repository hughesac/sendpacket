

#[macro_export]
macro_rules! arp {
   ({$($func:ident => $value:expr), *}, $buf:expr) => {{
      const ARP_HEADER_LEN: usize = 28;
      let total_len = ARP_HEADER_LEN;
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::arp::MutableArpPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_hw_addr_len(6);
      pkt.set_proto_addr_len(4);
      pkt.set_sender_proto_addr("127.0.0.1".parse().unwrap());
      pkt.set_target_proto_addr("192.168.1.1".parse().unwrap());
      pkt.set_operation(pnet::packet::arp::ArpOperations::Request);
      pkt.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);  
      pkt.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4); 
      pkt.set_sender_hw_addr(pnet::util::MacAddr(1,2,3,4,5,6)); 
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ethernet::EtherTypes::Arp)
   }};
}

#[cfg(test)]
mod tests {
   use pnet::packet::Packet;
   use ::ipv4addr;

   #[test]
   fn macro_arp_basic() {
      let mut buf = [0; 28];
      let (pkt, proto) = arp!({set_target_proto_addr => ipv4addr!("192.168.1.1"), set_sender_proto_addr => ipv4addr!("192.168.1.245")}, buf); 
      assert_eq!(proto, pnet::packet::ethernet::EtherTypes::Arp );

      let buf_expected = vec![0; 28];
      let mut pkt_expected = pnet::packet::arp::MutableArpPacket::owned(buf_expected).unwrap();
      pkt_expected.set_hw_addr_len(6);
      pkt_expected.set_proto_addr_len(4);
      pkt_expected.set_sender_proto_addr("192.168.1.245".parse().unwrap());
      pkt_expected.set_target_proto_addr("192.168.1.1".parse().unwrap());
      pkt_expected.set_operation(pnet::packet::arp::ArpOperations::Request);
      pkt_expected.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);  
      pkt_expected.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4); 
      pkt_expected.set_sender_hw_addr(pnet::util::MacAddr(1,2,3,4,5,6));
      assert_eq!(pkt_expected.packet(), pkt.packet());
   }
}

