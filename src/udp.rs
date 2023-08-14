use std::net::Ipv4Addr;

use pnet::packet::udp::{ipv4_checksum as ipv4_udp_checksum, MutableUdpPacket};

use crate::L4Checksum;

impl<'p> L4Checksum for MutableUdpPacket<'p> {
    fn checksum_ipv4(&mut self, source: &Ipv4Addr, destination: &Ipv4Addr) {
        self.set_checksum(ipv4_udp_checksum(&self.to_immutable(), source, destination));
    }
}

#[macro_export]
macro_rules! udp {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr, $buf:expr) => {{
      const UDP_HEADER_LEN: usize = 8;
      let total_len = UDP_HEADER_LEN + $payload_pkt.packet().len();
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::udp::MutableUdpPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_length(total_len as u16);
      pkt.set_destination(53);
      pkt.set_source(12345);
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ip::IpNextHeaderProtocols::Udp)
   }};
}

#[cfg(test)]
mod tests {
    use pnet::packet::Packet;

    use crate::{payload, payload::PayloadData, udp};

    #[test]
    fn macro_udp_basic() {
        let mut buf = [0; 13];
        let (pkt, proto) = udp!({set_source => 53, set_destination => 5353},
        payload!({"hello".to_string().into_bytes()}, buf).0, None, buf);
        assert_eq!(proto, pnet::packet::ip::IpNextHeaderProtocols::Udp);

        let buf_expected = vec![0; 13];
        let mut pkt_expected = pnet::packet::udp::MutableUdpPacket::owned(buf_expected).unwrap();
        pkt_expected.set_destination(5353);
        pkt_expected.set_source(53);
        pkt_expected.set_length(13 as u16);
        pkt_expected.set_payload(&"hello".to_string().into_bytes());
        assert_eq!(pkt_expected.packet(), pkt.packet());
    }
}
