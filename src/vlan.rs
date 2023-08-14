#[macro_export]
macro_rules! vlan {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr, $buf:expr) => {{
      const VLAN_HEADER_LEN: usize = 4;
      let total_len = VLAN_HEADER_LEN + $payload_pkt.packet().len();
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::vlan::MutableVlanPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_ethertype($protocol);
      pkt.set_vlan_identifier(0);
      pkt.set_priority_code_point(pnet::packet::vlan::ClassesOfService::BE);
      pkt.set_drop_eligible_indicator(0);
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ethernet::EtherTypes::Vlan)
   }};
}

#[cfg(test)]
mod tests {
    use pnet::packet::Packet;

    use crate::{payload, payload::PayloadData};

    #[test]
    fn macro_vlan_basic() {
        let mut buf = [0; 4];
        let (pkt, proto) = vlan!({set_vlan_identifier => 10, set_drop_eligible_indicator => 2},
                               payload!({[0; 0]}, buf).0, pnet::packet::ethernet::EtherTypes::Ipv4, buf);
        assert_eq!(proto, pnet::packet::ethernet::EtherTypes::Vlan);

        let buf_expected = vec![0; 4];
        let mut pkt_expected = pnet::packet::vlan::MutableVlanPacket::owned(buf_expected).unwrap();
        pkt_expected.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);
        pkt_expected.set_vlan_identifier(10);
        pkt_expected.set_priority_code_point(pnet::packet::vlan::ClassesOfService::BE);
        pkt_expected.set_drop_eligible_indicator(2);
        assert_eq!(pkt_expected.packet(), pkt.packet());
    }
}
