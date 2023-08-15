use std::net::Ipv4Addr;

use pnet::packet::{util::checksum as generic_checksum, Packet};

use crate::L4Checksum;

#[macro_export]
macro_rules! icmp_echo_req {
    ($args:tt, $payload_pkt:expr, $proto:expr, $buf:expr) => {{
        $crate::icmp!(
            $args,
            $payload_pkt,
            pnet::packet::icmp::echo_request::MutableEchoRequestPacket,
            $buf
        )
    }};
    ($args:tt, $buf:expr) => {{
        $crate::icmp!(
            $args,
            pnet::packet::icmp::echo_request::MutableEchoRequestPacket,
            $buf
        )
    }};
}
#[macro_export]
macro_rules! icmp_echo_reply {
    ($args:tt, $payload_pkt:expr, $proto:expr, $buf:expr) => {{
        $crate::icmp!(
            $args,
            $payload_pkt,
            pnet::packet::icmp::echo_reply::MutableEchoReplyPacket,
            $buf
        )
    }};
    ($args:tt, $buf:expr) => {{
        $crate::icmp!(
            $args,
            pnet::packet::icmp::echo_reply::MutableEchoReplyPacket,
            $buf
        )
    }};
}
#[macro_export]
macro_rules! icmp_dest_unreach {
    ($args:tt, $payload_pkt:expr, $proto:expr, $buf:expr) => {{
        $crate::icmp!(
            $args,
            $payload_pkt,
            pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket,
            $buf
        )
    }};
    ($args:tt, $buf:expr) => {{
        $crate::icmp!(
            $args,
            pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket,
            $buf
        )
    }};
}
#[macro_export]
macro_rules! icmp_time_exceed {
    ($args:tt, $payload_pkt:expr, $proto:expr, $buf:expr) => {{
        $crate::icmp!(
            $args,
            $payload_pkt,
            pnet::packet::icmp::time_exceeded::MutableTimeExceededPacket,
            $buf
        )
    }};
    ($args:tt, $buf:expr) => {{
        $crate::icmp!(
            $args,
            pnet::packet::icmp::time_exceeded::MutableTimeExceededPacket,
            $buf
        )
    }};
}

macro_rules! icmp_checksum_func_gen {
  ($($icmp_type:ty),*) => {
    $(
      impl <'p>L4Checksum for $icmp_type {
        fn checksum_ipv4(&mut self, _source: &Ipv4Addr, _destination: &Ipv4Addr) {
          // ICMP checksum is the same as IP
          self.set_checksum(generic_checksum(&self.packet(), 1));
        }
      }
    )*
  };
}

icmp_checksum_func_gen!(
    pnet::packet::icmp::echo_reply::MutableEchoReplyPacket<'p>,
    pnet::packet::icmp::echo_request::MutableEchoRequestPacket<'p>,
    pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket<'p>,
    pnet::packet::icmp::time_exceeded::MutableTimeExceededPacket<'p>
);

#[macro_export]
macro_rules! icmp {
   ({$($func:ident => $value:expr), *}, $icmp_type:ty, $buf:expr) => {{
      let total_len = <$icmp_type>::minimum_packet_size();
      let buf_len = $buf.len();
      let mut pkt = <$icmp_type>::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_icmp_type(IcmpTypes::EchoRequest);
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ip::IpNextHeaderProtocols::Icmp)
   }};
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $icmp_type:ty, $buf:expr) => {{
      let total_len = <$icmp_type>::minimum_packet_size() + $payload_pkt.packet().len();
      let buf_len = $buf.len();
      let mut pkt = <$icmp_type>::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ip::IpNextHeaderProtocols::Icmp)
   }};
}

#[cfg(test)]
mod tests {
    use pnet::packet::{icmp::IcmpTypes, Packet};

    use crate::payload;

    #[test]
    fn macro_icmp_basic() {
        let mut buf = [0; 13];
        let (pkt, proto) = icmp_dest_unreach!({set_icmp_type => IcmpTypes::DestinationUnreachable},
        payload!({"hello".to_string().into_bytes()}, buf).0, None, buf);
        assert_eq!(proto, pnet::packet::ip::IpNextHeaderProtocols::Icmp);

        let buf_expected = vec![0; 13];
        let mut pkt_expected = pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket::owned(buf_expected).unwrap();
        pkt_expected.set_icmp_type(IcmpTypes::DestinationUnreachable);
        pkt_expected.set_payload(&"hello".to_string().into_bytes());
        assert_eq!(pkt_expected.packet(), pkt.packet());
    }
}
