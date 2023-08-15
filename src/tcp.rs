use std::net::Ipv4Addr;

use pnet::packet::tcp::{
    ipv4_checksum as ipv4_tcp_checksum, MutableTcpPacket, TcpOption, TcpOptionPacket,
};

use crate::L4Checksum;

impl<'p> L4Checksum for MutableTcpPacket<'p> {
    fn checksum_ipv4(&mut self, source: &Ipv4Addr, destination: &Ipv4Addr) {
        self.set_checksum(ipv4_tcp_checksum(&self.to_immutable(), source, destination));
    }
}

/// Calculate the length (in double words) of an array of TcpOption structs
pub fn get_options_len(vals: &[TcpOption]) -> u8 {
    let mut len = 0;
    for opt in vals.iter() {
        len += TcpOptionPacket::packet_size(opt);
    }

    match len {
        0 => 0,
        _ => {
            let mut ret = len / 4;
            ret += 1;
            ret as u8
        }
    }
}

#[macro_export]
macro_rules! extract_options_len {
    (set_options, $value:expr) => {{
        tcp::get_options_len($value)
    }};
    ($func:ident, $value:expr) => {{
        println!(
            "Unexpected case matched in extract_set_options: {} {}",
            stringify!($func),
            stringify!($value)
        );
        0
    }};
}

#[macro_export]
macro_rules! tcp {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr, $buf:expr) => {{
      const TCP_HEADER_LEN: usize = 20;
      // We need to calculate the length of the options before we create the MutableTcpPacket
      let mut opts_len = 0;
      $(
        match stringify!($func) {
          "set_options" => {
            opts_len = extract_options_len!($func, $value);
          }
          _ => (),
        }
      )*

      let total_len = TCP_HEADER_LEN + $payload_pkt.packet().len() + (opts_len as usize * 4);
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::tcp::MutableTcpPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_data_offset(5 + opts_len);
      pkt.set_flags(pnet::packet::tcp::TcpFlags::SYN);
      pkt.set_sequence(0);
      pkt.set_acknowledgement(0);
      pkt.set_urgent_ptr(0);
      pkt.set_window(65535);
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ip::IpNextHeaderProtocols::Tcp)
   }};
}

#[cfg(test)]
mod tests {
    use pnet::packet::{tcp::TcpOption, Packet};

    use crate::{payload, payload::PayloadData, tcp};

    #[test]
    fn macro_tcp_basic() {
        let mut buf = [0; 33];
        let (pkt, proto) = tcp!({set_source => 53, set_destination => 5353, set_options => &[TcpOption::mss(1200), TcpOption::wscale(2)]},
        payload!({"hello".to_string().into_bytes()}, buf).0, None, buf);
        assert_eq!(proto, pnet::packet::ip::IpNextHeaderProtocols::Tcp);

        let buf_expected = vec![0; 33];
        let mut pkt_expected = pnet::packet::tcp::MutableTcpPacket::owned(buf_expected).unwrap();
        pkt_expected.set_destination(5353);
        pkt_expected.set_source(53);
        pkt_expected.set_data_offset(7);
        pkt_expected.set_payload(&"hello".to_string().into_bytes());
        pkt_expected.set_options(&[TcpOption::mss(1200), TcpOption::wscale(2)]);
        pkt_expected.set_flags(pnet::packet::tcp::TcpFlags::SYN);
        pkt_expected.set_sequence(0);
        pkt_expected.set_acknowledgement(0);
        pkt_expected.set_urgent_ptr(0);
        pkt_expected.set_window(65535);
        assert_eq!(pkt_expected.packet(), pkt.packet());
    }
}
