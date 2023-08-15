use pnet::packet::ipv4::MutableIpv4Packet;

pub const IPV4_HEADER_LEN: usize = 20;
pub const DEFAULT_SOURCE: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127, 0, 0, 1);
pub const DEFAULT_DESTINATION: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127, 0, 0, 1);

pub fn init_ipv4_pkt(pkt: &mut MutableIpv4Packet, len: u16) {
    pkt.set_version(4);
    pkt.set_header_length(5);
    pkt.set_total_length(len);
    pkt.set_ttl(128);
    // TODO make the ID a random value
    pkt.set_identification(256);
    pkt.set_fragment_offset(0);
    pkt.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
}

#[macro_export]
macro_rules! extract_address {
    (set_source, $value:expr) => {{
        $value
    }};
    (set_destination, $value:expr) => {{
        $value
    }};
    ($func:ident, $value:expr) => {{
        println!(
            "Unexpected case matched in extract_address: {} {}",
            stringify!($func),
            stringify!($value)
        );
        $crate::ipv4::DEFAULT_SOURCE
    }};
}

#[macro_export]
macro_rules! ipv4 {
    ({$($func:ident => $value:expr), *}, $l4_pkt:expr, $protocol:expr, $buf:expr) => {{
        let total_len = $crate::ipv4::IPV4_HEADER_LEN + $l4_pkt.packet().len();
        let mut source = $crate::ipv4::DEFAULT_SOURCE;
        let mut dest = $crate::ipv4::DEFAULT_DESTINATION;
        // Get the source/destination IP addresses so we can set the L4 checksum before
        // creating the MutableIpv4Packet which is another mutable reference to the packet buffer.
        // Once the MutableIpv4Packet is created we can't use $l4_pkt or we will get borrow errors.
        $(
        // If we only used this match without calling the extract_address macro, the compiler can't
        // determine which func/value combos apply to which branch of the match and it assume they
        // can all match which will cause type errors.  The extract_address macro avoids this
        // problem.
        match stringify!($func) {
            "set_source" => source = $crate::extract_address!($func, $value),
            "set_destination" => dest = $crate::extract_address!($func, $value),
            _ => (),
        }
        )*

        $crate::L4Checksum::checksum_ipv4(&mut $l4_pkt, &source, &dest);
        let buf_len = $buf.len();
        let mut pkt = pnet::packet::ipv4::MutableIpv4Packet::new(&mut $buf[buf_len - total_len..]).unwrap();
        pkt.set_next_level_protocol($protocol);
        $crate::ipv4::init_ipv4_pkt(&mut pkt, total_len as u16);
        $(
            pkt.$func($value);
        )*
        pkt.set_checksum(pnet::packet::ipv4::checksum(&pkt.to_immutable()));

        (pkt, pnet::packet::ethernet::EtherTypes::Ipv4)
    }};
}

#[macro_export]
macro_rules! ipv4addr {
    ($addr_str:expr) => {{
        $addr_str.parse().unwrap()
    }};
}

#[cfg(test)]
mod tests {
    use pnet::packet::{ethernet::EtherTypes::Ipv4, Packet};

    use crate::payload;

    #[test]
    fn macro_ipv4_basic() {
        let mut buf = [0; 25];
        let (pkt, proto) = ipv4!({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("192.168.1.1"), set_version => 4},
        payload!({"hello".to_string().into_bytes()}, buf).0, pnet::packet::ip::IpNextHeaderProtocols::Udp, buf);
        assert_eq!(proto, Ipv4);

        let buf_expected = vec![0; 25];
        let mut pkt_expected = pnet::packet::ipv4::MutableIpv4Packet::owned(buf_expected).unwrap();
        pkt_expected.set_destination(ipv4addr!("192.168.1.1"));
        pkt_expected.set_source(ipv4addr!("127.0.0.1"));
        pkt_expected.set_version(4);
        pkt_expected.set_header_length(5);
        pkt_expected.set_total_length(25);
        pkt_expected.set_payload(&"hello".to_string().into_bytes());
        pkt_expected.set_ttl(128);
        pkt_expected.set_identification(256);
        pkt_expected.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
        pkt_expected.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        pkt_expected.set_checksum(pnet::packet::ipv4::checksum(&pkt_expected.to_immutable()));
        assert_eq!(pkt_expected.packet(), pkt.packet());
    }
}
