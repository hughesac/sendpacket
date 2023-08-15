pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod payload;
pub mod tcp;
pub mod udp;
pub mod vlan;

use std::net::Ipv4Addr;

pub trait L4Checksum {
    fn checksum_ipv4(&mut self, source: &Ipv4Addr, destination: &Ipv4Addr);
}

#[macro_export]
macro_rules! build_channel {
    ($ifname:expr) => {{
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == $ifname)
            .unwrap();

        let (sender, receiver) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
        (sender, receiver)
    }};
}

#[macro_export]
macro_rules! sub_builder {
    ($pkt_buf:expr, $build_macro:ident($args:tt) $(/ $rem_macros:ident($rem_args:tt))+) => {{
        #[allow(unused_mut)]
        let (mut payload_pkt, _payload_proto) = sub_builder!($pkt_buf, $($rem_macros($rem_args) )/ *);
        let (pkt, proto) = $build_macro!($args, payload_pkt, _payload_proto, $pkt_buf);
        (pkt, proto)
    }};
    ($pkt_buf:expr, $build_macro:ident($args:tt)) => {{
        $build_macro!($args, $pkt_buf)
    }};
}

// Call the sub builder so we can return just the packet rather than the tuple that gets returned
// by the sub builder for use during the recursion.
#[macro_export]
macro_rules! packet_builder {
    ($pkt_buf:expr, $( $rem_macros:ident($rem_args:tt))/ * ) => {{
        let (pkt, _proto) = sub_builder!($pkt_buf, $( $rem_macros($rem_args) )/ *);
        pkt
    }};
}

#[cfg(test)]
mod test {
    use pnet::packet::{
        icmp::IcmpTypes,
        tcp::{TcpFlags, TcpOption},
        Packet,
    };
    use pnet_datalink::MacAddr;

    use crate::{ether, icmp_dest_unreach, icmp_echo_req, ipv4, ipv4addr, payload, tcp, udp, vlan};

    #[test]
    fn can_build_example_1() {
        let mut pkt_buf = [0u8; 1500];
        let _pkt = packet_builder!(
             pkt_buf,
             ether({set_source => MacAddr(10,1,1,1,1,1)}) /
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             icmp_dest_unreach({set_icmp_type => IcmpTypes::DestinationUnreachable}) /
             ipv4({set_source => ipv4addr!("10.8.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             udp({set_source => 53, set_destination => 5353}) /
             payload({"hello".to_string().into_bytes()})
        );
    }

    #[test]
    fn can_build_example_2() {
        let mut pkt_buf = [0u8; 1500];
        let _pkt = packet_builder!(
             pkt_buf,
             ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) /
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             tcp({set_source => 43455, set_destination => 80, set_flags => (TcpFlags::PSH | TcpFlags::ACK)}) /
             payload({"hello".to_string().into_bytes()})
        );
    }

    #[test]
    fn can_build_example_3() {
        let mut pkt_buf = [0u8; 1500];
        let _pkt = packet_builder!(
           pkt_buf,
           ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) /
           vlan({set_vlan_identifier => 10}) /
           ipv4({set_source => ipv4addr!("192.168.1.1"), set_destination => ipv4addr!("127.0.0.1") }) /
           tcp({set_source => 43455, set_destination => 80, set_options => &[TcpOption::mss(1200), TcpOption::wscale(2)]}) /
           payload({[0; 0]})
        );
    }

    #[test]
    fn can_build_example_4() {
        let mut pkt_buf = [0u8; 1500];
        let _pkt = packet_builder!(
             pkt_buf,
             ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) /
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             udp({set_source => 12312, set_destination => 143}) /
             payload({"hello".to_string().into_bytes()})
        );
    }

    #[test]
    fn can_build_example_5() {
        let mut pkt_buf = [0u8; 1500];
        let _pkt = packet_builder!(
             pkt_buf,
             ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) /
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             icmp_echo_req({set_icmp_type => IcmpTypes::EchoRequest}) /
             payload({"hello".to_string().into_bytes()})
        );
    }
}
