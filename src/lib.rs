#![macro_use]
#![allow(unused_macros)]

extern crate derive_new;
extern crate ipnetwork;
extern crate pnet;

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
