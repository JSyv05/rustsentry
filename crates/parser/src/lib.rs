//! Parses raw Ethernet frames into structured packet summaries:
//! src/dst IP, src/dst port, protocol, TCP flags, payload length.

use std::net::IpAddr;

use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;

#[derive(Debug, Clone)]
pub struct PacketSummary {
    pub timestamp_micros: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub tcp_flags: Option<TcpFlags>,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

/// TODO(week 2): parse Ethernet -> IPv4/IPv6 -> TCP/UDP/ICMP using pnet's
/// packet types (EthernetPacket, Ipv4Packet, TcpPacket, etc).
pub fn parse_frame(_raw: &[u8], _timestamp_micros: i64) -> Option<PacketSummary> {
    //todo!("Ethernet/IP/TCP/UDP/ICMP dissection — week 2");
    let ethernet_packet = EthernetPacket::new(_raw)?;
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            todo!("Ipv4 branching");
        }

        EtherTypes::Ipv6 => None, // Not handling this yet, valid Option<PacketSummary>

        _ => None, // anything else: skip
    }
}
