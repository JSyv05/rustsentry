//! Parses raw Ethernet frames into structured packet summaries:
//! src/dst IP, src/dst port, protocol, TCP flags, payload length.

use std::net::IpAddr;

use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpFlags as PnetTcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

/// TODO(week 2): parse Ethernet -> IPv4/IPv6 -> TCP/UDP/ICMP using pnet's
/// packet types (EthernetPacket, Ipv4Packet, TcpPacket, etc).
pub fn parse_frame(_raw: &[u8], timestamp_micros: i64) -> Option<PacketSummary> {
    let ethernet_packet = EthernetPacket::new(_raw)?;
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;

            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;

                    let flags = tcp_packet.get_flags();

                    Some(PacketSummary {
                        timestamp_micros,
                        src_ip: IpAddr::V4(ipv4_packet.get_source()),
                        dst_ip: IpAddr::V4(ipv4_packet.get_destination()),
                        src_port: Some(tcp_packet.get_source()),
                        dst_port: Some(tcp_packet.get_destination()),
                        protocol: Protocol::Tcp,
                        tcp_flags: Some(TcpFlags {
                            syn: flags & PnetTcpFlags::SYN != 0,
                            ack: flags & PnetTcpFlags::ACK != 0,
                            fin: flags & PnetTcpFlags::FIN != 0,
                            rst: flags & PnetTcpFlags::RST != 0,
                        }),
                        payload_len: tcp_packet.payload().len(),
                    })
                }

                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;

                    Some(PacketSummary {
                        timestamp_micros,
                        src_ip: IpAddr::V4(ipv4_packet.get_source()),
                        dst_ip: IpAddr::V4(ipv4_packet.get_destination()),
                        src_port: Some(udp_packet.get_source()),
                        dst_port: Some(udp_packet.get_destination()),
                        protocol: Protocol::Udp,
                        tcp_flags: None,
                        payload_len: udp_packet.payload().len(),
                    })
                }

                IpNextHeaderProtocols::Icmp => {
                    let icmp_packet = IcmpPacket::new(ipv4_packet.payload())?;

                    Some(PacketSummary {
                        timestamp_micros,
                        src_ip: IpAddr::V4(ipv4_packet.get_source()),
                        dst_ip: IpAddr::V4(ipv4_packet.get_destination()),
                        src_port: None,
                        dst_port: None,
                        protocol: Protocol::Icmp,
                        tcp_flags: None,
                        payload_len: icmp_packet.payload().len(),
                    })
                }

                other => Some(PacketSummary {
                    timestamp_micros,
                    src_ip: IpAddr::V4(ipv4_packet.get_source()),
                    dst_ip: IpAddr::V4(ipv4_packet.get_destination()),
                    src_port: None,
                    dst_port: None,
                    protocol: Protocol::Other(other.0),
                    tcp_flags: None,
                    payload_len: ipv4_packet.payload().len(),
                }),
            }
        }

        EtherTypes::Ipv6 => None, // Not handling this yet, valid Option<PacketSummary>

        _ => None, // anything else: skip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // One real TCP frame, byte-for-byte, pulled from
    // test-data/pcaps/4SICS-GeekLounge-151020.pcap via:
    //   tcpdump -r <file> -nn -e -xx -c 1 'tcp'
    // Ground truth from that same tcpdump output:
    //   10.10.10.20.49156 > 10.10.10.10.102: Flags [P.], win 8192, length 99
    // ("P." = PSH+ACK; no SYN/FIN/RST set)
    #[rustfmt::skip]
    const RAW_TCP_FRAME: [u8; 153] = [
        0x28, 0x63, 0x36, 0x89, 0x59, 0x82, 0x00, 0x1c, 0x06, 0x27, 0x64, 0x11,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x8b, 0x16, 0x57, 0x00, 0x00, 0x1e, 0x06,
        0x5d, 0xe5, 0x0a, 0x0a, 0x0a, 0x14, 0x0a, 0x0a, 0x0a, 0x0a, 0xc0, 0x04,
        0x00, 0x66, 0x00, 0x05, 0x10, 0x07, 0x00, 0x04, 0x07, 0x4e, 0x50, 0x18,
        0x20, 0x00, 0xfc, 0xda, 0x00, 0x00, 0x03, 0x00, 0x00, 0x63, 0x02, 0xf0,
        0x80, 0x32, 0x01, 0x00, 0x00, 0x01, 0x91, 0x00, 0x52, 0x00, 0x00, 0x04,
        0x05, 0x12, 0x0e, 0xb2, 0xff, 0x00, 0x00, 0x00, 0x52, 0xea, 0x2d, 0xb0,
        0xd9, 0x40, 0x00, 0x00, 0x10, 0x12, 0x0e, 0xb2, 0xff, 0x00, 0x00, 0x00,
        0x52, 0x78, 0x04, 0x1f, 0x0f, 0x40, 0x00, 0x00, 0x11, 0x12, 0x0e, 0xb2,
        0xff, 0x00, 0x00, 0x00, 0x52, 0x6b, 0x12, 0x23, 0xfc, 0x40, 0x00, 0x00,
        0x12, 0x12, 0x0e, 0xb2, 0xff, 0x00, 0x00, 0x00, 0x52, 0xf9, 0x3b, 0x8c,
        0x2a, 0x40, 0x00, 0x00, 0x13, 0x12, 0x0e, 0xb2, 0xff, 0x00, 0x00, 0x00,
        0x52, 0x4d, 0x3e, 0x5a, 0x1a, 0x40, 0x00, 0x00, 0x14,
    ];

    #[test]
    fn parses_real_tcp_frame() {
        let summary = parse_frame(&RAW_TCP_FRAME, 1_234).expect("frame should parse");

        assert_eq!(summary.timestamp_micros, 1_234);
        assert_eq!(summary.src_ip, IpAddr::V4(Ipv4Addr::new(10, 10, 10, 20)));
        assert_eq!(summary.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)));
        assert_eq!(summary.src_port, Some(49156));
        assert_eq!(summary.dst_port, Some(102));
        assert_eq!(summary.protocol, Protocol::Tcp);
        assert_eq!(
            summary.tcp_flags,
            Some(TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
            })
        );
        assert_eq!(summary.payload_len, 99);
    }

    // One real UDP frame (a DNS query), pulled the same way:
    //   tcpdump -r <file> -nn -e -xx -c 1 'udp'
    // Ground truth: 192.168.88.61.949 > 192.168.88.1.53: 43814+ A? time.nist.gov. (31)
    #[rustfmt::skip]
    const RAW_UDP_FRAME: [u8; 73] = [
        0x00, 0x07, 0x7c, 0x1a, 0x61, 0x83, 0x00, 0x90, 0xe8, 0x27, 0x8c, 0x37,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x3b, 0xaf, 0x10, 0x00, 0x00, 0x40, 0x11,
        0x9a, 0x12, 0xc0, 0xa8, 0x58, 0x3d, 0xc0, 0xa8, 0x58, 0x01, 0x03, 0xb5,
        0x00, 0x35, 0x00, 0x27, 0xf4, 0x5d, 0xab, 0x26, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x04,
        0x6e, 0x69, 0x73, 0x74, 0x03, 0x67, 0x6f, 0x76, 0x00, 0x00, 0x01, 0x00,
        0x01,
    ];

    #[test]
    fn parses_real_udp_frame() {
        let summary = parse_frame(&RAW_UDP_FRAME, 5_678).expect("frame should parse");

        assert_eq!(summary.timestamp_micros, 5_678);
        assert_eq!(summary.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 88, 61)));
        assert_eq!(summary.dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 88, 1)));
        assert_eq!(summary.src_port, Some(949));
        assert_eq!(summary.dst_port, Some(53));
        assert_eq!(summary.protocol, Protocol::Udp);
        assert_eq!(summary.tcp_flags, None);
        // UDP length field (39) minus the 8-byte UDP header, matching
        // tcpdump's own "(31)" annotation on this packet.
        assert_eq!(summary.payload_len, 31);
    }

    // One real ICMP frame (destination unreachable), pulled the same way:
    //   tcpdump -r <file> -nn -e -xx -c 1 'icmp'
    // Ground truth: 192.168.89.1 > 192.168.89.2: ICMP net 8.8.8.8 unreachable, length 63
    #[rustfmt::skip]
    const RAW_ICMP_FRAME: [u8; 97] = [
        0x70, 0x71, 0xbc, 0x3a, 0x0d, 0xe8, 0x00, 0x0a, 0xdc, 0x64, 0x85, 0xc2,
        0x08, 0x00, 0x45, 0xc0, 0x00, 0x53, 0xd4, 0x03, 0x00, 0x00, 0x40, 0x01,
        0x72, 0x92, 0xc0, 0xa8, 0x59, 0x01, 0xc0, 0xa8, 0x59, 0x02, 0x03, 0x00,
        0x26, 0xef, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x37, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x11, 0x10, 0xfc, 0xc0, 0xa8, 0x59, 0x02, 0x08, 0x08,
        0x08, 0x08, 0x2e, 0x71, 0x00, 0x35, 0x00, 0x23, 0x6e, 0xdc, 0x80, 0x4a,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x6c,
        0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00,
        0x01,
    ];

    #[test]
    fn parses_real_icmp_frame() {
        let summary = parse_frame(&RAW_ICMP_FRAME, 9_012).expect("frame should parse");

        assert_eq!(summary.timestamp_micros, 9_012);
        assert_eq!(summary.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 89, 1)));
        assert_eq!(summary.dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 89, 2)));
        assert_eq!(summary.src_port, None);
        assert_eq!(summary.dst_port, None);
        assert_eq!(summary.protocol, Protocol::Icmp);
        assert_eq!(summary.tcp_flags, None);
        // tcpdump reports 63 bytes of ICMP message (type/code/checksum +
        // the embedded original packet); pnet's IcmpPacket only treats
        // type(1)+code(1)+checksum(2) = 4 bytes as the header, so payload
        // is 63 - 4 = 59.
        assert_eq!(summary.payload_len, 59);
    }

    // Synthetic frame — unlike the fixtures above, this one isn't pulled
    // from the test capture: `4SICS-GeekLounge-151020.pcap` has zero IP
    // packets carrying a protocol other than TCP/UDP/ICMP (checked via
    // `tcpdump -nn 'ip and not tcp and not udp and not icmp'`), so there's
    // nothing real to extract. Hand-built instead: minimal Ethernet + IPv4
    // header (no IP options, no payload), IP protocol 47 (GRE) as a
    // stand-in for "some protocol we don't special-case." The IP checksum
    // is left zeroed — parse_frame doesn't validate it.
    #[rustfmt::skip]
    const RAW_OTHER_PROTO_FRAME: [u8; 34] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x08, 0x00,                         // ethertype: IPv4
        0x45, 0x00,                         // version/IHL, DSCP/ECN
        0x00, 0x14,                         // total length: 20 (header only)
        0x00, 0x00,                         // identification
        0x00, 0x00,                         // flags/fragment offset
        0x40,                               // TTL
        0x2f,                               // protocol: 47 (GRE)
        0x00, 0x00,                         // header checksum (unvalidated)
        0x0a, 0x00, 0x00, 0x01,             // src IP: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02,             // dst IP: 10.0.0.2
    ];

    #[test]
    fn parses_frame_with_unhandled_ip_protocol() {
        let summary =
            parse_frame(&RAW_OTHER_PROTO_FRAME, 3_456).expect("frame should parse");

        assert_eq!(summary.timestamp_micros, 3_456);
        assert_eq!(summary.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(summary.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(summary.src_port, None);
        assert_eq!(summary.dst_port, None);
        assert_eq!(summary.protocol, Protocol::Other(47));
        assert_eq!(summary.tcp_flags, None);
        assert_eq!(summary.payload_len, 0);
    }
}
