//! Flow tracking: aggregates PacketSummary events into per-key counters
//! over sliding time windows. This is the shared primitive every detector
//! in `detect` builds on (week 3 in the capstone plan).

use parser::PacketSummary;
use parser::Protocol;
use std::collections::HashMap;
use std::net::IpAddr;

/// Key for grouping packets into a flow. Adjust granularity per detector:
/// SYN-flood detection groups by dst_ip; port-scan detection groups by src_ip.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: Protocol,
}

/// TODO(week 5): implement a time-bucketed ring buffer so window queries
/// are O(1) amortized instead of rescanning full packet history.
pub struct SlidingWindowCounters {
    window_secs: u64,
    counts: HashMap<FlowKey, WindowState>,
}

#[derive(Default)]
struct WindowState {
    packet_count: u64,
    syn_count: u64,
    ack_count: u64,
    byte_count: u64,
    distinct_dst_ports: std::collections::HashSet<u16>,
    window_start_micros: i64,
    last_seen_micros: i64,
}

impl SlidingWindowCounters {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            counts: HashMap::new(),
        }
    }

    pub fn flow_count(&self) -> usize {
        self.counts.len()
    }

    pub fn packet_count(&self, key: &FlowKey) -> u64 {
        self.counts.get(key).unwrap().packet_count
    }

    pub fn byte_count(&self, key: &FlowKey) -> u64 {
        self.counts.get(key).unwrap().byte_count
    }

    pub fn window_start_micros(&self, key: &FlowKey) -> i64 {
        self.counts.get(key).unwrap().window_start_micros
    }

    pub fn last_seen_micros(&self, key: &FlowKey) -> i64 {
        self.counts.get(key).unwrap().last_seen_micros
    }

    pub fn syn_count(&self, key: &FlowKey) -> u64 {
        self.counts.get(key).unwrap().syn_count
    }

    pub fn ack_count(&self, key: &FlowKey) -> u64 {
        self.counts.get(key).unwrap().ack_count
    }

    pub fn distinct_dst_ports_count(&self, key: &FlowKey) -> usize {
        self.counts.get(key).unwrap().distinct_dst_ports.len()
    }

    /// TODO(week 3): update counters for the appropriate key(s), evicting
    /// state that has aged out of the window.
    pub fn record(&mut self, key: FlowKey, pkt: &PacketSummary) {
        let state = self.counts.entry(key).or_insert_with(|| WindowState {
            window_start_micros: pkt.timestamp_micros,
            ..Default::default()
        });
        state.packet_count += 1;
        state.byte_count += pkt.payload_len as u64;
        state.last_seen_micros = pkt.timestamp_micros;

        if let Some(flags) = pkt.tcp_flags {
            if flags.syn {
                state.syn_count += 1;
            }
            if flags.ack {
                state.ack_count += 1;
            }
        }

        if let Some(port) = pkt.dst_port {
            state.distinct_dst_ports.insert(port);
        }
    }
}

#[cfg(test)]

mod tests {

    use parser::parse_frame;

    use super::*;
    use parser::TcpFlags;
    use std::net::Ipv4Addr;

    #[rustfmt::skip]
    const RAW_TCP_FRAME_1: [u8; 153] = [
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

    fn sample_tcp_packet(timestamp_micros: i64, payload_len: usize) -> PacketSummary {
        PacketSummary {
            timestamp_micros,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Tcp,
            tcp_flags: Some(TcpFlags::default()),
            payload_len,
        }
    }

    // Records one real, parsed TCP frame and checks that a single record()
    // call creates exactly one flow entry, with packet_count/byte_count/
    // last_seen_micros/window_start_micros all reflecting that one packet.
    // Unlike the other tests below, this one goes through parse_frame() on
    // real bytes rather than a hand-built PacketSummary, so it's the one
    // test exercising the seam between `parser` and `flow`, not just
    // record()'s own logic in isolation.
    #[test]
    fn record_one_flow() {
        let summary = parse_frame(&RAW_TCP_FRAME_1, 1_234).expect("frame should parse");

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

        let summary_key_flow = FlowKey {
            src_ip: summary.src_ip,
            dst_ip: summary.dst_ip,
            protocol: summary.protocol,
        };

        let mut counters = SlidingWindowCounters::new(10);

        counters.record(summary_key_flow.clone(), &summary);

        assert_eq!(counters.flow_count(), 1);
        assert_eq!(counters.packet_count(&summary_key_flow), 1);
        assert_eq!(
            counters.byte_count(&summary_key_flow),
            summary.payload_len as u64
        );
        assert_eq!(
            counters.last_seen_micros(&summary_key_flow),
            summary.timestamp_micros
        );
        assert_eq!(
            counters.window_start_micros(&summary_key_flow),
            summary.timestamp_micros
        );
    }

    // Records two different packets under the same FlowKey and checks that
    // they aggregate onto one flow entry (flow_count() stays 1) instead of
    // creating a second one, with packet_count/byte_count accumulating
    // across both record() calls rather than reflecting just the latest.
    #[test]
    fn record_key_aggregate() {
        let summary_1 = sample_tcp_packet(1_234, 80);
        let summary_2 = sample_tcp_packet(2_345, 110);

        let summary_key_flow = FlowKey {
            src_ip: summary_1.src_ip,
            dst_ip: summary_1.dst_ip,
            protocol: summary_1.protocol,
        };

        let mut counters = SlidingWindowCounters::new(10);

        counters.record(summary_key_flow.clone(), &summary_1);
        counters.record(summary_key_flow.clone(), &summary_2);

        assert_eq!(counters.flow_count(), 1);
        assert_eq!(counters.packet_count(&summary_key_flow), 2);

        let byte_sum = summary_1.payload_len + summary_2.payload_len;

        assert_eq!(counters.byte_count(&summary_key_flow) as usize, byte_sum);
    }

    #[test]
    fn key_independence() {
        let summary = parse_frame(&RAW_TCP_FRAME_1, 1_234).expect("frame should parse");

        let key_flow_1 = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 10, 10, 20)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 10, 10, 40)),
            protocol: Protocol::Tcp,
        };

        let key_flow_2 = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 10, 10, 30)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 10, 10, 40)),
            protocol: Protocol::Tcp,
        };

        let mut counters = SlidingWindowCounters::new(10);

        counters.record(key_flow_1.clone(), &summary);
        counters.record(key_flow_2.clone(), &summary);

        assert_eq!(counters.flow_count(), 2);
        assert_eq!(counters.packet_count(&key_flow_1), 1);
        assert_eq!(counters.packet_count(&key_flow_2), 1);
        assert_eq!(counters.byte_count(&key_flow_1), summary.payload_len as u64);
        assert_eq!(counters.byte_count(&key_flow_2), summary.payload_len as u64);
    }

    #[test]
    fn start_seen_micros_comparison() {
        let summary_1 = sample_tcp_packet(1_234, 80);
        let summary_2 = sample_tcp_packet(2_345, 110);

        let summary_key_flow = FlowKey {
            src_ip: summary_1.src_ip,
            dst_ip: summary_1.dst_ip,
            protocol: summary_1.protocol,
        };

        let mut counters = SlidingWindowCounters::new(10);
        counters.record(summary_key_flow.clone(), &summary_1);

        assert_eq!(
            counters.window_start_micros(&summary_key_flow),
            summary_1.timestamp_micros
        );
        assert_eq!(
            counters.last_seen_micros(&summary_key_flow),
            summary_1.timestamp_micros
        );

        counters.record(summary_key_flow.clone(), &summary_2);

        assert_eq!(
            counters.window_start_micros(&summary_key_flow),
            summary_1.timestamp_micros
        );

        assert_eq!(
            counters.last_seen_micros(&summary_key_flow),
            summary_2.timestamp_micros
        );
    }

    #[test]
    fn syn_ack_counting() {
        let syn_packet = PacketSummary {
            tcp_flags: Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            }),
            ..sample_tcp_packet(1_234, 80)
        };

        let ack_packet = PacketSummary {
            tcp_flags: Some(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            }),
            ..sample_tcp_packet(2_345, 90)
        };

        let no_flags_packet = PacketSummary {
            tcp_flags: None,
            ..sample_tcp_packet(3_456, 60)
        };

        let mut counters = SlidingWindowCounters::new(10);

        let summary_flow_key = FlowKey {
            src_ip: syn_packet.src_ip,
            dst_ip: syn_packet.dst_ip,
            protocol: syn_packet.protocol,
        };

        counters.record(summary_flow_key.clone(), &syn_packet);

        assert_ne!(
            counters.syn_count(&summary_flow_key),
            counters.ack_count(&summary_flow_key)
        );

        counters.record(summary_flow_key.clone(), &ack_packet);
        counters.record(summary_flow_key.clone(), &no_flags_packet);

        assert_eq!(counters.packet_count(&summary_flow_key), 3);

        assert_eq!(counters.syn_count(&summary_flow_key), 1);

        assert_eq!(counters.ack_count(&summary_flow_key), 1);
    }

    #[test]
    fn distinct_dst_ports_dupes() {
        let summary_1 = sample_tcp_packet(1_234, 80);
        let summary_2 = sample_tcp_packet(2_345, 110);
        let summary_3 = PacketSummary {
            dst_port: Some(440),
            ..sample_tcp_packet(3_456, 90)
        };

        let summary_key_flow = FlowKey {
            src_ip: summary_1.src_ip,
            dst_ip: summary_1.dst_ip,
            protocol: summary_1.protocol,
        };

        let mut counters = SlidingWindowCounters::new(10);

        counters.record(summary_key_flow.clone(), &summary_1);
        counters.record(summary_key_flow.clone(), &summary_2);
        counters.record(summary_key_flow.clone(), &summary_3);

        assert_eq!(counters.distinct_dst_ports_count(&summary_key_flow), 2);
    }
}
