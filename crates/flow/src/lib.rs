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

    /// TODO(week 3): update counters for the appropriate key(s), evicting
    /// state that has aged out of the window.
    pub fn record(&mut self, key: FlowKey, pkt: &PacketSummary) {
        let state = self.counts.entry(key).or_insert_with(|| WindowState { window_start_micros: pkt.timestamp_micros, ..Default::default() });
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
