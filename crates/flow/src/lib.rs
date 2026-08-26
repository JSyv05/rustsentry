//! Flow tracking: aggregates PacketSummary events into per-key counters
//! over sliding time windows. This is the shared primitive every detector
//! in `detect` builds on (week 5 in the capstone plan).

use parser::PacketSummary;
use std::collections::HashMap;
use std::net::IpAddr;

/// Key for grouping packets into a flow. Adjust granularity per detector:
/// SYN-flood detection groups by dst_ip; port-scan detection groups by src_ip.
pub type FlowKey = IpAddr;

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
    distinct_dst_ports: std::collections::HashSet<u16>,
    window_start_micros: i64,
}

impl SlidingWindowCounters {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            counts: HashMap::new(),
        }
    }

    /// TODO(week 5): update counters for the appropriate key(s), evicting
    /// state that has aged out of the window.
    pub fn record(&mut self, _key: FlowKey, _pkt: &PacketSummary) {
        todo!("sliding window update — week 5")
    }
}
