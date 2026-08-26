//! Detection engine: rule-based detectors that read from flow::SlidingWindowCounters
//! and emit Alerts. Add one module per attack pattern.

pub mod syn_flood;
pub mod port_scan;
// pub mod icmp_flood;   // Phase 3 stretch goal
// pub mod slowloris;    // Phase 3 stretch goal, only if time allows

use std::net::IpAddr;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    pub target: IpAddr,
    pub detected_at_micros: i64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum AlertKind {
    SynFlood,
    PortScan,
    IcmpFlood,
}

/// Thresholds are config-driven (see config/thresholds.toml) rather than
/// hardcoded, so they can be tuned during Phase 4 evaluation without
/// recompiling.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DetectorConfig {
    pub window_secs: u64,
    pub syn_without_ack_threshold: u64,
    pub distinct_ports_threshold: u64,
}
