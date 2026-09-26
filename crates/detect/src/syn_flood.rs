//! Week 6: SYN flood detector.
//! Alert when a destination IP receives more SYNs than ACKs (beyond
//! threshold) within the configured window — classic half-open-connection
//! flood signature.

use crate::{Alert, AlertKind, DetectorConfig};
use flow::SlidingWindowCounters;
use std::collections::HashMap;
use std::net::IpAddr;

pub fn check(
    _counters: &SlidingWindowCounters,
    _cfg: &DetectorConfig,
    now_micros: i64,
) -> Vec<Alert> {
    let mut per_dst: HashMap<IpAddr, (u64, u64)> = HashMap::new();

    for flow in _counters.flows() {
        let entry = per_dst.entry(flow.key.dst_ip).or_default();
        entry.0 += flow.syn_count;
        entry.1 += flow.ack_count;
    }

    per_dst
        .into_iter()
        .filter(|(_, (syn, ack))| syn.saturating_sub(*ack) >= _cfg.syn_without_ack_threshold)
        .map(|(dst, (syn, ack))| Alert {
            kind: AlertKind::SynFlood,
            target: dst,
            detected_at_micros: now_micros,
            detail: format!("{syn} SYN vs {ack} ACKS in window"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn below_threshold_no_alert() {}

    #[test]
    fn at_threshold_alerts_on_victim() {}

    #[test]
    fn distributed_sources_aggregate_per_destination() {}

    #[test]
    fn balanced_handshakes_no_alert() {}

    #[test]
    fn only_victim_over_threshold_alerts() {}
}
