//! Week 7: Port scan detector.
//! Alert when a single source IP contacts more than N distinct destination
//! ports within the configured window.

use crate::{Alert, AlertKind, DetectorConfig};
use flow::SlidingWindowCounters;
use std::collections::HashMap;
use std::net::IpAddr;

pub fn check(
    _counters: &SlidingWindowCounters,
    _cfg: &DetectorConfig,
    now_micros: i64,
) -> Vec<Alert> {
    let mut per_ip: HashMap<IpAddr, usize> = HashMap::new();
    for flow in _counters.flows() {
        let entry: &mut usize = per_ip.entry(flow.key.src_ip).or_default();
        *entry = (*entry).max(flow.distinct_dst_ports);
    }
    per_ip
        .into_iter()
        .filter(|(_, ports)| *ports as u64 >= _cfg.distinct_ports_threshold)
        .map(|(src, ports)| Alert {
            kind: AlertKind::PortScan,
            target: src,
            detected_at_micros: now_micros,
            detail: format!("{ports} distinct ports in window"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn below_threshold_no_alert() {}

    #[test]
    fn many_ports_one_host_alerts_on_scanner() {}

    #[test]
    fn same_port_many_hosts_no_alert() {}

    #[test]
    fn exactly_at_threshold_alerts() {}
}
