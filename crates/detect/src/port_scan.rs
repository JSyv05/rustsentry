//! Week 7: Port scan detector.
//! Alert when a single source IP contacts at or more than N distinct destination
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
            detail: format!("{src} probed {ports} distinct ports in window"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::test_utils;
    use flow::SlidingWindowCounters;
    use parser::{MICROS_PER_SEC, PacketSummary, TcpFlags};

    const WINDOW_SECS: u64 = 10;
    const SYN_WITHOUT_ACK_THRESHOLD: u64 = 100;
    const DISTINCT_PORTS_THRESHOLD: u64 = 20;
    const DUMP_INTERVAL_SECS: u64 = 5;
    #[test]
    fn below_threshold_no_alert() {
        let clt_ip = test_utils::ip(0);
        let tgt_ip = test_utils::ip(1);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for n in 0..cfg.distinct_ports_threshold - 1 {
            let clt_sum = test_utils::sample_tcp_packet(
                clt_ip,
                tgt_ip,
                Some(1),
                Some(n as u16 + 2),
                Some(TcpFlags {
                    ..TcpFlags::default()
                }),
            );

            test_utils::record_tcp_packet(&mut ctr, &clt_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);

        assert!(alerts.is_empty());
    }

    #[test]
    fn many_ports_one_host_alerts_on_scanner() {
        let clt_ip = test_utils::ip(0);
        let tgt_ip = test_utils::ip(1);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for n in 0..cfg.distinct_ports_threshold {
            let clt_sum = test_utils::sample_tcp_packet(
                clt_ip,
                tgt_ip,
                Some(1),
                Some(n as u16 + 2),
                Some(TcpFlags {
                    ..TcpFlags::default()
                }),
            );

            test_utils::record_tcp_packet(&mut ctr, &clt_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);

        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].target, clt_ip);
        assert_eq!(alerts[0].kind, crate::AlertKind::PortScan);
    }

    #[test]
    fn same_port_many_hosts_no_alert() {
        let clt_ip = test_utils::ip(0);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for n in 0..cfg.distinct_ports_threshold {
            let tgt_ip = test_utils::ip(n as u8 + 1);
            let clt_sum = test_utils::sample_tcp_packet(
                clt_ip,
                tgt_ip,
                Some(1),
                Some(2),
                Some(TcpFlags::default()),
            );

            test_utils::record_tcp_packet(&mut ctr, &clt_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);

        assert!(alerts.is_empty());
    }
    // A scan that has aged out of the window must stop alerting, even though
    // its flow is still active on other traffic.
    #[test]
    fn scan_ages_out_of_window() {
        let clt_ip = test_utils::ip(0);
        let tgt_ip = test_utils::ip(1);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for n in 0..cfg.distinct_ports_threshold {
            let scan_pkt = test_utils::sample_tcp_packet(
                clt_ip,
                tgt_ip,
                Some(1),
                Some(n as u16 + 2),
                Some(TcpFlags::default()),
            );
            test_utils::record_tcp_packet(&mut ctr, &scan_pkt);
        }
        assert_eq!(super::check(&ctr, &cfg, 0).len(), 1);

        let later = 20 * MICROS_PER_SEC;
        let keepalive = PacketSummary {
            timestamp_micros: later,
            ..test_utils::sample_tcp_packet(
                clt_ip,
                tgt_ip,
                Some(1),
                Some(2),
                Some(TcpFlags::default()),
            )
        };
        test_utils::record_tcp_packet(&mut ctr, &keepalive);
        ctr.evict_stale(later);

        assert!(super::check(&ctr, &cfg, later).is_empty());
    }
}
