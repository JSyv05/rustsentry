//! Week 6: SYN flood detector.
//! Alert when a destination IP receives more SYNs than ACKs (beyond or at
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
    use crate::test_utils;

    use flow::SlidingWindowCounters;
    use parser::TcpFlags;

    const WINDOW_SECS: u64 = 10;
    const SYN_WITHOUT_ACK_THRESHOLD: u64 = 100;
    const DISTINCT_PORTS_THRESHOLD: u64 = 20;
    const DUMP_INTERVAL_SECS: u64 = 5;

    #[test]
    fn below_threshold_no_alert() {
        let clt_ip = test_utils::ip(1);
        let tgt_ip = test_utils::ip(2);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let clt_sum = test_utils::sample_tcp_packet(
            clt_ip,
            tgt_ip,
            Some(1),
            Some(2),
            Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            }),
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for _ in 0..cfg.syn_without_ack_threshold - 1 {
            test_utils::record_tcp_packet(&mut ctr, &clt_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);
        assert!(alerts.is_empty());
    }

    #[test]
    fn at_threshold_alerts_on_victim() {
        let clt_ip = test_utils::ip(1);
        let tgt_ip = test_utils::ip(2);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let clt_sum = test_utils::sample_tcp_packet(
            clt_ip,
            tgt_ip,
            Some(1),
            Some(2),
            Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            }),
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for _ in 0..cfg.syn_without_ack_threshold {
            test_utils::record_tcp_packet(&mut ctr, &clt_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);
        assert!(!alerts.is_empty());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].target, tgt_ip);
    }

    #[test]
    fn distributed_sources_aggregate_per_destination() {
        let tgt_ip = test_utils::ip(0);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for n in 0..cfg.syn_without_ack_threshold {
            let clt_ip = test_utils::ip(n as u8 % 4 + 1);
            let clt_sum = test_utils::sample_tcp_packet(
                clt_ip,
                tgt_ip,
                Some(1),
                Some(2),
                Some(TcpFlags {
                    syn: true,
                    ..TcpFlags::default()
                }),
            );
            test_utils::record_tcp_packet(&mut ctr, &clt_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);
        assert!(!alerts.is_empty());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].target, tgt_ip);
    }

    #[test]
    fn balanced_handshakes_no_alert() {
        let clt_ip = test_utils::ip(1);
        let tgt_ip = test_utils::ip(2);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let clt_syn_sum = test_utils::sample_tcp_packet(
            clt_ip,
            tgt_ip,
            Some(1),
            Some(2),
            Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            }),
        );

        let tgt_syn_ack_sum = test_utils::sample_tcp_packet(
            tgt_ip,
            clt_ip,
            Some(2),
            Some(1),
            Some(TcpFlags {
                syn: true,
                ack: true,
                ..TcpFlags::default()
            }),
        );

        let clt_ack_sum = test_utils::sample_tcp_packet(
            clt_ip,
            tgt_ip,
            Some(1),
            Some(2),
            Some(TcpFlags {
                ack: true,
                ..TcpFlags::default()
            }),
        );

        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for _ in 0..cfg.syn_without_ack_threshold {
            test_utils::record_tcp_packet(&mut ctr, &clt_syn_sum);
            test_utils::record_tcp_packet(&mut ctr, &tgt_syn_ack_sum);
            test_utils::record_tcp_packet(&mut ctr, &clt_ack_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);
        assert!(alerts.is_empty());
    }

    #[test]
    fn only_victim_over_threshold_alerts() {
        let clt_ip = test_utils::ip(1);
        let tgt_ip = test_utils::ip(2);
        let otr_ip = test_utils::ip(3);

        let cfg = test_utils::sample_config(
            WINDOW_SECS,
            SYN_WITHOUT_ACK_THRESHOLD,
            DISTINCT_PORTS_THRESHOLD,
            DUMP_INTERVAL_SECS,
        );

        let clt_sum = test_utils::sample_tcp_packet(
            clt_ip,
            tgt_ip,
            Some(1),
            Some(2),
            Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            }),
        );

        let clt_otr_sum = test_utils::sample_tcp_packet(
            clt_ip,
            otr_ip,
            Some(1),
            Some(2),
            Some(TcpFlags {
                syn: true,
                ..TcpFlags::default()
            }),
        );
        let mut ctr = SlidingWindowCounters::new(cfg.window_secs);

        for _ in 0..cfg.syn_without_ack_threshold {
            test_utils::record_tcp_packet(&mut ctr, &clt_sum);
        }

        for _ in 0..cfg.syn_without_ack_threshold - 1 {
            test_utils::record_tcp_packet(&mut ctr, &clt_otr_sum);
        }

        let alerts = super::check(&ctr, &cfg, 0);
        assert!(!alerts.is_empty());

        for alert in &alerts {
            assert_ne!(alert.target, otr_ip)
        }
    }
}
