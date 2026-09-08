//! Phase 3 backlog (priority 6, see capstone-plan.md): ARP spoofing detector.
//! Alert when an IP address's ARP-advertised MAC address changes within the
//! configured window — the classic ARP cache-poisoning / MITM signature.
//!
//! Not implementable as-is: `parser::parse_frame` currently drops ARP
//! frames entirely (non-IP ethertypes return `None`), so this needs an ARP
//! dissector added to `parser` first, plus IP-to-MAC binding history that
//! `flow::SlidingWindowCounters` doesn't track today (it's keyed on
//! (src, dst, proto), not on observed MAC addresses). The signature below
//! matches the other detectors for consistency, but will likely need to
//! change once the real state this detector needs exists.

use crate::{Alert, AlertKind, DetectorConfig};
use flow::SlidingWindowCounters;

pub fn check(_counters: &SlidingWindowCounters, _cfg: &DetectorConfig) -> Vec<Alert> {
    todo!("ARP spoofing detection — Phase 3 backlog")
}
