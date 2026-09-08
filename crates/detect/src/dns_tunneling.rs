//! Phase 3 backlog (priority 7, see capstone-plan.md): DNS tunneling detector.
//! Alert on abnormal DNS query volume or query-name length per source IP
//! within the configured window — the classic data-exfiltration-via-DNS
//! signature.
//!
//! Not implementable as-is: `parser::parse_frame` records `payload_len` for
//! UDP packets but doesn't parse DNS message contents, so there's no query
//! name or query count to threshold on yet. This needs actual DNS message
//! parsing added on top of the existing UDP path before this detector has
//! anything to check. The signature below matches the other detectors for
//! consistency, but will likely need to change once that data exists.

use crate::{Alert, AlertKind, DetectorConfig};
use flow::SlidingWindowCounters;

pub fn check(_counters: &SlidingWindowCounters, _cfg: &DetectorConfig) -> Vec<Alert> {
    todo!("DNS tunneling detection — Phase 3 backlog")
}
