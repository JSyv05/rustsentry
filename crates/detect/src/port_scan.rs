//! Week 7: Port scan detector.
//! Alert when a single source IP contacts more than N distinct destination
//! ports within the configured window.

use crate::{Alert, AlertKind, DetectorConfig};
use flow::SlidingWindowCounters;

pub fn check(_counters: &SlidingWindowCounters, _cfg: &DetectorConfig) -> Vec<Alert> {
    todo!("port scan threshold check — week 7")
}
