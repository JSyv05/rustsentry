//! Week 6: SYN flood detector.
//! Alert when a destination IP receives more SYNs than ACKs (beyond
//! threshold) within the configured window — classic half-open-connection
//! flood signature.

use crate::{Alert, AlertKind, DetectorConfig};
use flow::SlidingWindowCounters;

pub fn check(_counters: &SlidingWindowCounters, _cfg: &DetectorConfig) -> Vec<Alert> {
    todo!("SYN flood threshold check — week 6")
}
