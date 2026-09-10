//! Phase 3 backlog (priority 8, see capstone-plan.md): DHCP starvation detector.
//! Alert when one source rapidly cycles through many distinct client MAC
//! addresses issuing DHCPDISCOVER/DHCPREQUEST within the configured window —
//! the classic address-pool-exhaustion DoS signature.
//!
//! Not implementable as-is: `parser::parse_frame` doesn't parse DHCP/BOOTP
//! message contents (it only sees these as generic UDP packets on ports
//! 67/68), so there's no message type or client MAC to threshold on yet.
//! Also, like ARP spoofing, this needs state keyed on MAC address rather
//! than IP — a DHCPDISCOVER is sent from 0.0.0.0, so IP-based flow keys
//! (what `flow::SlidingWindowCounters` uses today) don't identify the
//! requesting client at all. The signature below matches the other
//! detectors for consistency, but will likely need to change once the real
//! state this detector needs exists.

use crate::{Alert, AlertKind, DetectorConfig};
use flow::SlidingWindowCounters;

pub fn check(_counters: &SlidingWindowCounters, _cfg: &DetectorConfig) -> Vec<Alert> {
    todo!("DHCP starvation detection — Phase 3 backlog")
}
