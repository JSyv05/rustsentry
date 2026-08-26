# rustsentry

A Rust network anomaly detector: captures live traffic (or replays .pcap
files) and flags DoS-style attack patterns — SYN floods, port scans, and
(stretch goal) ICMP floods — using flow-based sliding-window detection.

See `capstone-plan.md` (in the parent deliverables) for the full 15-week
milestone plan, and `DECISIONS.md` for the running log of scope decisions.

## Workspace layout
- `crates/capture` — live pcap capture + offline .pcap replay
- `crates/parser` — Ethernet/IP/TCP/UDP/ICMP dissection
- `crates/flow` — sliding-window flow tracking (shared by all detectors)
- `crates/detect` — one module per attack pattern (syn_flood, port_scan, ...)
- `crates/cli` — binary entry point, wires the pipeline together
- `config/thresholds.toml` — tunable detector thresholds
- `test-data/pcaps/` — sample benign + attack captures for tests/eval

## Getting started
```
cargo build
cargo run --bin rustsentry
```
Note: live capture requires elevated permissions (`sudo setcap
cap_net_raw,cap_net_admin=eip target/debug/rustsentry` on Linux, or run as
root). Development is expected to start against replayed .pcap files instead
— see DECISIONS.md.
