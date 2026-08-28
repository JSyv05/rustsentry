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

``` bash
cargo build
cargo run --bin rustsentry
```

Note: live capture requires elevated permissions (`sudo setcap
cap_net_raw,cap_net_admin=eip target/debug/rustsentry` on Linux, or run as
root). Development is expected to start against replayed .pcap files instead
— see DECISIONS.md.

## AI component (advisor requirement)

`crates/detect/src/ml_classifier.rs` holds the ML-based flow classifier —
trained offline via `linfa` against a labeled NIDS dataset (CICIDS2017 /
NSL-KDD / UNSW-NB15 — pick one), producing `Alert`s alongside the rule-based
detectors. See `capstone-plan.md`, Phase 3 weeks 9–11, for the full plan.
Place the raw dataset under `test-data/datasets/` (gitignored — these are
typically large; don't commit them).

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
