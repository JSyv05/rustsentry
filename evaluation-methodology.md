# Evaluation Methodology — RustSentry

**Purpose:** define, in advance, how this capstone will prove its detectors
actually work — drafted in Week 2 per `capstone-plan.md`, so instrumentation
(timestamps, counters, logging format) is built into the pipeline from the
start rather than bolted on at Week 13. Submitted for advisor sign-off as
its own checkpoint, separate from the Week 1 proposal approval.

---

## Scope

What gets evaluated, and when it becomes available to evaluate:

- **Rule-based detectors** (SYN flood, port scan) — Phase 2, available by
  Week 8 (Milestone 2). This is the minimum defensible evaluation target;
  everything below is additive.
- **ML classifier** (`linfa`, trained on flow features) — Phase 3, if it
  lands per the priority order in `capstone-plan.md`. Adds a rule-based vs.
  ML comparison to the evaluation.
- **Adaptive/statistical detection**, **third attack pattern** — only if
  they land; treated as stretch comparison points, not required for a
  complete evaluation.

## Attack Traffic Generation

- Generate real SYN floods, ICMP floods, and port scans with `hping3` or
  `nping`, against a VM under my control on an isolated lab network — never
  targeting anything I don't own.
- Capture generated traffic with both RustSentry and `tcpdump` running
  simultaneously, so `tcpdump`'s capture serves as ground truth for what
  attack traffic actually occurred and when.

## Benign Traffic Baseline

- Capture (or source a public benign pcap of) a normal browsing/streaming
  session to measure the false-positive rate against traffic with no
  attacks present.
- The existing ICS/SCADA test capture
  (`test-data/pcaps/4SICS-GeekLounge-151020.pcap`) is a development fixture,
  not this baseline — it's real-world traffic, but not labeled benign vs.
  attack, and its protocol mix (Modbus/S7comm-heavy, 88-byte average packet
  size) isn't representative of general network traffic.

## Metrics to Report

- **Detection latency** — time from attack start to alert.
- **False positive rate** — on the benign baseline above.
- **True positive rate** — across varied attack intensities (flood rate).
- **Throughput/overhead** — packets-per-second the pipeline sustains before
  dropping packets. This doubles as the answer to the daemon-mode CPU
  question raised in the 09/01/2026 `DECISIONS.md` entry: packet *rate*,
  not packet size, is the actual load driver.

## Optional Comparison Point

- Run the same pcaps through Suricata or Zeek and compare detection
  behavior. Even a modest, honest comparison ("we detect the same SYN
  floods with X ms more/less latency, at Y% of the code size") is strong
  evaluation content, and doesn't require matching their feature set.

## Rule-Based vs. ML Comparison

- If the ML classifier lands (Phase 3): report precision/recall/F1 for the
  `linfa` classifier against a labeled test set, compared directly against
  the rule-based detectors' false-positive/true-positive rates on the same
  traffic. This is the strongest evaluation content available and directly
  demonstrates the AI component requirement.
- If PyTorch is used instead of `linfa` (open question, see `DECISIONS.md`
  — pinned for Week 9-11), this comparison methodology doesn't change, only
  the training/inference implementation underneath it.

## Timeline

- **Week 2 (now):** this document drafted, submitted for advisor sign-off.
- **Weeks 5-8:** instrumentation (timestamps, counters, structured logging)
  built into the pipeline as detectors are implemented, so the metrics
  above can actually be measured once Milestone 2 lands.
- **Weeks 13-15 (Phase 4):** full evaluation suite executed, metrics
  collected, charts generated, written up in the final report.

---

**Advisor sign-off:**  ______________________   **Date:**  ____________
