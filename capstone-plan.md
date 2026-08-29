# Capstone Project Plan: Rust Network Anomaly Detector

**Working title:** RustSentry (placeholder — rename freely)
**Scope:** A live packet-capture tool in Rust that detects DoS-style attack patterns (SYN floods, port scans, ICMP floods) using flow-based analysis, with a threshold-based detector as the core deliverable and an adaptive/statistical detector as a stretch goal.

**Constraint driving this plan:** advisor goes on sabbatical after this semester (15 weeks), so the plan front-loads anything that needs their sign-off (scope, milestones, evaluation methodology) into the first third of the term.

---

## Design principles for scoping

1. **Get an end-to-end pipeline working by week 4**, even if every stage is minimal. A thin vertical slice (capture → parse → naive threshold alert → print to stdout) de-risks the whole project far more than perfecting one stage in isolation.
2. **Everything after week 8 is additive**, not foundational. If you fall behind, you cut features from weeks 9–13, not from the core pipeline.
3. **Write the eval methodology in week 2**, not week 13. You need your advisor's sign-off on "how will I prove this works" while they're still around, and it shapes how you instrument the code from day one (timestamps, counters, logging format).

---

## Phase 1 — Foundation (Weeks 1–4)

**Goal:** end-to-end pipeline that captures live traffic, parses it, and prints packet summaries. No detection logic yet.

| Week | Deliverable |
| --- | --- |
| 1 | Project proposal doc finalized w/ advisor. Rust workspace scaffolded. Dev environment (Linux VM or container with `libpcap-dev`, capture permissions) working. `pcap` crate capturing raw frames and printing byte counts. |
| 2 | Ethernet/IP/TCP/UDP/ICMP parsing via `pnet` (or hand-rolled parsers — decide and justify in writeup). Print structured packet summaries (src/dst IP, ports, protocol, flags). **Also: draft evaluation methodology** (see Phase 4) and get advisor sign-off. |
| 3 | Flow tracking data structure: aggregate packets into per-(src,dst,proto) flow records with counters (packet count, byte count, SYN/ACK counts, first/last seen timestamp). |
| 4 | **Milestone 1 checkpoint.** Live capture → parse → flow table, dumped periodically to stdout/log file. This is your minimum viable pipeline — protect this milestone above all else. |

**Risk to flag now:** capture permissions. Decide early whether you're developing as root, with `setcap cap_net_raw,cap_net_admin=eip`, or entirely against replayed `.pcap` files (safer for a shared dev machine, and you can add live capture later). Recommend defaulting to pcap-file replay for early development and adding live capture in Phase 2 — it decouples "does my parser work" from "do I have the right permissions on this machine."

---

## Phase 2 — Detection engine v1: threshold-based (Weeks 5–8)

**Goal:** working detector for 2 attack patterns, rule-based thresholds, config-driven.

| Week | Deliverable |
| --- | --- |
| 5 | Sliding time-window infrastructure (ring buffer or time-bucketed counters per tracked host). This is the shared primitive both detectors below need. |
| 6 | **SYN flood detector**: track SYN-without-ACK ratio per destination IP over a window; alert on threshold breach. Config file for thresholds (don't hardcode — you'll want to tune these in Phase 4). |
| 7 | **Port scan detector**: track distinct destination ports contacted by one source IP over a window; alert on threshold breach. |
| 8 | **Milestone 2 checkpoint.** Both detectors running against replayed pcaps of known attack traffic (see Phase 4 for how to generate these) with alerts logged. This is your "minimum defensible capstone" — if everything after this slips, you still have a complete, demoable project. |

---

## Phase 3 — Stretch features (Weeks 9–12)

**Advisor requirement:** the project must incorporate AI in some form. Confirm with your advisor which flavor satisfies this (see note below), then treat the ML classifier as the primary Phase 3 feature rather than an optional stretch item — it's no longer purely optional the way the TUI is.

**AI scoping decision — ML-based anomaly detection (recommended) vs. LLM alert triage:**

- **ML classifier (recommended path, scoped below):** train a classical ML model (via `linfa`, in-Rust) on flow-level features to classify traffic as benign/SYN-flood/port-scan/etc. Strongest fit for a security-research capstone — gives you a real evaluation story (precision/recall/F1 against a labeled dataset, comparison against your rule-based detector) and a genuine differentiator versus existing Rust sniffer projects.
- **LLM alert triage (lower-risk alternative):** pipe structured alerts to an LLM API for human-readable summarization/prioritization. Faster to build, demos well, but is a UX layer on top of detection you've already done, not a detection contribution itself — confirm explicitly with your advisor whether this alone would satisfy the AI requirement before betting the semester's "AI component" on it.

Pick based on how Phase 2 went. Suggested priority order (do them top-down, stop whenever you run low on time):

| Priority | Feature | Why this order |
| --- | --- | --- |

| 1 | **ML classifier** (`linfa`) trained on flow features, added as a new `detect` module alongside the rule-based detectors | Satisfies the advisor's AI requirement *and* is your strongest evaluation/differentiation content — do this before anything else in Phase 3. |
| 2 | **TUI dashboard** (`ratatui`) showing live flow table + alerts | Highest demo value for lowest implementation risk — pure UI work over data you already have. |
| 3 | **Adaptive/statistical detection** (EWMA or z-score baselining instead of fixed thresholds) | Good secondary comparison point once the ML classifier exists — "rule-based vs. statistical vs. ML" is a nice three-way evaluation table. |
| 4 | **Third attack pattern** (ICMP flood or basic DNS amplification signal) | Straightforward extension of Phase 2 infrastructure once it exists. |
| 5 | **Slowloris-style detection** (long-lived low-rate connections) | Hardest — needs connection-lifecycle tracking over minutes, not just packet-rate windows. Only attempt if everything above finished early. |

### ML classifier sub-plan (Weeks 9–11)

| Week | Deliverable |
| --- | --- |
| 9 | Acquire a labeled NIDS dataset (CICIDS2017, NSL-KDD, or UNSW-NB15 are the standard benchmarks — pick one with clear DoS/port-scan labels). Build a feature-extraction pipeline that turns your existing `flow::SlidingWindowCounters` state into a feature vector (packet rate, distinct-port count, SYN/ACK ratio, etc.) matching what the dataset provides. |
| 10 | Train a classifier with `linfa` (start with something interpretable and fast to iterate on — logistic regression or decision tree — before trying anything fancier). Tune on a held-out validation split. |
| 11 | Integrate the trained model as a new `detect` module (`ml_classifier.rs`) that runs on live/replayed flow state and emits `Alert`s in the same format as the rule-based detectors, so it plugs into the existing pipeline and dashboard without special-casing. |

Week 12 is now buffer/comparison-prep time (folds into Phase 4's evaluation) rather than a fixed new-feature week — treat weeks 9–12 as a backlog you pull from, and better to ship the ML classifier solidly than to also force in the TUI and a third attack pattern half-done.

---

## Phase 4 — Evaluation, writeup, defense prep (Weeks 13–15)

**Goal:** turn a working tool into a defensible capstone with evidence it works.

**Evaluation methodology (draft this in Week 2, execute here):**

- **Attack traffic generation:** use `hping3` or `nping` against a VM you control (isolated lab network — never target anything you don't own) to generate real SYN floods, ICMP floods, and port scans. Capture these with your tool and with `tcpdump` simultaneously for ground truth.
- **Benign traffic baseline:** capture or find a public benign traffic pcap (e.g., normal browsing/streaming session) to measure your false positive rate.
- **Metrics to report:**
  - Detection latency (time from attack start to alert)
  - False positive rate on benign traffic
  - True positive rate across attack intensities (vary the flood rate)
  - Throughput/overhead: packets-per-second your pipeline can sustain before dropping packets
- **Optional comparison point:** run the same pcaps through Suricata or Zeek and compare detection behavior — even a modest, honest comparison ("we detect the same SYN floods with X ms more/less latency, at Y% of the code size") is a strong evaluation section.
- **Rule-based vs. ML comparison (now a core part of the eval, not optional):** report precision/recall/F1 for the `linfa` classifier against your labeled test set, and compare it directly against the rule-based detectors' false-positive/true-positive rates on the same traffic. This three-way (or two-way, if TUI/statistical detection didn't make it in) comparison is your strongest evaluation content and directly demonstrates the AI component your advisor asked for.

| Week | Deliverable |
| --- | --- |
| 13 | Run full evaluation suite, collect metrics, generate charts. |
| 14 | Write final report (motivation, related work — Snort/Suricata/Zeek/pnet ecosystem, architecture, evaluation, limitations/future work). Polish demo script. |
| 15 | Buffer week + defense/presentation. Do not schedule new features here. |

---

## Since your advisor won't be around next semester

- Get written sign-off (email is fine) on: the proposal (end of Week 1), the evaluation methodology (end of Week 2), and the Milestone 2 scope (end of Week 8) — these are the three points where scope disputes would otherwise stall you with no one to arbitrate.
- Ask now who reviews/grades the final defense if your advisor is unavailable, and confirm it in writing.
- Keep a short running decisions log (a `DECISIONS.md` in the repo) noting scope calls you made and why — useful both for your final report's "design decisions" section and as a paper trail if scope gets questioned later.

---

## Suggested Rust workspace structure

``` md
rustsentry/
├── Cargo.toml                # workspace root
├── DECISIONS.md
├── crates/
│   ├── capture/               # pcap/pnet wrapper: live capture + pcap-file replay
│   ├── parser/                # Ethernet/IP/TCP/UDP/ICMP dissection
│   ├── flow/                  # flow tracking, sliding-window primitives
│   ├── detect/                # detectors: syn_flood.rs, port_scan.rs, icmp_flood.rs
│   └── cli/                   # binary crate: wires it together, config loading, logging
├── tui/                       # optional ratatui dashboard (Phase 3)
├── config/
│   └── thresholds.toml
└── test-data/
    └── pcaps/                 # sample benign + attack captures for tests/eval
```

Splitting into crates isn't just tidiness — it lets you unit-test `parser` and `detect` against static pcap fixtures without needing capture permissions, which matters a lot given the permissions friction noted in Phase 1.
