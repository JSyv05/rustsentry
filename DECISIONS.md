# Decisions Log

Track scope calls and their rationale here as you make them — this feeds
directly into your final report's design-decisions section, and gives you
a paper trail since your advisor is on sabbatical during grading.

## Format

- **Date:**
- **Decision:**
- **Why:**
- **Alternatives considered:**

---

- **Date:** Week 1
- **Decision:** Development starts against replayed .pcap files, not live capture.
- **Why:** Avoids capture-permission friction on shared dev machines while
  parser/flow/detect logic is still unstable.
- **Alternatives considered:** Live capture from day one — rejected, too much
  early risk tied up in environment setup rather than logic.

---

- **Date:** 08/28/2026 Week 1
- **Decision:** Chose Rust over languages like C and Go
- **Why:** I want to take advantage of Rust's garbage collector to create a memory safe program will low runtime overhead.
- **Alternatives considered:** C: rejected, smarter memory management over manual menory management. Go: rejected, Rust's garbage collector has the advantage of not possibly pausing. Packets/second is an important metric for tracking the efficiency of the program.

---

- **Date:** 08/29/2026
- **Decision:** libpcap is a documented system prerequisite, not vendored
- **Why:** This would require building libpcap into the project, unnecessary
- **Alternatives considered:** Vendoring libpcap: rejected, increases scope and takes away from current scope

---

- **Date:** Week 1 08/31/2026
- **Decision:** Have the program run as a daemon
- **Why:** For a NIDS to work effectively, it need to constantly run
- **Alternatives considered:** Run as user software: rejected, makes more practical sense to run constantly.

---

- **Date:** 09/01/2026
- **Decision:** Daemon-mode implementation (flow-table eviction, signal
  handling, file/syslog logging) is deferred until flow tracking exists
  (Week 3+); not building it during Week 1.
- **Why:** Looked into CPU/memory risk for long-running operation. Packet
  size doesn't drive per-packet cost — packet *rate* does, and smaller
  average packet size means a *higher* rate at a given bandwidth (the
  4SICS test capture averages 88 bytes/packet, which is on the small
  side). The existing design already keeps expensive work off the
  per-packet path: parsing/flow-update is cheap per packet, while
  threshold/ML checks run periodically over the flow table, so cost
  scales with active-flow count, not raw packets/sec. The real
  long-running risk is unbounded growth of the flow `HashMap` if stale
  flows are never evicted — something a one-shot pcap-replay demo never
  surfaces, since the process just exits when the file ends.
- **Alternatives considered:** Building eviction/signal-handling/logging
  now: rejected, flow tracking (Week 3) doesn't exist yet so there's
  nothing to prune. Ignoring eviction entirely: rejected, would cause
  unbounded memory growth on a real long-running deployment.

---

- **Date:** 09/04/2026
- **Decision:** Advisor approved the project proposal (scope and milestones
  as described in `capstone-plan.md`) — Week 1 sign-off checkpoint complete.
  Note: this covers the proposal specifically; the evaluation methodology
  (Week 2 sign-off checkpoint, see `evaluation-methodology.md`) is a
  separate approval, still to be confirmed.
- **Why:** The plan calls for written sign-off on the proposal while the
  advisor is still available this semester, ahead of sabbatical, so scope
  can't later be disputed with no one to arbitrate.
- **Alternatives considered:** N/A — this is a sign-off record, not a scope
  decision.

---

- **Date:** 09/07/2026
- **Decision:** Added ARP spoofing and DNS tunneling detection as Phase 3
  backlog items, priorities 6 and 7 in `capstone-plan.md` (below the ML
  classifier, TUI, adaptive detection, and Slowloris) — stubbed as
  `crates/detect/src/arp_spoof.rs` and `dns_tunneling.rs`, matching the
  `syn_flood.rs`/`port_scan.rs` pattern. Not committed to building either;
  logging this now so the idea and its cost are on record.
- **Why:** Reviewed for scope bloat before adding. Cost today is ~zero —
  two backlog rows, two `todo!()` stub files, no new dependencies, nothing
  wired into `main.rs`'s detection loop — and their position at the bottom
  of an already-optional, top-down backlog (below Slowloris, which the plan
  already flags as "only attempt if everything above finished early") means
  they're unlikely to be reached at all within 15 weeks. If they ever are
  built, they're heavier than the other backlog items: both need new
  `parser` dissection work (ARP frames are dropped entirely today; DNS
  query contents aren't parsed at all), and ARP spoofing needs IP-to-MAC
  binding history that doesn't fit `flow::SlidingWindowCounters`'s
  per-flow model. Design call for whenever this is picked up: give ARP/DNS
  their own purpose-built types and parsing functions rather than bolting
  new optional fields onto `PacketSummary` — keeps it scoped to what it
  already represents and leaves the existing, tested TCP/UDP/ICMP parsing
  code untouched, at the cost of the two stub `check()` signatures needing
  to change (already known to be provisional; nothing calls them yet, so
  free to change later).
- **Alternatives considered:** Extending `PacketSummary` with ARP/DNS
  fields directly: rejected for whenever implementation happens — turns a
  scoped "IP packet summary" into a grab-bag of every protocol's leftover
  fields, and forces edits to all four existing struct-literal sites for
  fields most of them don't use. Not adding these to the plan at all:
  rejected, cost of recording the idea now is effectively zero.

---
