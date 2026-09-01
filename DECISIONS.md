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
