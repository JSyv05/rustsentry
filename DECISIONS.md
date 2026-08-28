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
- **Alternatives Considered:** C - rejected, smarter memory management over manual menory management. Go  - rejected, Rust's garbage collector has the advantage of not possibly pausing. Packets/second is an important metric for tracking the efficiency of the program.
