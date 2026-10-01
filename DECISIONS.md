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
  separate approval, still to be confirmed. (Update: approved 09/29/2026 —
  see that entry below.)
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

- **Date:** 09/08/2026
- **Decision:** Added DHCP starvation detection as a Phase 3 backlog item,
  priority 8 in `capstone-plan.md` (below ARP spoofing and DNS tunneling) —
  stubbed as `crates/detect/src/dhcp_starvation.rs`, same pattern as the
  other backlog detectors. Did **not** add brute-force detection, which was
  considered alongside it.
- **Why:** DHCP starvation cleared the same bar ARP/DNS did: it's DoS-style
  (pool exhaustion denies service to legitimate clients), fits the existing
  flow/threshold detection paradigm, and costs ~zero to log now — a backlog
  row and a `todo!()` stub, nothing wired into `main.rs`. Like ARP spoofing,
  it will need new `parser` work (DHCP/BOOTP message parsing over UDP) and
  MAC-keyed state that `flow::SlidingWindowCounters` doesn't have today,
  since a DHCPDISCOVER is sent from 0.0.0.0 and isn't identifiable by its
  IP-based flow key.
- **Alternatives considered:** Brute-force detection (e.g. repeated failed
  SSH/FTP/HTTP auth) — rejected, at least for now. Two reasons, different
  in kind from the ARP/DNS cost-benefit above: (1) it isn't a DoS attack,
  and `capstone-plan.md`'s scope line (which the advisor's 09/04 sign-off
  covers) specifically defines this project as detecting "DoS-style attack
  patterns" — adding it would redefine the thesis, not just extend the
  backlog under it, and that warrants asking the advisor directly rather
  than logging it unilaterally. (2) it doesn't fit the existing detection
  shape the way ARP/DNS/DHCP do: real brute-force detection needs app-layer
  parsing of auth failure responses, generally a separate parser per
  targeted protocol (SSH, FTP, HTTP, RDP, ...), not one more UDP-based
  message format like DNS/DHCP. A cheap proxy (many short connections to
  one port from one source) is really just port-scan detection aimed at a
  single port, not a real brute-force signature, so it wasn't worth stubbing
  as one.

---

- **Date:** 09/13/2026
- **Decision:** Bumped the workspace Rust edition from 2021 to 2024
  (`Cargo.toml`'s `[workspace.package] edition`). Every crate inherits it
  via `edition.workspace = true`, so this is a single-line, workspace-wide
  change rather than a per-crate edit.
- **Why:** No reason found to stay on 2021 — there's no `rust-toolchain`
  file or documented MSRV anywhere in the repo pinning an older toolchain,
  and this workspace has no external consumers whose edition compatibility
  would need protecting. Verified `cargo build --workspace` and
  `cargo test --workspace` both still pass with no new warnings and no
  behavior change after the bump (current toolchain: rustc 1.98.0, which
  fully supports edition 2024). Picking it up now, this early in the
  project, is cheaper than migrating later once more code exists to touch.
- **Alternatives considered:** Staying on edition 2021 — rejected, no
  constraint (MSRV, external consumer, CI toolchain pin) was found that
  edition 2024 would violate, so there was no offsetting downside to weigh
  against using the current edition.

---

- **Date:** 09/17/2026
- **Decision:** Replay mode keeps deriving "now" from the packet's own
  embedded timestamp (`pkt.timestamp_micros`, as `SlidingWindowCounters`
  already does in `crates/flow/src/lib.rs`). Live/daemon mode will instead
  need a real wall clock (`Instant`/`SystemTime`) ticking on its own,
  independent of packet arrival. Not implemented yet — daemon mode as a
  whole is still deferred per the 09/01/2026 entry; this just settles which
  time source each mode uses once eviction is built.
- **Why:** Replay's packet-timestamp-driven time is deterministic and
  matches the pcap file exactly, so there's no reason to change it for that
  mode. But it breaks down for live capture: if "now" only advances when a
  packet arrives, a quiet/idle period with no traffic never advances time at
  all, so a stale flow would never age out of the flow table — exactly the
  unbounded-growth risk the 09/01 entry flagged. A wall-clock tick (e.g. a
  periodic timer independent of the packet-read loop) is the only way to
  advance time during idle stretches in live mode.
- **Alternatives considered:** Using packet timestamps as the sole time
  source in both modes — rejected, doesn't solve idle-period eviction in
  live mode. Using a wall clock in both modes — rejected for replay, since
  it would make replay speed (and thus window/eviction behavior) dependent
  on how fast the file happens to be read rather than the pcap's own
  timestamps, breaking replay's determinism.

---

- **Date:** 09/28/2026
- **Decision:** No code change. Documenting a lab-environment quirk found
  while testing live capture in the Kali/Ubuntu VirtualBox NatNetwork
  setup: on a capture handle that has received zero packets since it was
  opened, libpcap's read timeout (`.timeout(100)` +
  `.immediate_mode(true)` in `crates/capture/src/lib.rs`) does not fire —
  the read blocks indefinitely until the first packet arrives, after which
  `FrameEvent::Timeout` starts firing on schedule as expected. Sending a
  single ping into the target VM unblocked it. Since `tick()`'s 5-second
  dump/check/evict cadence depends on `FrameEvent::Timeout` firing while
  idle, a fully silent interface never reaches Milestone 2's detectors at
  all until something breaks the silence.
- **Why:** Confirmed the capture config itself is correct (timeout and
  immediate mode are both set) — this is a platform behavior of libpcap on
  Linux, not a bug in `rustsentry`. Not fixing it in code because a real
  monitored interface is essentially never fully silent (background
  broadcast/ARP traffic alone would prime it); this only surfaces on an
  isolated lab network with nothing else running on it. Logged here so the
  fix isn't rediscovered blind next time, and to justify the background
  traffic note added to `evaluation-methodology.md`.
- **Alternatives considered:** Adding an application-level keepalive/tick
  independent of `FrameEvent::Timeout` — rejected for now; it would add a
  second timing path alongside the existing packet-timestamp/wall-clock
  split (see 09/17/2026 entry) to solve a problem that a real deployment
  won't have. Revisit only if daemon mode needs to guarantee eviction
  progress on genuinely silent interfaces.

---

- **Date:** 09/29/2026
- **Decision:** Advisor signed off on `evaluation-methodology.md` and
  `capstone-plan.md`, submitted as PDF copies of the versions in the repo
  as of commit `8e91081`. This completes the Week 2 evaluation-methodology
  checkpoint and the Week 8 Milestone 2 scope checkpoint. Milestone 2
  itself is complete: both detectors were exercised against simulated
  attacks (`nmap` port scans, `hping3` SYN floods) in the lab VMs, with
  `tcpdump` recording ground truth; those captures are still on the VM,
  pending transfer.
- **Why:** The plan calls for written sign-off at these checkpoints while
  the advisor is still available this semester, ahead of sabbatical.
  Pinning the commit records exactly which version was approved, so any
  later edits to either document are distinguishable from the signed scope.
- **Alternatives considered:** N/A — this is a sign-off record, not a scope
  decision.

---

- **Date:** 09/30/2026
- **Decision:** Advisor approval of ML as a classifier over a message formatter
- **Why:** An ML classifier can detect anomalies in a capture that the 
  algorithm alone could not. Proves ML capabilities in detecting anomalies.
- **Alternatives considered:** Using an ML alert triage to summarize the capture
  into a human readable report — rejected for now; it is still a viable option, 
  but it alone does not prove that ML is a viable option for anomaly detection over the 
  algorithm alone. Advisor wants us to apply ML and AI to the problem rather than
  leveraging it to make a minor part of it work differently.

---

- **Date:** 09/30/2026
- **Decision:** Use Linfa over PyTorch
- **Why:** Linfa is a simpler, more focused ML library that is easier to integrate with Rust.
- **Alternatives considered:** Using PyTorch directly — rejected; though I have prior knowledge
  with PyTorch, it would introduce a level of complexity that simply using Linfa would fix. Linfa
  is purely Rust, so integration into the project would be easier and less error-prone.

---

- **Date:** 09/30/2026
- **Decision:** Have Professor Singh -> Sharma -> Sinha grade project in that order if Darwish is not available
- **Why:** Going in order of preference based on availability and close parallels with existing grading procedures.
- **Alternatives considered:** N/A: this is a contingency record. To be confirmed and signed off on by the advisor(s).

---

- **Date:** 09/30/2026
- **Decision:** Scope brute force out for now
- **Why:** This project is focused on DoS-style attacks and does not require protocol-specific analysis as part of the thesis.
- **Alternatives considered:** Continue with brute force attacks — rejected for now; Brute force requires application layer 
  complexity that the application itself would be a better place to handle. This program operates at layers 2-4 
  (link, network, transport), and implementing detection at layer 7 (the application layer) would constitute creating 
  protocol-specific analyzers, which exceeds the current scope of this project. To be discussed more with Professor Darwish.

---

- **Date:** 09/30/2026
- **Decision:** Daemon mode and Webhooks added as part of the project. Priority set to 3 and 4 respectively. reorders current
  backlog as of 09/29
- **Why:** Rustsentry is intended to operate on servers, and daemon mode/webhooks are important to server deployment.
- **Alternatives considered:** Excluding daemon mode — rejected; daemon mode at this point is a low-cost
  implementation that only requires a clean shutdown process given our previous design choices.
  Excluding webhooks — rejected for now; Webhooks provide an easy and low-cost way to incorporate real time notifications to a 
  company ecosystem (Slack for example). Decision can be changed if webhooks prove to be a security vulnerability or if
  they actively hinder the performance of the program.

---

- **Date:** 10/01/2026
- **Decision:** Implementing syslog alongside webhooks
- **Why:** Lots of SIEM software read off of syslogs, so it provides easy
  integration into that ecosystem. It is a low-cost implementation and
  it allows direct comparison against software out there (Seek, Suricata).
---


- **Date:** 10/01/2026
- **Decision:** Dispatch webhook notifications from a background worker
  thread (fed by a channel, e.g. `std::sync::mpsc`) rather than sending
  the HTTP request synchronously from inside `tick()`.
- **Why:** The webhook's own delivery time (network round-trip to Slack/
  whatever endpoint) is unchanged either way — a background thread doesn't
  make the HTTP call itself faster. What it fixes is a different risk: a
  synchronous `POST` inside `tick()` would block packet capture and
  detection while waiting on that network call, which is exactly the wrong
  time to stall the pipeline — i.e. during a flood, when the detector is
  both busiest and most needed. Moving dispatch off the hot path protects
  capture/detection throughput regardless of how slow or unreliable the
  webhook endpoint is.
- **Alternatives considered:** Synchronous dispatch in `tick()` — rejected;
  head-of-line blocks detection on an external, untrusted endpoint's
  response time. Pulling in `tokio` plus an async HTTP client — rejected
  for now; the rest of the pipeline is synchronous, and a full async
  runtime is a heavy dependency to add for a single outbound call when a
  plain worker thread does the same job with no architectural change
  elsewhere. Revisit only if more async I/O (e.g. multiple notification
  backends) makes the runtime cost worth it.

---

- **Date:** 10/01/2026
- **Decision:** Not yet decided — how the webhook worker thread should
  behave when its channel backs up (endpoint down or slow): drop the
  alert, buffer with a cap, or retry. Open question, to be settled when
  the worker thread is actually implemented.
- **Why:** Logged now so the question isn't lost before implementation —
  raised while scoping the 10/01/2026 background-thread decision above,
  but not resolved yet.
- **Alternatives considered:** Drop silently — simplest, but an alert is
  lost with no record. Bounded buffer, drop oldest/newest on overflow —
  bounds memory, but still loses alerts under sustained backpressure.
  Retry with backoff — most complete, but risks the same queue buildup if
  the endpoint stays down for a while. No option chosen yet.
