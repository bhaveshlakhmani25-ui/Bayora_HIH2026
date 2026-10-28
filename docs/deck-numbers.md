# Deck numbers: PoC (v4.1) versus full build

PoC numbers came from a 2-vCPU cloud sandbox, Docker 29.8, mock model, 3 runs. They are now archived in `results_poc/`, which moved from `results_final/`, so update the slide 6 source line.
Full-build numbers come from Colima vz on an Apple M5 with Docker 29.5, userns-remap, the eBPF enforcer and 3 runs, in `results_final/final-{1,2,3}`.

| Slide | Claim | PoC (v4.1) | Full build | Notes |
|---|---|---|---|---|
| 6, 7, 8 | Cross-zone paths blocked | 3/3 | **4/4** forbidden paths, with EPERM from eBPF | The new probe is red→broker on a non-broker port, which Docker networks alone allow. Each attempt is logged as a `blocked_connect` event. |
| 6, 8 | Leak drills caught | v2 100/120, v1 20/120 | **v3 120/120** on the same 6 encodings; v3 160–162/180 with paraphrases | v2 on the 6 encodings is still 100/120 |
| 6, 7, 8 | Fragment leaks caught | 0/20 | **20/20** (v3) | Fragments under 10 chars are still missed (0–2/20) |
| 6, 8 | False positives | 0 in 10k noise lines | 0 in 10k noise lines (all modes) | |
| 6 | Tamper tests rejected | 3/3 | 3/3, with the split view now refused by an HTTP witness process | |
| 6 | Added latency | +0.3 ms p50 | eBPF on vs off: 0.25 vs 0.25 ms p50 (no measurable change) | Container vs macOS host (0.25 vs 0.10 ms) is not a like-for-like baseline |
| 3, 6, 7 | Cache-timing test | not run | **Shared 60/60 secret recovered; salted 11/60 (chance), 0 cache hits** | llama.cpp CPU, Qwen2.5-0.5B Q4_K_M. Not vLLM, so say "llama.cpp" on the slide. |
| 6 | Phase 4 | NEXT | eBPF ✔, userns-remap ✔ (not full rootless), real model for cache test ✔, cache audit passes ✔ | |
| 4 | MVP stack | Docker internal networks plus hardening; target rootless plus eBPF | Internal networks plus per-zone eBPF default-deny, userns-remap | |
| 3 | Witnessed receipt | 2 in-process witnesses | 2 witness processes with persistent keys (same host in this build, so separate rather than independent); DSSE in-toto receipt binds the model sha256, commitments, drill results and log root | |
| — | Ledger throughput | about 200k appends/s, 0.05 ms per proof | about 540–570k appends/s, 0.015 ms per proof | Faster CPU. Label it Apple M5. |
