# Threat model and residual risk

This document updates the risk register on slide 7 of the deck with the status measured in the full build.

**Environment for every number:** Colima `vz` VM (Ubuntu 24.04, kernel 6.8, 4 vCPU, 6 GB) on an Apple M5 (16 GB), Docker 29.5 with `userns-remap`, 3 runs (`results_final/final-{1,2,3}`), unless a row says otherwise.

## Scope

| | |
|---|---|
| **Attacker** | A compromised red- or blue-team process with code execution inside its own container. Separately, tenant B of a shared model server trying to learn tenant A's prompt. |
| **Trusted** | The host kernel and the VM, dockerd and the container runtime, the broker, the eBPF enforcer (root), and the log operator's signing key. Witnesses are trusted only to cosign consistent views; a quorum of them must be honest. |
| **Protected** | Attack payloads, defensive rules, model state (including the prompt cache) and audit records. |

## Risk register

| Risk | Status | Likelihood | Impact | Evidence and response |
|---|---|---|---|---|
| Cross-tenant network or file access | **MITIGATED** | Med | High | Two layers. Docker `--internal` networks, plus a per-zone eBPF default-deny on cgroup connect4/6 and UDP sendmsg4/6. All 4 forbidden red probes fail with `EPERM` (red→blue, red→model direct, red→internet, red→broker on a non-broker port). The blue volume is not mounted in red, and the code mount is read-only. Every blocked attempt is logged in the ledger (`blocked_connect`, 4 per run). Docker networks alone leave red→broker:9000 reachable (`ConnectionRefused`), and eBPF closes it. |
| Canary exposure via a monitored channel | **DETECTABLE** | Med | High | Scanner v3 catches 160–162/180 drills across 9 encodings, with 0 false positives on 10k noise lines. On the PoC's 6 encodings it catches 120/120 (v2: 100/120). |
| Fragment leak (≥10 chars of a canary) | **DETECTABLE** (was UNDETECTED) | Med | High | v3 matches K=10 base32 pieces, also reversed: 20/20 fragment drills caught (PoC: 0/20). |
| Fragment shorter than 10 chars, or a paraphrase that never quotes the canary | **UNDETECTED** | Med | High | Two 9-char pieces: 0–2/20 caught (only chance overlaps). Semantic paraphrase is not tested. Reported as residual risk. |
| Edit to a recorded event | **DETECTABLE** | Low | High | Inclusion proof against the cosigned root rejects it, and `bayora verify` rejects any edited, added or removed log line. |
| Omitted events, conflicting log views | **PARTIAL** | Low | High | 2 separate witness processes with persistent keys cosign every checkpoint and refuse a split view (HTTP 409). Both run on the operator's host as the same user, so they are separate but not independent; a remote witness (`--host`, config `witnesses:`) is supported but untested. Published checkpoints are re-derived from the log by the verifier. An operator that never logs an event at all is still residual risk. |
| KV/prefix-cache timing side channel | **MITIGATED for llama.cpp** (was PARTIAL) | Med | Invalidates findings | Shared cache: B recovers A's secret 60/60 times over 3 runs (chance 1/8). Per-tenant salt plus slot: 11/60 (p=0.12 vs chance), with 0 cross-tenant cache hits. This is llama.cpp CPU with Qwen2.5-0.5B; vLLM `cache_salt` is untested. Each run starts with a preflight audit, which is logged in the ledger (`cache_audit`). |
| Compromised host, VM, runtime or root insider | **OUT OF SCOPE** | Low | Total | Assumed trusted. The eBPF enforcer itself runs as root. The upgrade path is microVMs and full rootless dockerd (not tested; `userns-remap` only). |
| Prompt injection reveals blue-team rules | **OUT OF SCOPE** | Med | Med | A model-alignment problem. Model output is still scanned for canaries. |

## Known limits that are not risks of the design but of this build

- **Mock model for evaluation traffic.** The evaluation traffic in `bayora run` goes to the mock model. The real model is used only for the cache-timing audit.
- **Overhead baseline.** The host baseline runs on macOS while the containers run inside the VM, so container-vs-host p50 (0.25 vs 0.10 ms) mixes VM and network effects. The clean comparison is eBPF on versus off, both in the VM: 0.247–0.250 vs 0.248 ms p50. No measurable overhead was added.
- **Network channel capture.** The network channel is captured at the broker (application layer), not with packet capture.
- **Checkpoint and cosignature format.** These are signed-note style but not byte-compatible with C2SP tlog-cosignature.
- **Blind-test reveal.** `reveal.json` (content plus nonce) is published after the run; `bayora verify --reveal` checks it against the commitments in the receipt.
- **Zone enforcement timing.** The eBPF deny-all is attached to every zone cgroup before any container starts; allow entries are added once container addresses exist.
- **Key distribution.** `keys.json` is written by the run for convenience. A real auditor must pin the operator and witness keys out of band.
