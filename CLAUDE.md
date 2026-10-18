# Bayora: project context for Claude Code

Hack in Hills '26, Track 04 (Securing Adversarial AI Safety Testing). Team **Claude's Clan**: Bhavesh Lakhmani (lead), Tashvi Adhlakha, Ovneet Kour. Round 1 was qualified with the PoC in this repo. The next round is a **full build in 1–2 weeks**. The code goes to a GitHub repo.

## What Bayora is

Bayora runs a blind, leak-audited red-vs-blue evaluation:

- It enforces boundaries between the red team, the blue team and the model.
- It detects planted canary exposure in monitored channels.
- It issues a receipt that anyone can verify.
- It never claims "zero leakage". A clean scan is not proof, and unmonitored paths are reported as residual risk.

## What already exists (PoC, all tested)

| Path | Contents |
|---|---|
| `bayora/ledger.py` | RFC 9162 Merkle log with inclusion and consistency proofs, Ed25519-signed checkpoints, and a `Witness` that cosigns and refuses split views. |
| `bayora/canary.py` | HMAC-derived canaries `BYR` + base32(HMAC(key, run\|tenant\|slot))[:24] with attribution. Scanner v1 does exact matching; v2 normalises case and whitespace and decodes base64/hex. |
| `bayora/commit.py` | Commit-reveal for blind tests. |
| `containers/agent.py` | Mock roles: `model`, `broker`, `red`, `blue`. |
| `bayora/run.py` (`bayora run`) | End-to-end run on Docker `--internal` networks, hardened with cap-drop ALL, read-only, non-root and no-new-privileges. It runs isolation probes, a load test, 120 leak drills, tamper tests and benchmarks, and writes `results/results.json`, `receipt.json` and `log.jsonl`. |
| `bayora/drill.py` (`bayora drill`) | Leak-drill matrix and scoring, shared by `run`; `drill` runs it in-process without Docker. |
| `bayora/verify.py` (`bayora verify`) | Checks a receipt against `log.jsonl`: Merkle root and operator signature. |
| `bayora/default.yaml`, `bayora/config.py` | Run config: image, zone networks, channels, encodings, sizes. |
| `bayora/isolation/` | `connect.bpf.c` and `enforcer.py` run as root where dockerd lives (Colima VM via `colima ssh`, or sudo on Linux). Each zone is placed in its own cgroup via `--cgroup-parent`. |
| `Dockerfile` | Zone image `bayora/py:poc` (`python:3.12-slim`). |
| `tests/` | 8 tests. Run with `pip install -e ".[dev]" && python -m pytest -q tests`. CI: `.github/workflows/ci.yml`. |

Measured results (2-vCPU sandbox), which the deck cites:

- 3/3 cross-zone paths blocked.
- Leak drills: 100/120 caught by scanner v2, 20/120 by v1.
- 0 false positives in 10k noise lines.
- Fragment leaks: 0/20 caught. This is a known gap.
- 3/3 tamper tests rejected.
- About +0.3 ms p50 added per request through the containers.
- Ledger: about 200k appends/s, and inclusion-proof verification takes about 0.05 ms.

## Honest-claims rules (keep these)

- Claim only what was measured. Label the environment for every number.
- Isolation: Docker internal networks plus a per-zone eBPF default-deny egress policy (`bayora/isolation/`), measured on Colima (vz, Ubuntu 24.04, kernel 6.8, Apple M5) with dockerd `userns-remap`. It is not full rootless dockerd. `enforcer: docker` turns eBPF off for comparison.
- The model is a mock. The vLLM `cache_salt` timing test has not been run yet.
- The "network" channel is captured at the broker (application layer), not with packet capture.

## Build plan for the next round (in order)

1. **Repo and packaging.**
   - Turn the code into a `pyproject` package with a CLI: `bayora run`, `bayora drill`, `bayora verify <receipt> <log>`.
   - Add a config file (YAML) for zones and channels.
   - Add GitHub Actions CI to run the tests.
2. **Isolation upgrade.**
   - Run rootless Docker, or `dockerd --userns-remap=default` as a step towards it.
   - Add an eBPF default-deny policy: cgroup v2 `connect4`/`connect6` programs per zone, using libbpf or bcc, with a fall-back to nftables.
   - Log every blocked connect attempt into the ledger as an event.
3. **Real model and cache test (Phase 4).**
   - Use a small LLM. The preferred stack is vLLM with `cache_salt`, on a GPU if one is available. On CPU, use llama.cpp or llama-cpp-python with prompt caching.
   - Attack: tenant B probes time-to-first-token for guessed prefixes of tenant A's seeded prompt.
   - Measure how accurately B can infer A's prefix with the cache shared versus salted per tenant.
4. **Leak detection v3.** Add fragment and paraphrase detection, for example n-gram or MinHash over registered secrets or embedding similarity. Re-run the drills; the target is to improve on the 0/20 fragment result.
5. **Witnesses and receipts.**
   - Run the witnesses as separate processes or services.
   - Publish checkpoints.
   - Produce an in-toto-style receipt.
   - Build a standalone verifier that has no access to the log operator.
6. **Demo dashboard.** A web UI showing:
   - the zones
   - live alerts
   - the leak-drill coverage matrix
   - checkpoints and witness cosignatures
   - a "verify receipt" button
7. **Evaluation report.** Re-run everything, update `results/` and the deck numbers, and write `docs/` covering the threat model and the test plan.

## Environment notes from the cloud sandbox (may differ on your machine)

- Docker Hub was blocked there, so the image was built with `docker import` from host Python. On a normal machine, use `FROM python:3.12-slim`.
- huggingface.co and download.pytorch.org were blocked there. A real model needs those domains or a local download.
- The kernel had BPF_SYSCALL, CGROUP_BPF and BTF, and cgroup2 was mounted at `/sys/fs/cgroup/unified`. libbpf headers and bpftool were missing.
