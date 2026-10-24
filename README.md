# Bayora proof of concept (Hack in Hills '26, Track 04)

A runnable proof of concept for Bayora's detection and audit layers, with real Docker isolation between three zones.

## What it does

1. **Commit.** Red and blue teams commit `SHA-256(nonce || content)` of their payloads and rules into the log before the run.
2. **Isolate.** Red, blue and model run in separate Docker `--internal` networks. A broker container is the only path from red to the model. Every container runs with:
   - `--cap-drop ALL`, `--read-only` and `no-new-privileges`
   - non-root uid 65534
   - pids and memory limits
3. **Probe.** From inside the red zone, the run tries to reach the blue zone, the model directly and the internet. It also checks for the blue volume and tries to write the code mount.
4. **Load.** 500 requests go red → broker → model, and are compared with the same code running as plain host processes.
5. **Leak drills.** The run deliberately leaks 120 key-derived canaries through 4 channels (container log, filesystem, network at the broker, model output) in 6 encodings. It then scans with scanner v1 (exact match) and v2 (normalised and decoded).
6. **Audit.** Every result is appended to an RFC 9162 Merkle log. Checkpoints are Ed25519-signed and cosigned by two witnesses. The run then tests:
   - an edited event
   - a payload that doesn't match its commitment
   - a split-view checkpoint
7. **Receipt.** `results/receipt.json` binds the run ID, log root, commitments and drill recall.

## Run

On macOS, dockerd and the eBPF enforcer run in a Colima Linux VM:

```bash
brew install colima docker
colima start --vm-type vz --cpu 4 --memory 6
colima ssh -- sudo apt-get install -y python3-bpfcc linux-headers-$(colima ssh -- uname -r)
docker build -t bayora/py:poc .
```

For userns-remap, set this under `docker:` in `~/.colima/default/colima.yaml` and restart Colima (the containerd snapshotter cannot be combined with it):

```yaml
docker:
  userns-remap: default
  features:
    containerd-snapshotter: false
```

On Linux, install `python3-bpfcc` and the kernel headers, and make sure `sudo -n` works for the enforcer.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q tests                         # unit tests (also run in CI)
bayora drill                                      # leak drills in-process, no Docker
bayora run                                        # full run; needs Docker and the image in the config
bayora verify results/receipt.json results/log.jsonl
```

Configuration lives in `bayora/default.yaml` (image, zone networks, monitored channels, drill encodings, sizes).
Override any key with `bayora run -c my.yaml` or `bayora drill -c my.yaml`.

`bayora verify` checks that the log entries hash to the receipt's root and that the operator signature covers it.
With `--trust keys.json` it checks a witness quorum against pinned keys. `--checkpoints` checks the published checkpoints against the log, and `--reveal reveal.json` checks that each team's revealed content matches its commitment. In this build both witnesses run on the operator's machine. For independence, run one elsewhere with `bayora witness serve --host 0.0.0.0` and list it under `witnesses:` in the config.

## Measured results

These numbers come from Colima vz (Ubuntu 24.04, kernel 6.8, 4 vCPU) on an Apple M5, Docker 29.5 with userns-remap and the eBPF enforcer, over 3 runs. See `results_final/` and [docs/test-plan.md](docs/test-plan.md). The PoC numbers from the deck are in `results_poc/`, and [docs/deck-numbers.md](docs/deck-numbers.md) compares the two.

| Test | Result |
|---|---|
| Forbidden red paths (to blue, to model directly, to the internet, to the broker on another port) | 4/4 denied with EPERM by eBPF and logged in the ledger; red→broker still works |
| 3×500 requests through the containers | 100% completed; p50 0.25 ms with eBPF on and with it off |
| Leak drills (4 channels × 9 encodings × 5) | v1 20/180, v2 120/180, v3 160–162/180 |
| Fragment leaks (14 chars) | v3 20/20 (PoC: 0/20) |
| False positives | 0 in 10,000 noise lines, for every mode |
| Cache timing (llama.cpp, Qwen2.5-0.5B, K=8) | Shared cache: 60/60 secrets recovered. Salted: 11/60, which is chance (p=0.12), with 0 cross-tenant cache hits |
| Tamper: edited event, bad reveal, split view | 3/3 rejected; the split view is refused by an HTTP witness process |
| Receipt | DSSE in-toto receipt verifies with pinned keys, a 2-of-2 witness quorum, and published checkpoints |
| Ledger | about 540–570k appends/s; inclusion proof 0.015 ms |

The dashboard is `bayora dashboard --trust results_final/demo/keys.json` (default results folder `results_final/demo`, the complete demo run with the cache audit and reveal). It opens at http://127.0.0.1:8765. Without `--trust` it still verifies, but shows the result as consistent with unpinned keys. It has a landing page (`#/`) and a console (`#/app/overview`, isolation, detection, side channel, ledger, verify, limits). **Tamper and verify** edits a temporary copy of one event and shows the receipt being rejected, without touching the real log.

## Not in this build (honest scope)

- **Isolation layer.** Zones use Docker internal networks plus an eBPF default-deny egress policy per zone (cgroup v2 connect4/6 and UDP sendmsg4/6, `bayora/isolation/`). Blocked attempts are logged into the ledger. Measured on Colima (Ubuntu 24.04 VM, kernel 6.8, Apple M5) with `userns-remap`. Full rootless dockerd has not been tested.
- **Model.** Evaluation traffic goes to a mock model. The cache-timing audit uses a real model: llama.cpp server, CPU, Qwen2.5-0.5B Q4_K_M.
  Download it into `models/`:
  `curl -L -o models/qwen2.5-0.5b-instruct-q4_k_m.gguf https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf`
  Then run `bayora cachetest`.
  - Measured on Colima vz, Apple M5, 20 trials, K=8 candidates. With a shared cache, B recovers the secret 20/20 times (p≈9e-19). With a per-tenant salt and slot, 2/20, which is chance (p=0.73), with 0 cross-tenant cache hits.
  - Salting is emulated, because llama.cpp has no vLLM `cache_salt`. vLLM itself has not been tested.
- **Network channel.** It's captured at the broker (application layer), not with packet capture.
- **Detection limit.** Fragments shorter than 10 characters, and paraphrases that never quote the canary, are not detected. They are reported as residual risk.
