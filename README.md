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
It does not yet check witness cosignatures or whether the operator key is trusted (build plan step 5).

## Measured results

Measured on a 2-vCPU cloud sandbox, Docker 29.8, 3 runs. See `results_final/results.json`.

| Test | Result |
|---|---|
| Cross-zone paths blocked (red→blue, red→model direct, red→internet) | 3/3 blocked; red→broker works |
| Red sees blue volume / can write code mount | not mounted / read-only |
| 500 requests through hardened containers | 100% completed; p50 0.63–0.66 ms vs 0.31–0.33 ms on host, about +0.3 ms per request |
| Leak drills, scanner v1 | 20/120 detected (plain only) |
| Leak drills, scanner v2 | 100/120 detected. Plain, lowercase, base64, hex and split all 20/20; fragment leaks 0/20 |
| False positives | 0 in 10,000 noise lines, which include random forged `BYR…` canaries |
| Edited event | rejected by inclusion proof against the cosigned root |
| Mismatched reveal | rejected |
| Split view | refused by witness ("split view at size N") |
| Ledger | about 195k–218k appends/s; inclusion proof 16 hashes, verified in about 0.05 ms |

## Not in this PoC (honest scope)

- **Isolation layer.** It uses rootful Docker with hardening plus Docker internal networks (iptables). Rootless Docker and an eBPF policy are the target, not what was tested.
- **Model.** It's a mock model, not an LLM. The vLLM `cache_salt` timing test is Phase 4.
- **Network channel.** It's captured at the broker (application layer), not with packet capture.
- **Detection limit.** Fragment leaks and paraphrases are not detected by token scanning. They are reported as residual risk.
