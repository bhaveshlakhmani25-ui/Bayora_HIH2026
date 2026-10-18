# Test plan

Each official objective maps to a control, a test, a command, and the measured result. The environment is the same as in [threat-model.md](threat-model.md): Colima vz, Apple M5, userns-remap, 3 runs.

| Objective | Control | Test | Command | Result |
|---|---|---|---|---|
| Isolate without breaking function | Internal networks, per-zone eBPF default-deny, hardened containers (cap-drop ALL, read-only, uid 65534, no-new-privileges), userns-remap | Red-zone probes; 3×500 requests red→broker→model | `bayora run` (`enforcer: ebpf`) | 4/4 forbidden paths blocked with EPERM; red→broker works; 1500/1500 requests complete; p50 0.25 ms (eBPF off: 0.25 ms) |
| Prevent information leakage | HMAC canaries, scanner v1/v2/v3 over 4 channels | 180 leak drills (4 channels × 9 encodings × 5) plus 10k noise lines | `bayora run`, `bayora drill` | v3 160–162/180, v2 120/180, v1 20/180; 0 false positives |
| Detect fragment leaks | v3 K=10 fragment index | 20 fragment drills (14-char prefix) | same | 20/20 (PoC 0/20) |
| Guarantee audit integrity | RFC 9162 Merkle log, Ed25519 operator, 2 witness processes, DSSE in-toto receipt | Edited event, bad reveal, split view; standalone verify | `bayora run`, `bayora verify <receipt> <log> --trust keys.json --checkpoints <dir>` | 3/3 tamper tests rejected; all 4 receipts verify with pinned keys; forged cosignature, missed quorum, untrusted key, bad DSSE, edited log and forked checkpoint all fail (`tests/test_receipt.py`) |
| Address LLM-native threats | Per-tenant salt plus slot at the serving layer; preflight timing audit | Tenant B infers which of 8 secrets A's prompt holds via time to first token | `bayora cachetest`, or `cache_audit: true` in `bayora run` | Shared 60/60, salted 11/60 (chance 7.5/60, p=0.12), 0 cross-tenant cache hits (llama.cpp, Qwen2.5-0.5B, CPU) |
| Quantify residual risk | Per-channel, per-encoding drill matrix; risk register | Same drills | dashboard coverage matrix | `described` (9-char pieces) 0–2/20 and listed as residual; unmonitored paths in threat-model.md |

## Reproduce

```bash
pip install -e ".[dev]" && python -m pytest -q tests            # 17 tests
docker build -t bayora/py:poc .
printf 'enforcer: ebpf\ncache_audit: true\ncache_trials: 20\n' > final.yaml
bayora run -c final.yaml -o results/final-1                    # repeat for -2, -3
bayora run -c <(echo 'enforcer: docker') -o results/compare-docker
bayora verify results/final-1/receipt.json results/final-1/log.jsonl --trust results/final-1/keys.json --checkpoints results/final-1/checkpoints
bayora dashboard --results results/final-1
```

CI runs the unit tests on Python 3.10 and 3.12, plus a full `bayora run` with the eBPF enforcer on `ubuntu-24.04`. First CI run (GitHub Actions run 39159248322, `ubuntu-24.04`): enforcer `ebpf`, 4/4 forbidden paths denied with EPERM, 4 `blocked_connect` events, receipt verifies with a 2-of-2 witness quorum. This is a second environment for the isolation claim.
