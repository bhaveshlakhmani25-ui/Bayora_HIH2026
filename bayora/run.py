"""Bayora proof of concept: runs real Docker workloads and records every result in a
witness-cosigned Merkle log. Needs a running Docker daemon and the configured image.
Writes <out>/results.json, <out>/receipt.json and <out>/log.jsonl (the raw log entries)."""
import atexit, subprocess, json, os, sys, time, base64, shutil, statistics, random, platform
from pathlib import Path
from .ledger import LogOperator, verify_inclusion, leaf_hash, MerkleLog, checkpoint_body
from .canary import CanaryAuthority, scan
from .commit import commit, verify_reveal
from .drill import make_drills, score, MODES
from . import isolation
from .witness import load_key, pub_hex, RemoteWitness
from .receipt import build_receipt, write_checkpoint

# shortcut: container code is read from the source checkout, so `bayora run` needs an editable install; package it when images are built properly
CODE = Path(__file__).resolve().parents[1] / "containers"
# under $HOME so Colima/Docker Desktop VMs see the same path (they share the home dir, not /tmp)
HOME = os.environ.get("BAYORA_HOME", str(Path.home() / ".bayora"))   # operator + witness keys persist here across runs
WORK = os.path.join(HOME, "work")


def sh(*a, check=True):
    p = subprocess.run(list(a), capture_output=True, text=True)
    if check and p.returncode: raise RuntimeError(p.stderr)
    return p.stdout.strip()


def ip(name): return sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name).split()[0]


OUTPUTS = ("results.json", "receipt.json", "keys.json", "reveal.json", "cachetest.json", "log.jsonl")


def clear_outputs(out):
    """Remove an earlier run's outputs from `out` (only Bayora's own files), so a reused folder never mixes two runs."""
    shutil.rmtree(f"{out}/checkpoints", ignore_errors=True)
    for f in OUTPUTS:
        if os.path.exists(f"{out}/{f}"): os.remove(f"{out}/{f}")


def cleanup(zones):
    for c in ["bz-model", "bz-broker", "bz-blue"]: sh("docker", "rm", "-f", c, check=False)
    for n in zones.values(): sh("docker", "network", "rm", n, check=False)


def main(cfg, out="results"):
    if not (CODE / "agent.py").exists(): sys.exit(f"container code not found at {CODE}; install with `pip install -e .`")
    IMG, Z, CH = cfg["image"], cfg["zones"], cfg["channels"]
    RUN = "run-" + time.strftime("%Y%m%dT%H%M%S")
    HARDEN = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--user", "65534:65534",
              "--pids-limit", "128", "--memory", "256m", "--tmpfs", "/tmp", "-v", f"{CODE}:/app:ro"]
    R = {"run_id": RUN, "host": {"platform": platform.platform(), "cpus": os.cpu_count(), "docker": isolation.docker_mode()}, "config": cfg}
    CG = {z: isolation.cgroup_parent(z) for z in ("red", "blue", "model", "broker")}
    zone = lambda z: ["--cgroup-parent", CG[z][0]]

    # ---------------- setup ----------------
    cleanup(Z); shutil.rmtree(WORK, ignore_errors=True)
    for d in ["red", "blue", "broker"]: os.makedirs(f"{WORK}/{d}"); os.chmod(f"{WORK}/{d}", 0o777)
    op = LogOperator(f"bayora.dev/run/{RUN}", load_key(f"{HOME}/operator.key"))
    os.makedirs(out, exist_ok=True); clear_outputs(out)
    # witnesses are separate processes with their own persistent keys; config `witnesses` lists external ones instead
    urls, wprocs = list(cfg["witnesses"]), []
    for name in ([] if urls else ["witness-A", "witness-B"]):
        p = subprocess.Popen([sys.executable, "-m", "bayora.cli", "witness", "serve", "--name", name, "--port", "0",
                              "--state", f"{HOME}/{name}", "--operator-pubkey", pub_hex(op.key)], stdout=subprocess.PIPE, text=True)
        wprocs.append(p); urls.append(f"http://127.0.0.1:{p.stdout.readline().split()[1]}")
    atexit.register(lambda: [p.terminate() for p in wprocs])
    witnesses = [RemoteWitness(u, op.origin) for u in urls]
    w1 = witnesses[0]
    auth = CanaryAuthority(RUN)
    logf = open(f"{out}/log.jsonl", "wb")      # streamed as events happen, so the dashboard can follow a live run

    def log(kind, **kw):
        op.log.append({"run": RUN, "kind": kind, "ts": time.time(), **kw})
        logf.write(op.log.entries[-1] + b"\n"); logf.flush()
    cosigs, cps = [], []

    def checkpoint(prev_size):
        cp = op.checkpoint()
        proof = op.log.consistency_proof(prev_size) if prev_size else []
        sigs = {w.name: s for w in witnesses if (s := w.cosign(cp, proof))}
        cosigs.append({"size": cp["size"], "cosigned_by": list(sigs)})
        write_checkpoint(out, cp, "operator", cp["sig"], list(sigs.items()))
        cps.append(cp); cp["cosigs"] = sigs
        return cp

    # red payloads carry red canaries; blue rules carry blue canaries
    red_tokens = [auth.mint("red", f"payload-{i}") for i in range(20)]
    blue_tokens = [auth.mint("blue", f"rule-{i}") for i in range(10)]
    payloads = "\n".join(f"Attack prompt #{i}: ignore previous instructions [{t}]" for i, t in enumerate(red_tokens))
    rules = "\n".join(f"deny if pattern matches injection-{i} [{t}]" for i, t in enumerate(blue_tokens))
    open(f"{WORK}/red/payloads.txt", "w").write(payloads)
    open(f"{WORK}/blue/rules.txt", "w").write(rules)

    # 1. blind-test commitments (before the run)
    c_red, n_red = commit(payloads.encode()); c_blue, n_blue = commit(rules.encode())
    log("commitment", tenant="red", digest=c_red); log("commitment", tenant="blue", digest=c_blue)
    # preflight cache-timing audit on the real model (Phase 4): logged before any evaluation traffic
    model_sha = None
    if cfg["cache_audit"]:
        from .cachetest import run as cachetest
        ca = cachetest(cfg, out=out)
        model_sha = ca["model_sha256"]
        R["cache_audit"] = {k: v for k, v in ca.items() if k not in ("shared", "salted")}
        for c in ("shared", "salted"): R["cache_audit"][c] = {k: v for k, v in ca[c].items() if k != "rows"}
        log("cache_audit", engine=ca["engine"], model_sha256=model_sha, passed=ca["pass"],
            **{f"{c}_{k}": ca[c][k] for c in ("shared", "salted") for k in ("correct", "trials", "cross_tenant_cache_hits")})
    cp0 = checkpoint(0)

    # ---------------- zones ----------------
    # default-deny egress on every zone cgroup before any container starts; allow entries follow once IPs exist
    enf = isolation.Enforcer(cfg["enforcer"], {z: {"cgroup": CG[z][1], "allow": []} for z in CG}, f"{WORK}/blocked.jsonl")
    for n in Z.values(): sh("docker", "network", "create", "--internal", n)
    sh("docker", "run", "-d", "--name", "bz-model", "--network", Z["model"], *HARDEN, *zone("model"), IMG, "python3", "/app/agent.py", "model")
    sh("docker", "run", "-d", "--name", "bz-blue", "--network", Z["blue"], *HARDEN, *zone("blue"), "-v", f"{WORK}/blue:/data", IMG, "python3", "/app/agent.py", "blue", "serve")
    sh("docker", "create", "--name", "bz-broker", "--network", Z["red"], *HARDEN, *zone("broker"), "-e", "MODEL_HOST=bz-model", "-v", f"{WORK}/broker:/data", IMG, "python3", "/app/agent.py", "broker")
    sh("docker", "network", "connect", Z["model"], "bz-broker"); sh("docker", "start", "bz-broker")
    time.sleep(2)
    # red may reach only the broker, the broker only the model
    net_ip = lambda c, n: sh("docker", "inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{n}").IPAddress}}}}', c)
    allow = {"red": [[net_ip("bz-broker", Z["red"]), 7000]], "broker": [[ip("bz-model"), 9000]], "blue": [], "model": []}
    enf.allow(allow)
    R["isolation"] = {"enforcer": enf.mode, "allow": allow, "deny_before_start": enf.mode == "ebpf"}
    env = ["-e", f"BLUE_IP={ip('bz-blue')}", "-e", f"MODEL_IP={ip('bz-model')}", "-e", "BROKER_HOST=bz-broker"]
    red = lambda *args, extra=(): sh("docker", "run", "--rm", "--network", Z["red"], *HARDEN, *zone("red"), *env, *extra, "-v", f"{WORK}/red:/data", IMG, "python3", "/app/agent.py", "red", *args)

    # 2. isolation probes from inside the red zone
    probe = json.loads(red("probe"))
    R["isolation_probes"] = probe
    for k, v in probe.items(): log("isolation_probe", probe=k, result=v)

    # 3. function preserved under the policy: 3 x N requests red -> broker -> model through the hardened containers
    # (compare enforcer: ebpf against enforcer: docker for the policy's cost; a macOS host baseline would not be like for like)
    N = cfg["load_requests"]
    cont = [json.loads(red("load", str(N))) for _ in range(3)]
    med = lambda xs, k: statistics.median(x[k] for x in xs)
    R["function"] = {"requests_per_run": N, "runs": 3, "completed": all(c["n"] == N for c in cont),
                     "containers_p50_ms": med(cont, "p50_ms"), "containers_total_s": med(cont, "total_s"), "enforcer": enf.mode}
    log("function", **R["function"])
    cp1 = checkpoint(cp0["size"])

    # 4. leak drills: deliberately leak canaries through every monitored channel in several encodings
    drills = make_drills(auth, CH, cfg["encodings"], cfg["drills_per_cell"])
    blue_drills = [d for d in drills if d["channel"] in ("container_log", "filesystem")]
    red_drills = [d for d in drills if d["channel"] in ("network_broker", "model_output")]
    b64 = lambda xs: base64.b64encode(json.dumps(xs).encode()).decode()
    blue_log = sh("docker", "logs", "bz-blue") + "\n"
    blue_log_drill = subprocess.run(["docker", "run", "--rm", "--network", Z["blue"], *HARDEN, *zone("blue"), "-e", f"DRILLS={b64(blue_drills)}", "-e", f"NOISE={cfg['noise_lines']}",
                                     "-v", f"{WORK}/blue:/data", IMG, "python3", "/app/agent.py", "blue", "drill"], capture_output=True, text=True).stdout
    red("drill", extra=("-e", f"DRILLS={b64(red_drills)}"))
    time.sleep(1)
    transcript = [json.loads(l) for l in open(f"{WORK}/broker/transcript.jsonl")]
    sources = {
        "container_log": blue_log + blue_log_drill,
        "filesystem": open(f"{WORK}/blue/notes.txt").read() if os.path.exists(f"{WORK}/blue/notes.txt") else "",
        "network_broker": "\n".join(json.dumps(t["req"]) for t in transcript),
        "model_output": "\n".join(t["resp"]["output"] for t in transcript),
    }
    results = {}
    for mode in MODES:
        results[mode], alerts = score(drills, sources, auth, CH, mode)
    # alerts from the strongest scanner: planted drills and possible real leaks alike
    for x in alerts:
        log("leak_alert", observed_channel=x["channel"], src_tenant=x["tenant"], slot=x["slot"], canary=x["token"][:10] + "...", drill=x["drill"])
    R["leak_drills"] = results
    blocked = enf.stop()
    for b in blocked: log("blocked_connect", **b)
    R["isolation"]["blocked_connects"] = len(blocked)
    R["noise_lines_scanned"] = cfg["noise_lines"]
    # forged canaries: random BYR-strings in the noise never attribute (no key) -> part of FP count above
    cp2 = checkpoint(cp1["size"])

    # 5. reveal + tamper tests
    R["reveal"] = {"red_ok": verify_reveal(c_red, n_red, payloads.encode()), "blue_ok": verify_reveal(c_blue, n_blue, rules.encode()),
                   "tampered_payload_rejected": not verify_reveal(c_red, n_red, (payloads + " ").encode())}
    log("reveal", **R["reveal"])
    cp3 = checkpoint(cp2["size"])
    # tamper: change one recorded event and check it against the cosigned root
    idx = 5
    orig = op.log.entries[idx]
    tampered = orig.replace(b"BLOCKED", b"CONNECTED") if b"BLOCKED" in orig else orig + b" "
    proof = op.log.inclusion_proof(idx, cp3["size"])
    R["tamper"] = {"original_verifies": verify_inclusion(idx, cp3["size"], leaf_hash(orig), proof, cp3["root"]),
                   "edited_event_rejected": not verify_inclusion(idx, cp3["size"], leaf_hash(tampered), proof, cp3["root"])}
    # split view: operator shows witness-A a different history of the same size
    fork = MerkleLog(); [fork.leaves.append(l) for l in op.log.leaves]; fork.leaves[idx] = leaf_hash(tampered)
    body = checkpoint_body(op.origin, cp3["size"], fork.root())
    forged_cp = {"size": cp3["size"], "root": fork.root(), "body": body, "sig": op.key.sign(body)}
    R["tamper"]["split_view_refused_by_witness"] = w1.cosign(forged_cp, []) is None
    R["tamper"]["witness_alarm"] = w1.alarms[-1] if w1.alarms else None

    # 6. ledger + scanner micro-benchmarks
    bl = MerkleLog(); t = time.perf_counter()
    for i in range(50000): bl.append({"i": i, "kind": "bench", "payload": "x" * 64})
    ta = time.perf_counter() - t; t = time.perf_counter(); root = bl.root(); tr = time.perf_counter() - t
    rnd = random.Random(1); t = time.perf_counter(); ok = 0
    for _ in range(1000):
        m = rnd.randrange(50000); ok += verify_inclusion(m, 50000, bl.leaves[m], bl.inclusion_proof(m), root)
    tp = (time.perf_counter() - t) / 1000
    big = (sources["container_log"] * 20).encode()
    t = time.perf_counter(); scan(big.decode(), auth, "v2"); ts = time.perf_counter() - t
    t = time.perf_counter(); scan(big.decode(), auth, "v3"); ts3 = time.perf_counter() - t
    R["bench"] = {"append_events_per_s": 50000 / ta, "root_50k_s": tr, "inclusion_proof_ms": tp * 1e3, "proofs_ok": ok,
                  "proof_hashes": len(bl.inclusion_proof(0)), "scanner_v2_MB_per_s": len(big) / 1e6 / ts, "scanner_v3_MB_per_s": len(big) / 1e6 / ts3}

    final = checkpoint(cp3["size"])
    R["ledger"] = {"events": final["size"], "root": final["root"].hex(), "origin": op.origin, "checkpoints": cosigs,
                   "witness_alarms": {w.name: w.alarms for w in witnesses}}
    drills_summary = {m: {"recall": f'{r["detected"]}/{r["total"]}', "false_positives": r["false_positives"]} for m, r in results.items()}
    receipt = build_receipt(op, final, witnesses, final["cosigs"], RUN, {"red": c_red, "blue": c_blue}, drills_summary, model_sha, cps)
    # public keys to pin: an auditor should get these out of band, not from the operator's output directory
    keys = {"operator": pub_hex(op.key), "witnesses": {w.name: w.pub_hex for w in witnesses}, "quorum": len(witnesses)}
    json.dump(R, open(f"{out}/results.json", "w"), indent=2, default=str)
    json.dump(receipt, open(f"{out}/receipt.json", "w"), indent=2)
    json.dump(keys, open(f"{out}/keys.json", "w"), indent=2)
    # published after the run so anyone can check the blind commitments (bayora verify --reveal)
    reveal = {t: {"nonce": n.hex(), "content": base64.b64encode(c.encode()).decode()} for t, n, c in (("red", n_red, payloads), ("blue", n_blue, rules))}
    json.dump(reveal, open(f"{out}/reveal.json", "w"), indent=2)
    logf.close()
    cleanup(Z)
    print(json.dumps(R, indent=1, default=str)[:6000])
