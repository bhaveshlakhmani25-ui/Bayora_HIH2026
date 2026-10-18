"""Bayora proof of concept: runs real Docker workloads and records every result in a
witness-cosigned Merkle log. Needs a running Docker daemon and the configured image.
Writes <out>/results.json, <out>/receipt.json and <out>/log.jsonl (the raw log entries)."""
import subprocess, json, os, sys, time, base64, shutil, statistics, random, platform
from pathlib import Path
from .ledger import LogOperator, Witness, verify_inclusion, leaf_hash, MerkleLog, checkpoint_body
from .canary import CanaryAuthority, scan
from .commit import commit, verify_reveal
from .drill import make_drills, score

# shortcut: container code is read from the source checkout, so `bayora run` needs an editable install; package it when images are built properly
CODE = Path(__file__).resolve().parents[1] / "containers"
WORK = "/tmp/bayora"


def sh(*a, check=True):
    p = subprocess.run(list(a), capture_output=True, text=True)
    if check and p.returncode: raise RuntimeError(p.stderr)
    return p.stdout.strip()


def ip(name): return sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name).split()[0]


def cleanup(zones):
    for c in ["bz-model", "bz-broker", "bz-blue"]: sh("docker", "rm", "-f", c, check=False)
    for n in zones.values(): sh("docker", "network", "rm", n, check=False)


def main(cfg, out="results"):
    if not (CODE / "agent.py").exists(): sys.exit(f"container code not found at {CODE}; install with `pip install -e .`")
    IMG, Z, CH = cfg["image"], cfg["zones"], cfg["channels"]
    RUN = "run-" + time.strftime("%Y%m%dT%H%M%S")
    HARDEN = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--user", "65534:65534",
              "--pids-limit", "128", "--memory", "256m", "--tmpfs", "/tmp", "-v", f"{CODE}:/app:ro"]
    R = {"run_id": RUN, "host": {"platform": platform.platform(), "cpus": os.cpu_count()}, "config": cfg}

    # ---------------- setup ----------------
    cleanup(Z); shutil.rmtree(WORK, ignore_errors=True)
    for d in ["red", "blue", "broker"]: os.makedirs(f"{WORK}/{d}"); os.chmod(f"{WORK}/{d}", 0o777)
    op = LogOperator(); w1 = Witness("witness-A", op.pub); w2 = Witness("witness-B", op.pub)
    auth = CanaryAuthority(RUN)
    log = lambda kind, **kw: op.log.append({"run": RUN, "kind": kind, "ts": time.time(), **kw})
    cosigs = []

    def checkpoint(prev_size):
        cp = op.checkpoint()
        proof = op.log.consistency_proof(prev_size) if prev_size else []
        sigs = [w.cosign(cp, proof) for w in (w1, w2)]
        cosigs.append({"size": cp["size"], "cosigned_by": [w.name for w, s in zip((w1, w2), sigs) if s]})
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
    cp0 = checkpoint(0)

    # ---------------- zones ----------------
    for n in Z.values(): sh("docker", "network", "create", "--internal", n)
    sh("docker", "run", "-d", "--name", "bz-model", "--network", Z["model"], *HARDEN, IMG, "python3", "/app/agent.py", "model")
    sh("docker", "run", "-d", "--name", "bz-blue", "--network", Z["blue"], *HARDEN, "-v", f"{WORK}/blue:/data", IMG, "python3", "/app/agent.py", "blue", "serve")
    sh("docker", "create", "--name", "bz-broker", "--network", Z["red"], *HARDEN, "-e", "MODEL_HOST=bz-model", "-v", f"{WORK}/broker:/data", IMG, "python3", "/app/agent.py", "broker")
    sh("docker", "network", "connect", Z["model"], "bz-broker"); sh("docker", "start", "bz-broker")
    time.sleep(2)
    env = ["-e", f"BLUE_IP={ip('bz-blue')}", "-e", f"MODEL_IP={ip('bz-model')}", "-e", "BROKER_HOST=bz-broker"]
    red = lambda *args, extra=(): sh("docker", "run", "--rm", "--network", Z["red"], *HARDEN, *env, *extra, "-v", f"{WORK}/red:/data", IMG, "python3", "/app/agent.py", "red", *args)

    # 2. isolation probes from inside the red zone
    probe = json.loads(red("probe"))
    R["isolation_probes"] = probe
    for k, v in probe.items(): log("isolation_probe", probe=k, result=v)

    # 3. function preserved + overhead: containerised path vs. same code as host processes
    N = cfg["load_requests"]
    cont = [json.loads(red("load", str(N))) for _ in range(3)]
    procs = [subprocess.Popen([sys.executable, f"{CODE}/agent.py", "model"])]
    time.sleep(0.5)
    os.makedirs(f"{WORK}/hostbroker", exist_ok=True)
    # host baseline: broker writes to its own dir; reuse agent code with /data remapped via cwd trick
    hb_env = dict(os.environ, MODEL_HOST="127.0.0.1")
    broker_code = open(f"{CODE}/agent.py").read().replace("/data/", f"{WORK}/hostbroker/").replace("serve(7000", "serve(7001")
    open(f"{WORK}/hostbroker/agent_b.py", "w").write(broker_code)
    procs.append(subprocess.Popen([sys.executable, f"{WORK}/hostbroker/agent_b.py", "broker"], env=hb_env))
    red_code = broker_code.replace(f"{WORK}/hostbroker/payloads.txt", f"{WORK}/red/payloads.txt").replace("7000), timeout=10)", "7001), timeout=10)")
    open(f"{WORK}/hostbroker/agent_r.py", "w").write(red_code)
    time.sleep(0.5)
    base = []
    for _ in range(3):
        out_ = subprocess.run([sys.executable, f"{WORK}/hostbroker/agent_r.py", "red", "load", str(N)],
                              env=dict(os.environ, BROKER_HOST="127.0.0.1"), capture_output=True, text=True).stdout
        base.append(json.loads(out_))
    for p in procs: p.terminate()
    med = lambda xs, k: statistics.median(x[k] for x in xs)
    R["function"] = {"requests_per_run": N, "runs": 3, "completed": all(c["n"] == N for c in cont),
                     "containers_p50_ms": med(cont, "p50_ms"), "baseline_p50_ms": med(base, "p50_ms"),
                     "containers_total_s": med(cont, "total_s"), "baseline_total_s": med(base, "total_s")}
    R["function"]["throughput_overhead_pct"] = 100 * (R["function"]["containers_total_s"] / R["function"]["baseline_total_s"] - 1)
    log("function", **R["function"])
    cp1 = checkpoint(cp0["size"])

    # 4. leak drills: deliberately leak canaries through every monitored channel in several encodings
    drills = make_drills(auth, CH, cfg["encodings"], cfg["drills_per_cell"])
    blue_drills = [d for d in drills if d["channel"] in ("container_log", "filesystem")]
    red_drills = [d for d in drills if d["channel"] in ("network_broker", "model_output")]
    b64 = lambda xs: base64.b64encode(json.dumps(xs).encode()).decode()
    blue_log = sh("docker", "logs", "bz-blue") + "\n"
    blue_log_drill = subprocess.run(["docker", "run", "--rm", "--network", Z["blue"], *HARDEN, "-e", f"DRILLS={b64(blue_drills)}", "-e", f"NOISE={cfg['noise_lines']}",
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
    drill_toks = {d["token"] for d in drills}
    for mode in ("v1", "v2"):
        results[mode], found = score(drills, sources, auth, CH, mode)
        if mode == "v2":
            for ch in CH:
                for tok, a in found[ch].items():
                    if tok in drill_toks:
                        log("leak_alert", observed_channel=ch, src_tenant=a["tenant"], slot=a["slot"], canary=tok[:10] + "...")
    R["leak_drills"] = results
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
    R["bench"] = {"append_events_per_s": 50000 / ta, "root_50k_s": tr, "inclusion_proof_ms": tp * 1e3, "proofs_ok": ok,
                  "proof_hashes": len(bl.inclusion_proof(0)), "scanner_v2_MB_per_s": len(big) / 1e6 / ts}

    final = checkpoint(cp3["size"])
    R["ledger"] = {"events": final["size"], "root": final["root"].hex(), "checkpoints": cosigs,
                   "witness_alarms": {w1.name: w1.alarms, w2.name: w2.alarms}}
    receipt = {"run_id": RUN, "origin": op.origin, "log_size": final["size"], "log_root": final["root"].hex(),
               "commitments": {"red": c_red, "blue": c_blue}, "operator_pubkey_raw": op.pub.public_bytes_raw().hex(),
               "operator_sig": final["sig"].hex(), "cosigned_by": cosigs[-1]["cosigned_by"],
               "drill_recall_v2": f'{results["v2"]["detected"]}/{results["v2"]["total"]}', "false_positives": results["v2"]["false_positives"]}
    os.makedirs(out, exist_ok=True)
    json.dump(R, open(f"{out}/results.json", "w"), indent=2, default=str)
    json.dump(receipt, open(f"{out}/receipt.json", "w"), indent=2)
    with open(f"{out}/log.jsonl", "wb") as f: f.write(b"".join(e + b"\n" for e in op.log.entries[:final["size"]]))
    cleanup(Z)
    print(json.dumps(R, indent=1, default=str)[:6000])
