"""Single entry point for the PoC workloads. Role chosen by argv[1]: model | broker | red | blue."""
import sys, os, json, socket, time, base64, random, string

ROLE = sys.argv[1]


def serve(port, handler):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(64)
    while True:
        c, _ = s.accept()
        f = c.makefile("rwb")
        try:
            for line in f:
                out = handler(json.loads(line))
                f.write((json.dumps(out) + "\n").encode()); f.flush()
        except Exception:
            pass
        finally:
            c.close()


def ask(sock_file, obj):
    sock_file.write((json.dumps(obj) + "\n").encode()); sock_file.flush()
    return json.loads(sock_file.readline())


if ROLE == "model":
    # Mock client LLM: refuses, but in drill mode echoes a DRILL payload (simulated model-output leak)
    def h(req):
        p = req.get("prompt", "")
        if p.startswith("DRILL:"):
            return {"output": "Sure, here is what I remember: " + p[6:]}
        return {"output": f"I can't help with that. (len={len(p)})"}
    serve(9000, h)

elif ROLE == "broker":
    mh, mp = os.environ["MODEL_HOST"], 9000
    log = open("/data/transcript.jsonl", "a", buffering=1)
    def h(req):
        with socket.create_connection((mh, mp), timeout=5) as m:
            out = ask(m.makefile("rwb"), req)
        log.write(json.dumps({"ts": time.time(), "from": req.get("tenant"), "req": req, "resp": out}) + "\n")
        return out
    serve(7000, h)

elif ROLE == "red":
    mode = sys.argv[2]
    if mode == "probe":
        res = {}
        for name, host, port in [("red->blue", os.environ["BLUE_IP"], 8080), ("red->model_direct", os.environ["MODEL_IP"], 9000),
                                 ("red->internet", "1.1.1.1", 443), ("red->broker", os.environ["BROKER_HOST"], 7000),
                                 ("red->broker_other_port", os.environ["BROKER_HOST"], 9000)]:
            t = time.time()
            try:
                socket.create_connection((host, port), timeout=3).close(); res[name] = "CONNECTED"
            except OSError as e:
                res[name] = f"BLOCKED ({type(e).__name__})"
        res["red_reads_blue_volume"] = "VISIBLE" if os.path.exists("/blue_data") else "NOT MOUNTED"
        try:
            open("/app/agent.py", "a"); res["red_writes_code"] = "WRITABLE"
        except OSError:
            res["red_writes_code"] = "READ-ONLY"
        print(json.dumps(res))
    elif mode == "load":
        n = int(sys.argv[3]); payloads = open("/data/payloads.txt").read().split("\n")
        s = socket.create_connection((os.environ["BROKER_HOST"], 7000), timeout=10); f = s.makefile("rwb")
        lat = []
        t0 = time.perf_counter()
        for i in range(n):
            t = time.perf_counter(); ask(f, {"tenant": "red", "prompt": payloads[i % len(payloads)]}); lat.append(time.perf_counter() - t)
        total = time.perf_counter() - t0
        lat.sort()
        print(json.dumps({"n": n, "total_s": total, "p50_ms": lat[n // 2] * 1e3, "p95_ms": lat[int(n * .95)] * 1e3}))
    elif mode == "drill":
        # sends DRILL prompts so the model echoes foreign canaries (model_output channel) and
        # raw canary-bearing prompts through the broker (network channel at the choke point)
        items = json.loads(base64.b64decode(os.environ["DRILLS"]))
        s = socket.create_connection((os.environ["BROKER_HOST"], 7000), timeout=10); f = s.makefile("rwb")
        for it in items:
            if it["channel"] == "model_output":
                ask(f, {"tenant": "red", "prompt": "DRILL:" + it["text"]})
            elif it["channel"] == "network_broker":
                ask(f, {"tenant": "red", "prompt": "relay " + it["text"]})
        print("drills sent", len(items))

elif ROLE == "blue":
    mode = sys.argv[2]
    if mode == "serve":
        serve(8080, lambda r: {"ok": True})
    elif mode == "drill":
        items = json.loads(base64.b64decode(os.environ["DRILLS"]))
        rnd = random.Random(7)
        notes = open("/data/notes.txt", "a")
        # benign noise: IDs, hashes and base64 blobs that must NOT raise alarms
        for i in range(int(os.environ.get("NOISE", "2000"))):
            blob = "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(32))
            print(f"[blue] rule-eval id={rnd.getrandbits(64):016x} sig={base64.b64encode(blob.encode()).decode()} BYR{''.join(rnd.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') for _ in range(24))}")
        for it in items:
            if it["channel"] == "container_log":
                print(f"[blue] observed suspicious string: {it['text']}")
            elif it["channel"] == "filesystem":
                notes.write(f"note: {it['text']}\n")
        notes.close(); sys.stdout.flush()
