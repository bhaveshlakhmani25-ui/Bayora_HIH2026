"""Phase 4 cache-timing audit on a real llama.cpp server (CPU). Tenant B tries to infer which of K
candidate secrets tenant A's seeded prompt contains by timing its own prompts. Two conditions:
shared (both tenants on one slot, no salt) and salted (per-tenant salt prefix + per-tenant slot).
llama.cpp has no vLLM cache_salt; the salted condition emulates it at the broker. Results are labelled llama.cpp."""
import base64, hashlib, json, math, os, random, secrets, time
from .run import CODE, sh
from . import isolation

LLM_IMG = "ghcr.io/ggml-org/llama.cpp:server"
HEADER = "System prompt for tenant A. Confidential patient record follows. Record: "
BODY = (" Treatment notes: the patient reports mild symptoms; continue the current plan, review in two weeks,"
        " and keep this record confidential under the evaluation agreement.") * 6
K = 8
WARDS = ["east", "north", "west", "south", "annex", "level 2", "level 3", "oncology"]


def candidates(rnd):
    """K distinct secrets for one trial: llama.cpp's host-RAM prompt cache would otherwise let B hit its own past probes."""
    return [f"Diagnosis code {rnd.choice('CEFIJKMN')}{rnd.randrange(10, 99)}.{rnd.randrange(100)}, ward {w}." for w in WARDS]


def p_at_least(k, n, p):
    """Binomial tail P[X >= k]: chance that guessing at rate p gets k or more right out of n."""
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k, n + 1))


def passed(salted):
    """The timing probe must fail with salt on: the server reused no cross-tenant cache, and the attacker's
    accuracy is not distinguishable from chance. Chance-level accuracy alone is weak evidence with few trials."""
    return salted["cross_tenant_cache_hits"] == 0 and salted["p_value_vs_chance"] >= 0.05


def model_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def start_server(cfg, net):
    """Hardened llama.cpp container in the model zone; returns its base URL on `net`."""
    m = os.path.abspath(cfg["model_path"])
    sh("docker", "rm", "-f", "bz-llm", check=False)
    sh("docker", "run", "-d", "--name", "bz-llm", "--network", net, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
       "--read-only", "--user", "65534:65534", "--tmpfs", "/tmp", "--memory", "2g", "--pids-limit", "256",
       "--cgroup-parent", isolation.cgroup_parent("model")[0], "-v", f"{os.path.dirname(m)}:/models:ro", LLM_IMG,
       "-m", f"/models/{os.path.basename(m)}", "--host", "0.0.0.0", "--port", "8080", "-np", "2", "-c", "4096", "-t", str(cfg["llm_threads"]))
    for _ in range(120):
        if '"ok"' in sh("docker", "run", "--rm", "--network", net, cfg["image"], "python3", "-c",
                        "import urllib.request;print(urllib.request.urlopen('http://bz-llm:8080/health',timeout=2).read().decode())", check=False):
            return "http://bz-llm:8080"
        time.sleep(1)
    raise RuntimeError("llama.cpp server did not become healthy: " + sh("docker", "logs", "bz-llm", check=False)[-2000:])


def probe(cfg, net, url, salted, trials, seed):
    rnd = random.Random(seed)
    spec = {"candidates": [candidates(rnd) for _ in range(trials)], "header": HEADER, "body": BODY, "seed": seed, "salted": salted,
            "salts": {"A": f"[tenant-salt:{secrets.token_hex(8)}] ", "B": f"[tenant-salt:{secrets.token_hex(8)}] "},
            "slots": {"A": 0, "B": 1, "shared": 0}}
    out = sh("docker", "run", "--rm", "--network", net, "--cap-drop", "ALL", "--read-only", "--user", "65534:65534",
             "-v", f"{CODE}:/app:ro", "-e", f"LLM_URL={url}", "-e", "PROBE=" + base64.b64encode(json.dumps(spec).encode()).decode(),
             cfg["image"], "python3", "/app/agent.py", "cacheprobe")
    rows = json.loads(out)
    k, n, chance = sum(r["guess"] == r["secret"] for r in rows), len(rows), 1 / K
    # ground truth from the server: did B's probe of the true secret reuse A's cached prefix (almost nothing re-evaluated)?
    hits = sum(r["prompt_n"][str(r["secret"])] is not None and r["prompt_n"][str(r["secret"])] < 10 for r in rows)
    return {"trials": n, "correct": k, "accuracy": k / n, "chance": chance, "p_value_vs_chance": p_at_least(k, n, chance),
            "cross_tenant_cache_hits": hits, "rows": rows}


def run(cfg, trials=None, out=None):
    net, trials = cfg["zones"]["model"] + "_cache", trials or cfg["cache_trials"]
    sh("docker", "network", "rm", net, check=False); sh("docker", "network", "create", "--internal", net)
    try:
        url = start_server(cfg, net)
        res = {"environment": f"llama.cpp server (CPU, {cfg['llm_threads']} threads) in {isolation.docker_mode()['context']}, probe in the model network (strongest-case attacker, no broker jitter)",
               "engine": "llama.cpp", "image": LLM_IMG, "model": os.path.basename(cfg["model_path"]), "model_sha256": model_sha256(cfg["model_path"]),
               "candidates": K,
               "shared": probe(cfg, net, url, False, trials, 1), "salted": probe(cfg, net, url, True, trials, 2)}
    finally:
        sh("docker", "rm", "-f", "bz-llm", check=False); sh("docker", "network", "rm", net, check=False)
    res["pass"] = passed(res["salted"])
    if out:
        os.makedirs(out, exist_ok=True)
        json.dump(res, open(f"{out}/cachetest.json", "w"), indent=2)
    return res
