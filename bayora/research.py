"""Research evidence: fetch the sources behind Bayora's claims with TinyFish, fingerprint each page, and seal the
list in a Merkle log, so the research has a receipt like everything else Bayora produces.
`collect` and `watch` call TinyFish and need TINYFISH_API_KEY (agent.tinyfish.ai/api-keys); `seal` and `verify` run offline."""
import hashlib, json, os, time, urllib.error, urllib.request
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .ledger import MerkleLog, leaf_hash, checkpoint_body
from .witness import load_key, pub_hex

FETCH_URL = "https://api.fetch.tinyfish.ai"
MONITOR_URL = "https://agent.tinyfish.ai/v1/monitors"
ORIGIN = "bayora.dev/research"
READ = ("full", "section", "abstract", "snippet", "searched")
FIELDS = ("id", "title", "url", "kind", "read", "supports")


def canon(d): return json.dumps(d, sort_keys=True, separators=(",", ":"))


def utc(t): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def load_manifest(path):
    with open(path) as f: m = yaml.safe_load(f) or {}
    claims, sources = m.get("claims") or {}, m.get("sources") or []
    if len({s.get("id") for s in sources}) != len(sources): raise ValueError("duplicate source id")
    for s in sources:
        if missing := [k for k in FIELDS if k not in s]: raise ValueError(f"source {s.get('id')}: missing {', '.join(missing)}")
        if not str(s["url"]).startswith(("http://", "https://")): raise ValueError(f"{s['id']}: url must be http(s)")
        if s["read"] not in READ: raise ValueError(f"{s['id']}: read must be one of {', '.join(READ)}")
        if unknown := [c for c in s["supports"] if c not in claims]: raise ValueError(f"{s['id']} supports unknown claim {unknown[0]}")
    return {"claims": claims, "sources": sources}


def _call(url, key, body=None, timeout=120):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method="POST",
                                 headers={"X-API-Key": key, "Content-Type": "application/json", "User-Agent": "bayora-research"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"TinyFish answered HTTP {e.code} for {url}") from None   # never echo the key


def collect(manifest, out, key, call=_call, now=time.time):
    """Fetch every source (10 per request), keep each page's text in <out>/cache, write <out>/evidence.jsonl."""
    os.makedirs(os.path.join(out, "cache"), exist_ok=True)
    src, got, errs = manifest["sources"], {}, {}
    for i in range(0, len(src), 10):
        r = call(FETCH_URL, key, {"urls": [s["url"] for s in src[i:i + 10]], "format": "markdown",
                                  "purpose": "Collect the primary sources behind Bayora's research claims, to fingerprint each page"})
        for x in r.get("results") or []: got[x.get("url")] = x
        for e in r.get("errors") or []: errs[e.get("url")] = e.get("error") or e.get("code") or e.get("message") or "error"
    ts, rows = utc(now()), []
    for s in src:
        x = got.get(s["url"]) or {}
        row = {"id": s["id"], "url": s["url"], "final_url": x.get("final_url"), "title": x.get("title"), "fetched_at": ts, "via": "tinyfish-fetch-api"}
        if x.get("text") is not None:
            data = x["text"].encode()
            with open(os.path.join(out, "cache", s["id"] + ".md"), "wb") as f: f.write(data)
            row.update(status="ok", sha256=hashlib.sha256(data).hexdigest(), chars=len(x["text"]))
        else:
            row.update(status="error", error=str(errs.get(s["url"], "no result returned")))
        rows.append(row)
    with open(os.path.join(out, "evidence.jsonl"), "w") as f: f.writelines(canon(r) + "\n" for r in rows)
    return rows


def _lines(path):
    with open(path, "rb") as f: return [l for l in f.read().split(b"\n") if l]


def _root(lines):
    m = MerkleLog(); m.leaves = [leaf_hash(l) for l in lines]
    return m.root()


def seal(out, key_path, now=time.time):
    """Sign a checkpoint over the evidence lines: <out>/seal.json."""
    lines = _lines(os.path.join(out, "evidence.jsonl")); root, key = _root(lines), load_key(key_path)
    s = {"origin": ORIGIN, "size": len(lines), "root": root.hex(), "operator_pubkey": pub_hex(key), "sealed_at": utc(now()),
         "sig": key.sign(checkpoint_body(ORIGIN, len(lines), root)).hex()}
    with open(os.path.join(out, "seal.json"), "w") as f: json.dump(s, f, indent=2, sort_keys=True)
    return s


def verify_pack(out, trust=None):
    """(ok, message). Recomputes the root, checks the signature, and re-hashes every cached page."""
    try:
        with open(os.path.join(out, "seal.json")) as f: s = json.load(f)
        lines = _lines(os.path.join(out, "evidence.jsonl"))
    except OSError as e:
        return False, f"cannot read the evidence pack: {e.filename or e}"
    if len(lines) != s["size"]: return False, f"evidence has {len(lines)} lines, the seal says {s['size']}"
    root = _root(lines)
    if root.hex() != s["root"]: return False, "evidence root does not match the seal (a line was edited, added or removed)"
    pub = trust or s["operator_pubkey"]
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(s["sig"]), checkpoint_body(s["origin"], s["size"], root))
    except (InvalidSignature, ValueError): return False, "seal signature does not verify" + (" with the trusted key" if trust else "")
    checked = bad = 0
    for r in map(json.loads, lines):
        p = os.path.join(out, "cache", r["id"] + ".md")
        if r.get("status") == "ok" and os.path.exists(p):
            with open(p, "rb") as f: checked, bad = checked + 1, bad + (hashlib.sha256(f.read()).hexdigest() != r["sha256"])
    if bad: return False, f"{bad} cached page(s) no longer match their fingerprints"
    return True, (f"OK: {s['size']} sources, root {s['root'][:16]}..., signed by {pub[:12]}...; {checked} cached pages match their fingerprints. "
                  f"Key {'pinned by --trust' if trust else 'taken from the seal itself (pass --trust to pin it)'}.")


def watch(state_path, out, key, call=_call, now=time.time):
    """Run each TinyFish Monitor now; a page whose text changed since the last check is appended to <out>/drift.jsonl."""
    with open(state_path) as f: st = json.load(f)
    ts, drift = utc(now()), []
    for m in st["monitors"]:
        run = (call(f"{MONITOR_URL}/{m['id']}/runs", key) or {}).get("run") or {}
        text = next((r["text"] for r in run.get("results") or [] if r.get("text") is not None), None)
        if text is None: continue
        h = hashlib.sha256(text.encode()).hexdigest()
        if m.get("last_sha256") and m["last_sha256"] != h: drift.append({"monitor": m["name"], "url": m["url"], "was": m["last_sha256"], "now": h, "at": ts})
        m["last_sha256"], m["last_checked"] = h, ts
    with open(state_path, "w") as f: json.dump(st, f, indent=2)
    if drift:
        with open(os.path.join(out, "drift.jsonl"), "a") as f: f.writelines(canon(d) + "\n" for d in drift)
    return drift


def key_from_env():
    key = os.environ.get("TINYFISH_API_KEY")
    if not key: raise SystemExit("set TINYFISH_API_KEY first (create one at https://agent.tinyfish.ai/api-keys)")
    return key
