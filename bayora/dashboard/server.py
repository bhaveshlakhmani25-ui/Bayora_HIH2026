"""Demo dashboard: serves index.html and read-only JSON views of one results directory.
GET /api/state, GET /api/events?since=N (tails log.jsonl), POST /api/verify (runs bayora.verify)."""
import base64, glob, json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from ..receipt import read_checkpoint
from ..verify import verify

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")


def _json(path):
    try:
        with open(path) as f: return json.load(f)
    except (OSError, ValueError):
        return None


def state(d):
    rc = _json(f"{d}/receipt.json")
    statement = json.loads(base64.b64decode(rc["payload"])) if rc and "payload" in rc else None
    cps = []
    for p in sorted(glob.glob(f"{d}/checkpoints/*"), key=lambda x: int(os.path.basename(x))):
        body, sigs = read_checkpoint(p)
        origin, size, root = body.decode().splitlines()
        cps.append({"size": int(size), "root": base64.b64decode(root).hex(), "signers": list(sigs)})
    ct = _json(f"{d}/cachetest.json")
    if ct:
        for c in ("shared", "salted"): ct[c].pop("rows", None)
    return {"dir": os.path.abspath(d), "results": _json(f"{d}/results.json"), "receipt": rc, "statement": statement,
            "checkpoints": cps, "cachetest": ct}


def events(d, since):
    try:
        with open(f"{d}/log.jsonl", "rb") as f: lines = f.read().splitlines()
    except OSError:
        return {"total": 0, "events": []}
    return {"total": len(lines), "events": [dict(json.loads(l), index=i) for i, l in enumerate(lines) if i >= since]}


def make_server(results_dir, port, trust=None):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            b = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/": return self._send(200, open(HTML, "rb").read(), "text/html; charset=utf-8")
            if u.path == "/api/state": return self._send(200, state(results_dir))
            if u.path == "/api/events":
                try: since = int(parse_qs(u.query).get("since", ["0"])[0])
                except ValueError: since = 0
                return self._send(200, events(results_dir, since))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if urlparse(self.path).path != "/api/verify": return self._send(404, {"error": "not found"})
            try:
                ok, msg = verify(f"{results_dir}/receipt.json", f"{results_dir}/log.jsonl", trust,
                                 f"{results_dir}/checkpoints" if os.path.isdir(f"{results_dir}/checkpoints") else None)
            except (OSError, ValueError, KeyError) as e:
                ok, msg = False, f"could not verify: {e}"
            self._send(200, {"ok": ok, "message": msg, "trust": trust or "keys taken from the receipt"})

        def log_message(self, *a): pass

    return ThreadingHTTPServer(("127.0.0.1", port), H)


def serve(results_dir, port, trust=None):
    httpd = make_server(results_dir, port, trust)
    print(f"Bayora dashboard for {os.path.abspath(results_dir)}: http://127.0.0.1:{httpd.server_address[1]}", flush=True)
    httpd.serve_forever()
