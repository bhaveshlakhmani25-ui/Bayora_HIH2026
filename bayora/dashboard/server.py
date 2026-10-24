"""Demo dashboard: serves index.html and read-only JSON views of one results directory.
GET /api/state, GET /api/events?since=N (tails log.jsonl), POST /api/verify (runs bayora.verify)."""
import base64, glob, json, os, socket, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from ..receipt import read_checkpoint
from ..verify import verify

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
FONTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")


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
    return {"dir": os.path.basename(os.path.abspath(d)), "results": _json(f"{d}/results.json"), "receipt": rc, "statement": statement,
            "checkpoints": cps, "cachetest": ct}


def events(d, since):
    try:
        with open(f"{d}/log.jsonl", "rb") as f: lines = f.read().splitlines()
    except OSError:
        return {"total": 0, "events": []}
    return {"total": len(lines), "events": [dict(json.loads(l), index=i) for i, l in enumerate(lines) if i >= since]}


def tampered_copy(log_path, index, tmpdir):
    """Writes a copy of the log with event `index` edited the way a dishonest operator might; the real log is never touched."""
    with open(log_path, "rb") as f: lines = f.read().splitlines()
    if not 0 <= index < len(lines): raise ValueError(f"event index {index} out of range (0..{len(lines) - 1})")
    old = lines[index]
    for a, b in ((b"BLOCKED", b"CONNECTED"), (b"true", b"false"), (b"false", b"true")):
        if a in old: lines[index], change = old.replace(a, b, 1), f"changed {a.decode()} to {b.decode()}"; break
    else:
        lines[index], change = old + b" ", "added one space"
    path = os.path.join(tmpdir, "log.jsonl")
    with open(path, "wb") as f: f.write(b"".join(l + b"\n" for l in lines))
    return path, f"event #{index}: {change}"


def make_server(results_dir, port, trust=None):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            b = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/": return self._send(200, open(HTML, "rb").read(), "text/html; charset=utf-8")
            if u.path.startswith("/fonts/"):
                name = u.path[len("/fonts/"):]
                # only files that ship in the fonts folder; no paths, so nothing outside it can be read
                if name.endswith(".woff2") and name in os.listdir(FONTS):
                    with open(os.path.join(FONTS, name), "rb") as f: return self._send(200, f.read(), "font/woff2")
                return self._send(404, {"error": "not found"})
            if u.path == "/api/state": return self._send(200, state(results_dir))
            if u.path == "/api/events":
                try: since = int(parse_qs(u.query).get("since", ["0"])[0])
                except ValueError: since = 0
                return self._send(200, events(results_dir, since))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if urlparse(self.path).path != "/api/verify": return self._send(404, {"error": "not found"})
            cps = f"{results_dir}/checkpoints" if os.path.isdir(f"{results_dir}/checkpoints") else None
            try:
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n) or b"{}") if n else {}
                with tempfile.TemporaryDirectory() as tmp:
                    log, change = f"{results_dir}/log.jsonl", None
                    if req.get("tamper") is not None: log, change = tampered_copy(log, int(req["tamper"]), tmp)
                    rv = f"{results_dir}/reveal.json" if os.path.exists(f"{results_dir}/reveal.json") else None
                    ok, msg = verify(f"{results_dir}/receipt.json", log, trust, cps, None, rv)
            except (OSError, ValueError, KeyError, TypeError) as e:
                ok, msg, change = False, f"could not verify: {e}", None
            # without pinned keys a self-made receipt also verifies, so the page must not show it as fully trusted
            self._send(200, {"ok": ok, "pinned": bool(trust), "message": msg, "tampered": change, "trust": trust or "keys taken from the receipt"})

        def log_message(self, *a): pass

    return ThreadingHTTPServer(("127.0.0.1", port), H)


class _V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def listen_v6(httpd):
    """Also serve on IPv6 loopback: browsers resolve localhost to ::1 first, and Chrome may not fall back to IPv4."""
    try:
        v6 = _V6Server(("::1", httpd.server_address[1]), httpd.RequestHandlerClass)
    except OSError:
        return None                                  # no IPv6 loopback on this host; 127.0.0.1 still works
    threading.Thread(target=v6.serve_forever, daemon=True).start()
    return v6


def serve(results_dir, port, trust=None):
    if not os.path.exists(f"{results_dir}/results.json"):
        print(f"warning: no results.json in {os.path.abspath(results_dir)}; run from the repo folder or pass --results", flush=True)
    httpd = make_server(results_dir, port, trust)
    listen_v6(httpd)
    print(f"Bayora dashboard for {os.path.abspath(results_dir)}: http://localhost:{httpd.server_address[1]}  (Ctrl-C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("dashboard stopped")
