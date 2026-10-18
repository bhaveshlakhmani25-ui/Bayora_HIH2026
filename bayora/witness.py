"""Witness as a separate process: an HTTP service with its own persistent Ed25519 key that cosigns
an operator's checkpoints only if they are consistent with everything it saw before for that origin.
POST /cosign {origin, size, root, body, sig, proof} -> 200 {name, cosig} | 409 {alarm}.  GET /pubkey."""
import base64, json, os, threading, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .ledger import Witness


def load_key(path):
    """Ed25519 private key stored as 32 raw bytes; created on first use."""
    if os.path.exists(path):
        return Ed25519PrivateKey.from_private_bytes(open(path, "rb").read())
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    k = Ed25519PrivateKey.generate()
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f: f.write(k.private_bytes_raw())
    return k


def pub_hex(key): return key.public_key().public_bytes_raw().hex()


class WitnessService:
    """One ledger.Witness per origin, sharing this witness's persistent key; last-seen state survives restarts."""

    def __init__(self, name, state_dir, operator_pub_hex):
        self.name, self.dir = name, state_dir
        self.key = load_key(os.path.join(state_dir, "key"))
        self.op_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(operator_pub_hex))
        self.state_path = os.path.join(state_dir, "state.json")
        self.state = json.load(open(self.state_path)) if os.path.exists(self.state_path) else {}
        self.lock = threading.Lock()

    def cosign(self, req):
        with self.lock:
            w = Witness(self.name, self.op_pub); w.key, w.pub = self.key, self.key.public_key()
            if req["origin"] in self.state:
                s = self.state[req["origin"]]; w.last = (s["size"], bytes.fromhex(s["root"]))
            cp = {"size": req["size"], "root": bytes.fromhex(req["root"]), "body": base64.b64decode(req["body"]), "sig": bytes.fromhex(req["sig"])}
            if cp["body"] != f"{req['origin']}\n{req['size']}\n{base64.b64encode(cp['root']).decode()}\n".encode():
                return None, "checkpoint body does not match origin/size/root"
            cosig = w.cosign(cp, [bytes.fromhex(p) for p in req["proof"]])
            if cosig is None: return None, w.alarms[-1]
            self.state[req["origin"]] = {"size": cp["size"], "root": req["root"]}
            tmp = self.state_path + ".tmp"
            json.dump(self.state, open(tmp, "w")); os.replace(tmp, self.state_path)
            return cosig, None


def make_server(name, port, state_dir, operator_pub_hex):
    svc = WitnessService(name, state_dir, operator_pub_hex)

    class H(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            if self.path == "/pubkey": self._send(200, {"name": name, "pubkey": pub_hex(svc.key)})
            else: self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/cosign": return self._send(404, {"error": "not found"})
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                cosig, alarm = svc.cosign(req)
            except (KeyError, ValueError, TypeError) as e:
                return self._send(400, {"error": f"bad request: {e}"})
            if alarm: self._send(409, {"name": name, "alarm": alarm})
            else: self._send(200, {"name": name, "cosig": cosig.hex()})

        def log_message(self, *a): pass

    httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
    httpd.pub_hex = pub_hex(svc.key)
    return httpd


def serve(name, port, state_dir, operator_pub_hex):
    httpd = make_server(name, port, state_dir, operator_pub_hex)
    print(f"LISTENING {httpd.server_address[1]} {httpd.pub_hex}", flush=True)
    httpd.serve_forever()


class RemoteWitness:
    """Client for a witness service; same cosign(cp, proof) -> cosig | None contract as ledger.Witness."""

    def __init__(self, url, origin):
        self.url, self.origin, self.alarms = url.rstrip("/"), origin, []
        info = json.loads(urllib.request.urlopen(self.url + "/pubkey", timeout=10).read())
        self.name, self.pub_hex = info["name"], info["pubkey"]

    def cosign(self, cp, proof):
        req = {"origin": self.origin, "size": cp["size"], "root": cp["root"].hex(), "body": base64.b64encode(cp["body"]).decode(),
               "sig": cp["sig"].hex(), "proof": [p.hex() for p in proof]}
        try:
            r = urllib.request.urlopen(urllib.request.Request(self.url + "/cosign", json.dumps(req).encode(), {"Content-Type": "application/json"}), timeout=10)
            return bytes.fromhex(json.loads(r.read())["cosig"])
        except urllib.error.HTTPError as e:
            if e.code != 409: raise
            self.alarms.append(json.loads(e.read())["alarm"]); return None
