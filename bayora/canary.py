"""Key-derived, attributable canaries and a leak scanner.
Canary = 'BYR' + base32(HMAC-SHA256(authority_key, run|tenant|slot))[:24].
Only the audit service holds the key, so tenants cannot mint valid canaries (no forged alarms),
and every hit maps back to (run, tenant, slot)."""
import hmac, hashlib, base64, re, os, binascii

TOKEN_RE = re.compile(r"BYR[A-Z2-7]{24}")


class CanaryAuthority:
    def __init__(self, run_id, key=None):
        self.run_id = run_id
        self.key = key or os.urandom(32)
        self.registry = {}

    def mint(self, tenant, slot):
        mac = hmac.new(self.key, f"{self.run_id}|{tenant}|{slot}".encode(), hashlib.sha256).digest()
        tok = "BYR" + base64.b32encode(mac).decode()[:24]
        self.registry[tok] = {"run": self.run_id, "tenant": tenant, "slot": slot}
        return tok

    def attribute(self, tok):
        return self.registry.get(tok)


def _decoded_views(text):
    """Scanner v2 normalisation: also look inside base64 / hex blobs, ignore case,
    and rejoin tokens split by whitespace or line breaks."""
    views = [text, text.upper(), re.sub(r"[\s\-_|]+", "", text).upper()]
    for blob in re.findall(r"[A-Za-z0-9+/=]{24,}", text):
        for dec in (_b64(blob), _hex(blob)):
            if dec: views.append(dec.upper())
    return views


def _b64(s):
    try: return base64.b64decode(s + "=" * (-len(s) % 4), validate=True).decode("utf-8", "ignore")
    except (binascii.Error, ValueError): return None


def _hex(s):
    try: return bytes.fromhex(s).decode("utf-8", "ignore")
    except ValueError: return None


def scan(text, authority, mode="v2"):
    """Return attributed hits. v1 = exact token match only; v2 = normalised + decoded views."""
    views = [text] if mode == "v1" else _decoded_views(text)
    hits = {}
    for v in views:
        for tok in TOKEN_RE.findall(v):
            a = authority.attribute(tok)
            if a: hits[tok] = a
    return hits
