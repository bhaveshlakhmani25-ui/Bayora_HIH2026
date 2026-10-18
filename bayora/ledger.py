"""Append-only Merkle log following IETF RFC 9162 (Certificate Transparency v2.0) hashing,
with Ed25519-signed checkpoints and an independent witness that cosigns only consistent views."""
import hashlib, json, base64, time
from functools import lru_cache
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature


def H(b): return hashlib.sha256(b).digest()
def leaf_hash(data: bytes): return H(b"\x00" + data)
def node_hash(l, r): return H(b"\x01" + l + r)


def _k(n):  # largest power of two strictly smaller than n
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleLog:
    def __init__(self):
        self.entries = []      # raw bytes
        self.leaves = []       # leaf hashes
        self._memo = {}

    def append(self, event: dict) -> int:
        data = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        self.entries.append(data)
        self.leaves.append(leaf_hash(data))
        return len(self.leaves) - 1

    def mth(self, lo, hi):
        n = hi - lo
        if n == 0: return H(b"")
        if n == 1: return self.leaves[lo]
        key = (lo, hi)
        if key in self._memo: return self._memo[key]
        k = _k(n)
        r = node_hash(self.mth(lo, lo + k), self.mth(lo + k, hi))
        # memoise only complete power-of-two subtrees (they never change as the log grows)
        if n & (n - 1) == 0: self._memo[key] = r
        return r

    def root(self, size=None):
        return self.mth(0, len(self.leaves) if size is None else size)

    def inclusion_proof(self, m, size=None):
        n = len(self.leaves) if size is None else size
        def path(m, lo, hi):
            n = hi - lo
            if n <= 1: return []
            k = _k(n)
            if m < k: return path(m, lo, lo + k) + [self.mth(lo + k, hi)]
            return path(m - k, lo + k, hi) + [self.mth(lo, lo + k)]
        return path(m, 0, n)

    def consistency_proof(self, m, n=None):
        n = len(self.leaves) if n is None else n
        def sub(m, lo, hi, b):
            n = hi - lo
            if m == n: return [] if b else [self.mth(lo, hi)]
            k = _k(n)
            if m <= k: return sub(m, lo, lo + k, b) + [self.mth(lo + k, hi)]
            return sub(m - k, lo + k, hi, False) + [self.mth(lo, lo + k)]
        return sub(m, 0, n, True)


def verify_inclusion(leaf_index, tree_size, lh, path, root):
    if leaf_index >= tree_size: return False
    fn, sn, r = leaf_index, tree_size - 1, lh
    for p in path:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not (fn & 1 or fn == 0):
                    fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first, second, first_hash, second_hash, path):
    if first == second: return first_hash == second_hash and not path
    if first == 0: return True
    if first & (first - 1) == 0: path = [first_hash] + list(path)
    if not path: return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr); sr = node_hash(c, sr)
            if not fn & 1:
                while not (fn & 1 or fn == 0):
                    fn >>= 1; sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return fr == first_hash and sr == second_hash and sn == 0


def checkpoint_body(origin, size, root):
    return f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n".encode()


class LogOperator:
    def __init__(self, origin="bayora.poc/log"):
        self.origin, self.log = origin, MerkleLog()
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key()

    def checkpoint(self):
        size = len(self.log.leaves); root = self.log.root()
        body = checkpoint_body(self.origin, size, root)
        return {"size": size, "root": root, "body": body, "sig": self.key.sign(body)}


class Witness:
    """Independent cosigner: verifies the operator signature and consistency with the
    last checkpoint it saw; refuses (and flags) a split view."""
    def __init__(self, name, operator_pub):
        self.name, self.op_pub = name, operator_pub
        self.key = Ed25519PrivateKey.generate(); self.pub = self.key.public_key()
        self.last = None; self.alarms = []

    def cosign(self, cp, proof):
        try:
            self.op_pub.verify(cp["sig"], cp["body"])
        except InvalidSignature:
            self.alarms.append("bad operator signature"); return None
        if self.last:
            ls, lr = self.last
            if cp["size"] == ls and cp["root"] != lr:
                self.alarms.append(f"split view at size {ls}"); return None
            if cp["size"] < ls or not verify_consistency(ls, cp["size"], lr, cp["root"], proof):
                self.alarms.append("inconsistent checkpoint"); return None
        self.last = (cp["size"], cp["root"])
        return self.key.sign(b"cosig\n" + cp["body"])
