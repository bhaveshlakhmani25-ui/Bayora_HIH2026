"""Standalone verifier: needs only the receipt, the log file and (ideally) pinned public keys; it never
contacts the log operator. Checks the DSSE signature, that the log hashes to the signed root, a quorum
of trusted witness cosignatures, and that every published checkpoint matches the log at its size."""
import base64, glob, json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .ledger import MerkleLog, leaf_hash, checkpoint_body
from .receipt import pae, read_checkpoint, PREDICATE_TYPE
from .commit import verify_reveal


def _ok(pub_hex, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, msg); return True
    except (InvalidSignature, ValueError):
        return False


def _log(log_path):
    with open(log_path, "rb") as f: entries = f.read().splitlines()
    m = MerkleLog(); m.leaves = [leaf_hash(e) for e in entries]
    return m


def checkpoint_files(d):
    """Published checkpoints are files named by their tree size; anything else in the folder is ignored."""
    return sorted((p for p in glob.glob(os.path.join(d, "*")) if os.path.basename(p).isdigit()), key=lambda p: int(os.path.basename(p))) if d else []


def verify(receipt_path, log_path, trust_path=None, checkpoints_dir=None, quorum=None, reveal_path=None):
    """Returns (ok, message)."""
    with open(receipt_path) as f: rc = json.load(f)
    if "payloadType" not in rc: return _verify_v0(rc, log_path)
    trust = json.load(open(trust_path)) if trust_path else None
    body = base64.b64decode(rc["payload"])
    st = json.loads(body); p = st["predicate"]
    if st.get("predicateType") != PREDICATE_TYPE: return False, f"unknown predicateType {st.get('predicateType')}"
    op_pub = trust["operator"] if trust else p["operator_pubkey"]
    if not any(_ok(op_pub, base64.b64decode(s["sig"]), pae(rc["payloadType"], body)) for s in rc["signatures"]):
        return False, "DSSE signature does not verify with the operator key"
    log = _log(log_path)
    if len(log.leaves) != p["log_size"]: return False, f"log has {len(log.leaves)} entries, receipt says {p['log_size']}"
    root = log.root()
    if root.hex() != p["log_root"] or st["subject"][0]["digest"]["sha256"] != p["log_root"]:
        return False, "log root does not match receipt (an entry was edited, added or removed)"
    body_cp = checkpoint_body(p["origin"], p["log_size"], root)
    if not _ok(op_pub, bytes.fromhex(p["operator_sig"]), body_cp): return False, "operator signature does not cover the final checkpoint"
    keys = trust["witnesses"] if trust else {w["name"]: w["pubkey"] for w in p["witnesses"]}
    need = quorum or (trust or {}).get("quorum") or 2
    # a set: a witness listed twice by the operator still counts once towards the quorum
    good = sorted({w["name"] for w in p["witnesses"] if w["cosig"] and w["name"] in keys and _ok(keys[w["name"]], bytes.fromhex(w["cosig"]), b"cosig\n" + body_cp)})
    if len(good) < need: return False, f"witness quorum not met: {len(good)}/{need} valid cosignatures ({', '.join(good) or 'none'})"
    n_cp = 0
    for path in checkpoint_files(checkpoints_dir):
        cbody, sigs = read_checkpoint(path)
        origin, size, root_b64 = cbody.decode().splitlines()
        size = int(size)
        if origin != p["origin"] or size > len(log.leaves) or base64.b64decode(root_b64) != log.root(size):
            return False, f"published checkpoint {size} is inconsistent with the log (split view or rewritten history)"
        if not any(_ok(op_pub, s, cbody) for s in sigs.values()): return False, f"published checkpoint {size} lacks a valid operator signature"
        n_cp += 1
    revealed = ""
    if reveal_path:
        # blind-test check: what each team revealed after the run must hash to what it committed before
        with open(reveal_path) as f: rv = json.load(f)
        if missing := {"red", "blue"} - set(p["commitments"]):
            return False, f"receipt has no commitment for the {' and '.join(sorted(missing))} team, so the blind test cannot be checked"
        for team, c in p["commitments"].items():
            if team not in rv or not verify_reveal(c, bytes.fromhex(rv[team]["nonce"]), base64.b64decode(rv[team]["content"])):
                return False, f"{team} team's revealed content does not match its commitment (changed after the run)"
        revealed = f" Reveal matches the {len(p['commitments'])} commitments."
    src = "pinned in trust file" if trust else "taken from the receipt itself (pass --trust to pin keys)"
    return True, (f"OK: {p['log_size']} entries match root {p['log_root'][:16]}...; DSSE and checkpoint signed by the operator; "
                  f"{len(good)} witness cosignatures ({', '.join(good)}) meet quorum {need}; {n_cp} published checkpoints consistent with the log. "
                  f"Keys {src}.{revealed}")


def _verify_v0(rc, log_path):
    """PoC receipt format (results_final/): root + operator signature only."""
    log = _log(log_path)
    if len(log.leaves) != rc["log_size"]: return False, f"log has {len(log.leaves)} entries, receipt says {rc['log_size']}"
    root = log.root()
    if root.hex() != rc["log_root"]: return False, "log root does not match receipt (an entry was edited, added or removed)"
    if not _ok(rc["operator_pubkey_raw"], bytes.fromhex(rc["operator_sig"]), checkpoint_body(rc.get("origin", "bayora.poc/log"), rc["log_size"], root)):
        return False, "operator signature does not cover this checkpoint"
    return True, (f"OK: {rc['log_size']} entries match root {rc['log_root'][:16]}... signed by the operator key in the receipt. "
                  f"Not checked (old receipt format): witness cosignatures, and whether that operator key is trusted.")
