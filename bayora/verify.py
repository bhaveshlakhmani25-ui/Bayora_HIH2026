"""Checks a receipt against a log file: the entries must hash to the receipt's Merkle root,
and the operator's Ed25519 signature must cover that checkpoint."""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .ledger import MerkleLog, leaf_hash, checkpoint_body


def verify(receipt_path, log_path):
    """Returns (ok, message)."""
    with open(receipt_path) as f: rc = json.load(f)
    with open(log_path, "rb") as f: entries = f.read().splitlines()
    if len(entries) != rc["log_size"]:
        return False, f"log has {len(entries)} entries, receipt says {rc['log_size']}"
    log = MerkleLog(); log.leaves = [leaf_hash(e) for e in entries]
    root = log.root()
    if root.hex() != rc["log_root"]:
        return False, "log root does not match receipt (an entry was edited, added or removed)"
    body = checkpoint_body(rc.get("origin", "bayora.poc/log"), rc["log_size"], root)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(rc["operator_pubkey_raw"])).verify(bytes.fromhex(rc["operator_sig"]), body)
    except InvalidSignature:
        return False, "operator signature does not cover this checkpoint"
    # shortcut: the operator key comes from the receipt itself and witness cosignatures are not in it yet; build plan step 5 fixes both
    return True, (f"OK: {rc['log_size']} entries match root {rc['log_root'][:16]}... signed by the operator key in the receipt. "
                  f"Not checked: witness cosignatures, and whether that operator key is trusted.")
