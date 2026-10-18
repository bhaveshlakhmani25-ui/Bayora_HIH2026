"""Run receipt: an in-toto Statement v1 in a DSSE envelope signed by the log operator, plus published
checkpoints in signed-note style (body, then one '— <name> <base64 sig>' line per signer).
The cosignature message is b'cosig\\n' + checkpoint body (ledger.Witness): signed-note style, not byte-compatible with C2SP tlog-cosignature."""
import base64, json, os

PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://bayora.dev/receipt/v1"


def pae(payload_type, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding: what the envelope signature covers."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def write_checkpoint(out_dir, cp, op_name, op_sig, cosigs):
    """cosigs: [(name, sig_bytes)]."""
    os.makedirs(f"{out_dir}/checkpoints", exist_ok=True)
    lines = [f"— {op_name} {base64.b64encode(op_sig).decode()}"] + [f"— {n} {base64.b64encode(s).decode()}" for n, s in cosigs]
    with open(f"{out_dir}/checkpoints/{cp['size']}", "w") as f: f.write(cp["body"].decode() + "\n" + "\n".join(lines) + "\n")


def read_checkpoint(path):
    """Returns (body bytes, {signer name: sig bytes})."""
    text = open(path).read()
    body, _, sigs = text.partition("\n\n")
    out = {}
    for line in sigs.splitlines():
        if line.startswith("— "):
            name, b64 = line[2:].rsplit(" ", 1); out[name] = base64.b64decode(b64)
    return (body + "\n").encode(), out


def build_receipt(op, final_cp, witnesses, cosigs, run_id, commitments, drills, model_sha256=None, checkpoints=()):
    """witnesses: objects with .name/.pub_hex; cosigs: {name: cosig bytes} on final_cp."""
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": f"bayora-log:{op.origin}", "digest": {"sha256": final_cp["root"].hex()}}],   # RFC 9162 SHA-256 Merkle root
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "run_id": run_id, "origin": op.origin, "log_size": final_cp["size"], "log_root": final_cp["root"].hex(),
            "operator_pubkey": op.pub.public_bytes_raw().hex(), "operator_sig": final_cp["sig"].hex(),
            "commitments": commitments, "model_sha256": model_sha256, "drills": drills,
            "checkpoints": [{"size": c["size"], "root": c["root"].hex()} for c in checkpoints],
            "witnesses": [{"name": w.name, "pubkey": w.pub_hex, "cosig": cosigs[w.name].hex() if w.name in cosigs else None} for w in witnesses],
        },
    }
    body = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(body).decode(),
            "signatures": [{"keyid": op.pub.public_bytes_raw().hex()[:16], "sig": base64.b64encode(op.key.sign(pae(PAYLOAD_TYPE, body))).decode()}]}
