import json, threading
from bayora.cli import main
from bayora.ledger import LogOperator, MerkleLog, leaf_hash, checkpoint_body
from bayora.receipt import build_receipt, write_checkpoint
from bayora.witness import make_server, load_key, pub_hex, RemoteWitness


def setup_run(tmp_path, tweak=lambda c: c):
    op = LogOperator("bayora.dev/run/test", load_key(str(tmp_path / "operator.key")))
    ws = []
    for name in ("witness-A", "witness-B"):
        httpd = make_server(name, 0, str(tmp_path / name), pub_hex(op.key))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        ws.append(RemoteWitness(f"http://127.0.0.1:{httpd.server_address[1]}", op.origin))
    out, cps = tmp_path / "out", []
    for i in range(5): op.log.append({"i": i})
    for extra, prev in ((0, 0), (3, 5)):
        for i in range(extra): op.log.append({"j": i})
        cp = op.checkpoint(); proof = op.log.consistency_proof(prev) if prev else []
        cp["cosigs"] = {w.name: s for w in ws if (s := w.cosign(cp, proof))}
        write_checkpoint(str(out), cp, "operator", cp["sig"], list(cp["cosigs"].items())); cps.append(cp)
    rc = build_receipt(op, cp, ws, tweak(dict(cp["cosigs"])), "test", {"red": "c"}, {}, None, cps)
    (out / "receipt.json").write_text(json.dumps(rc))
    (out / "log.jsonl").write_bytes(b"".join(e + b"\n" for e in op.log.entries))
    (out / "keys.json").write_text(json.dumps({"operator": pub_hex(op.key), "witnesses": {w.name: w.pub_hex for w in ws}, "quorum": 2}))
    return op, ws, cp, out


def v(out, *extra):
    return main(["verify", str(out / "receipt.json"), str(out / "log.jsonl"), "--trust", str(out / "keys.json"), "--checkpoints", str(out / "checkpoints"), *extra])


def test_good_run_verifies_with_pinned_keys_and_checkpoints(tmp_path):
    _, _, _, out = setup_run(tmp_path)
    assert v(out) == 0
    assert main(["verify", str(out / "receipt.json"), str(out / "log.jsonl")]) == 0      # keys from receipt: still consistent


def test_edited_log_and_bad_dsse_fail(tmp_path):
    _, _, _, out = setup_run(tmp_path)
    log = out / "log.jsonl"; good = log.read_bytes()
    log.write_bytes(good.replace(b'{"i":2}', b'{"i":9}')); assert v(out) == 1
    log.write_bytes(good)
    rc = json.loads((out / "receipt.json").read_text()); rc["signatures"][0]["sig"] = "A" * 86 + "=="
    (out / "receipt.json").write_text(json.dumps(rc)); assert v(out) == 1


def test_untrusted_operator_key_fails(tmp_path):
    _, _, _, out = setup_run(tmp_path)
    k = json.loads((out / "keys.json").read_text()); k["operator"] = "00" * 32
    (out / "keys.json").write_text(json.dumps(k)); assert v(out) == 1


def test_forged_cosignature_and_missed_quorum_fail(tmp_path):
    _, _, _, out = setup_run(tmp_path / "none", lambda c: {})
    assert v(out) == 1
    _, _, _, out = setup_run(tmp_path / "forged", lambda c: {**c, "witness-A": b"\1" * 64})   # operator forges witness-A
    assert v(out) == 1 and v(out, "--quorum", "1") == 0


def test_split_view_refused_by_http_witness_and_bad_published_checkpoint(tmp_path):
    op, ws, cp, out = setup_run(tmp_path)
    fork = MerkleLog(); fork.leaves = list(op.log.leaves); fork.leaves[1] = leaf_hash(b"forged")
    body = checkpoint_body(op.origin, cp["size"], fork.root())
    forged = {"size": cp["size"], "root": fork.root(), "body": body, "sig": op.key.sign(body)}
    assert ws[0].cosign(forged, []) is None and "split view" in ws[0].alarms[-1]
    write_checkpoint(str(out), forged, "operator", forged["sig"], [])       # operator publishes the forked view
    assert v(out) == 1


def test_one_witness_listed_twice_does_not_meet_quorum(tmp_path):
    class Twin:                                   # the same witness entered a second time by the operator
        pass
    op, ws, cp, out = setup_run(tmp_path)
    twin = Twin(); twin.name, twin.pub_hex = ws[0].name, ws[0].pub_hex
    rc = build_receipt(op, cp, [ws[0], twin], {ws[0].name: cp["cosigs"][ws[0].name]}, "test", {"red": "c"}, {}, None, [cp])
    (out / "receipt.json").write_text(json.dumps(rc))
    assert v(out) == 1                            # trust file pins witness-A and witness-B, quorum 2


def test_reveal_matches_commitments_and_catches_changed_rules(tmp_path):
    from bayora.commit import commit
    import base64
    op, ws, cp, out = setup_run(tmp_path)
    red, blue = b"attack payloads", b"defensive rules"
    (c_red, n_red), (c_blue, n_blue) = commit(red), commit(blue)
    rc = build_receipt(op, cp, ws, cp["cosigs"], "test", {"red": c_red, "blue": c_blue}, {}, None, [cp])
    (out / "receipt.json").write_text(json.dumps(rc))
    rv = lambda b: {"red": {"nonce": n_red.hex(), "content": base64.b64encode(red).decode()}, "blue": {"nonce": n_blue.hex(), "content": base64.b64encode(b).decode()}}
    (out / "reveal.json").write_text(json.dumps(rv(blue)))
    assert v(out, "--reveal", str(out / "reveal.json")) == 0
    (out / "reveal.json").write_text(json.dumps(rv(b"defensive rules, tuned after seeing the attacks")))
    assert v(out, "--reveal", str(out / "reveal.json")) == 1


def test_reveal_needs_both_teams_commitments(tmp_path):
    op, ws, cp, out = setup_run(tmp_path)
    rc = build_receipt(op, cp, ws, cp["cosigs"], "test", {}, {}, None, [cp])     # operator leaves the commitments out
    (out / "receipt.json").write_text(json.dumps(rc)); (out / "reveal.json").write_text("{}")
    assert v(out, "--reveal", str(out / "reveal.json")) == 1
