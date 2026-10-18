import os, sys, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from bayora.ledger import MerkleLog, verify_inclusion, verify_consistency, LogOperator, Witness
from bayora.canary import CanaryAuthority, scan
from bayora.commit import commit, verify_reveal


def test_inclusion_and_consistency_all_sizes():
    L = MerkleLog()
    for i in range(65): L.append({"i": i})
    for n in range(1, 66):
        r = L.root(n)
        for m in range(n):
            assert verify_inclusion(m, n, L.leaves[m], L.inclusion_proof(m, n), r)
        for m in range(1, n + 1):
            assert verify_consistency(m, n, L.root(m), r, L.consistency_proof(m, n))


def test_edited_event_rejected():
    L = MerkleLog()
    for i in range(10): L.append({"i": i})
    r = L.root(); p = L.inclusion_proof(3)
    assert not verify_inclusion(3, 10, L.leaves[4], p, r)


def test_witness_refuses_split_view():
    op = LogOperator(); w = Witness("w", op.pub)
    op.log.append({"a": 1}); cp = op.checkpoint(); assert w.cosign(cp, [])
    other = LogOperator(); other.key = op.key; other.log.append({"a": 2})
    assert w.cosign(other.checkpoint(), []) is None and "split view" in w.alarms[-1]


def test_canary_attribution_and_forgery():
    a = CanaryAuthority("r1"); t = a.mint("red", "payload-0")
    assert scan(f"x {t} y", a)[t]["tenant"] == "red"
    assert scan(base64.b64encode(t.encode()).decode(), a)          # v2 decodes base64
    assert not scan(base64.b64encode(t.encode()).decode(), a, "v1")
    assert not scan("BYR" + "A" * 24, a)                              # forged token: no key, no alarm
    assert not scan(t[:14], a)                                        # fragment: known gap


def test_commit_reveal():
    c, n = commit(b"payloads")
    assert verify_reveal(c, n, b"payloads") and not verify_reveal(c, n, b"payloads!")
