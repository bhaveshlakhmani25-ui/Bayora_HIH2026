"""Checks taken from the specifications Bayora follows (DSSE protocol, RFC 9162), not from our own code."""
import base64, json
from bayora.receipt import pae
from bayora.verify import verify, b64
from test_receipt import setup_run


def test_pae_matches_the_dsse_spec_test_vector():
    # secure-systems-lab/dsse protocol.md, "Test Vectors"
    assert pae("http://example.com/HelloWorld", b"hello world") == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"


def test_b64_accepts_standard_url_safe_padded_and_unpadded():
    assert b64("+/8=") == b64("-_8=") == b64("-_8") == b"\xfb\xff"


def test_verifier_accepts_a_url_safe_unpadded_envelope_and_rejects_an_unknown_payload_type(tmp_path):
    *_, out = setup_run(tmp_path)
    rc = json.loads((out / "receipt.json").read_text())
    log = str(out / "log.jsonl")
    assert verify(str(out / "receipt.json"), log, None, str(out / "checkpoints"))[0] is True
    url = lambda s: base64.urlsafe_b64encode(base64.b64decode(s)).decode().rstrip("=")
    alt = dict(rc, payload=url(rc["payload"]), signatures=[dict(x, sig=url(x["sig"])) for x in rc["signatures"]])
    (out / "alt.json").write_text(json.dumps(alt))
    assert verify(str(out / "alt.json"), log, None, str(out / "checkpoints"))[0] is True
    (out / "alt.json").write_text(json.dumps(dict(rc, payloadType="application/json")))
    ok, msg = verify(str(out / "alt.json"), log)
    assert not ok and "unsupported DSSE payloadType" in msg
