import json
import pytest
from bayora import config
from bayora.cli import main
from bayora.drill import offline
from bayora.ledger import LogOperator


def test_config_defaults_and_overrides(tmp_path):
    assert config.load()["zones"] == {"red": "bz_red", "blue": "bz_blue", "model": "bz_model"}
    p = tmp_path / "c.yaml"; p.write_text("zones: {red: my_red}\nchannels: [filesystem]\n")
    cfg = config.load(p)
    assert cfg["zones"]["red"] == "my_red" and cfg["zones"]["blue"] == "bz_blue" and cfg["channels"] == ["filesystem"]
    for bad in ("chanels: [x]\n", "channels: [carrier_pigeon]\n", "zones: {green: g}\n", "enforcer: selinux\n"):
        p.write_text(bad)
        with pytest.raises(ValueError): config.load(p)


def test_offline_drill_matches_poc_shape():
    r = offline({**config.load(), "noise_lines": 500})
    assert (r["v1"]["detected"], r["v2"]["detected"], r["v2"]["total"]) == (20, 100, 120)
    assert r["v1"]["false_positives"] == r["v2"]["false_positives"] == 0
    assert all(r["v2"]["by_channel_encoding"][f"{ch}|partial"][0] == 0 for ch in config.load()["channels"])


def write_run(tmp_path, n=7):
    op = LogOperator()
    for i in range(n): op.log.append({"i": i})
    cp = op.checkpoint()
    rc = {"origin": op.origin, "log_size": cp["size"], "log_root": cp["root"].hex(),
          "operator_pubkey_raw": op.pub.public_bytes_raw().hex(), "operator_sig": cp["sig"].hex()}
    (tmp_path / "receipt.json").write_text(json.dumps(rc))
    (tmp_path / "log.jsonl").write_bytes(b"".join(e + b"\n" for e in op.log.entries))
    return str(tmp_path / "receipt.json"), tmp_path / "log.jsonl"


def test_verify_accepts_good_log_and_rejects_edits(tmp_path):
    rc, log = write_run(tmp_path)
    assert main(["verify", rc, str(log)]) == 0
    log.write_bytes(log.read_bytes().replace(b'{"i":3}', b'{"i":4}'))
    assert main(["verify", rc, str(log)]) == 1
    log.write_bytes(log.read_bytes().split(b"\n", 1)[1])          # drop an entry
    assert main(["verify", rc, str(log)]) == 1
    rc, log = write_run(tmp_path)                                  # fresh log, forged signature
    r = json.loads(open(rc).read()); r["operator_sig"] = "00" * 64; open(rc, "w").write(json.dumps(r))
    assert main(["verify", rc, str(log)]) == 1


def test_binomial_tail():
    from bayora.cachetest import p_at_least
    assert abs(p_at_least(0, 20, 1 / 8) - 1) < 1e-12
    assert p_at_least(20, 20, 1 / 8) == (1 / 8) ** 20
    assert 0.05 < p_at_least(4, 20, 1 / 8) < 0.5 and p_at_least(8, 20, 1 / 8) < 0.01
