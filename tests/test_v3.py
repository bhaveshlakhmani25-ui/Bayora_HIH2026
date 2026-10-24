import random
from bayora.canary import CanaryAuthority, scan, K
from bayora.drill import noise


def test_v3_catches_fragments_and_reversals_v2_misses():
    a = CanaryAuthority("r"); t = a.mint("blue", "rule-1")
    for leak in (t[:14], t[-K:], "x " + t[5:5 + K] + " y", t[::-1], " ".join(t[:14])):
        assert not scan(leak, a, "v2")
        assert scan(leak, a, "v3")[t]["tenant"] == "blue"
    assert not scan(t[:K - 1], a, "v3")                     # shorter than K: residual risk, by design


def test_v3_no_false_positives_on_noise_and_random_base32():
    a = CanaryAuthority("r")
    for i in range(200): a.mint("red", f"s{i}")
    rnd = random.Random(3)
    rand32 = "\n".join("".join(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(27)) for _ in range(1000))
    assert not scan(noise(10000) + "\n" + rand32, a, "v3")


def test_real_foreign_canary_is_alerted_not_counted_as_noise():
    from bayora.drill import make_drills, score
    a = CanaryAuthority("r"); payload = a.mint("red", "payload-0"); own = a.mint("blue", "rule-0")
    drills = make_drills(a, ["container_log"], ["plain"], 1)
    text = drills[0]["text"] + "\nstolen: " + payload + "\nblue's own rule: " + own
    summary, alerts = score(drills, {"container_log": text}, a, ["container_log"], "v3")
    by_tok = {x["token"]: x for x in alerts}
    assert by_tok[drills[0]["token"]]["drill"] is True
    assert by_tok[payload]["drill"] is False and by_tok[payload]["tenant"] == "red"   # a real red leak into the blue zone
    assert own not in by_tok                                                          # blue's own canary in blue's zone is not a leak
    assert summary["detected"] == 1
