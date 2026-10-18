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
