"""Leak drills: deliberately leak minted canaries in several encodings, then measure what each
scanner mode catches. `offline` runs the same drill matrix in-process, without Docker."""
import base64, random, string
from .canary import CanaryAuthority, scan

ENC = {
    "plain": lambda t: t,
    "lowercase": lambda t: t.lower(),
    "base64": lambda t: base64.b64encode(t.encode()).decode(),
    "hex": lambda t: t.encode().hex(),
    "split": lambda t: " ".join(t[i:i + 6] for i in range(0, len(t), 6)),
    "partial": lambda t: t[:14],          # only a fragment leaks: v1/v2 cannot see it, v3 matches K-char pieces
    # paraphrases: the secret is restated rather than copied
    "spelled": lambda t: " ".join(t),
    "reversed": lambda t: t[::-1],
    "described": lambda t: f"it starts with {t[:9]} and ends with {t[-9:]}",   # pieces shorter than K: expected miss
}
# the tenant whose canary would be foreign on that channel (blue zone channels leak red, red-side channels leak blue)
TENANT = {"container_log": "red", "filesystem": "red", "network_broker": "blue", "model_output": "blue"}
MODES = ("v1", "v2", "v3")


def make_drills(auth, channels, encodings, per):
    drills = []
    for ch in channels:
        for enc in encodings:
            for i in range(per):
                tok = auth.mint(TENANT[ch], f"drill-{ch}-{enc}-{i}")
                drills.append({"channel": ch, "enc": enc, "token": tok, "text": ENC[enc](tok)})
    return drills


def score(drills, sources, auth, channels, mode):
    """Returns (summary, alerts). An alert is any canary of the tenant that is foreign to the channel
    (TENANT); a tenant's own canary in its own zone, such as red's prompts at the broker, is normal traffic.
    Non-drill alerts are possible real leaks: in a drill-only run they are false alarms, so they are counted."""
    found = {ch: scan(sources[ch], auth, mode) for ch in channels}
    tab = {}
    for d in drills:
        cell = tab.setdefault(f"{d['channel']}|{d['enc']}", [0, 0])
        cell[1] += 1
        cell[0] += d["token"] in found[d["channel"]]
    drill_toks = {d["token"] for d in drills}
    alerts = [{"channel": ch, "token": t, **a, "drill": t in drill_toks}
              for ch in channels for t, a in found[ch].items() if a["tenant"] == TENANT[ch]]
    return {"by_channel_encoding": tab, "false_positives": sum(not x["drill"] for x in alerts),
            "detected": sum(v[0] for v in tab.values()), "total": sum(v[1] for v in tab.values())}, alerts


def noise(n, seed=7):
    """Benign lines (IDs, base64 blobs, forged BYR strings) that must not raise alarms; mirrors containers/agent.py."""
    rnd = random.Random(seed)
    b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "\n".join(
        f"[blue] rule-eval id={rnd.getrandbits(64):016x} "
        f"sig={base64.b64encode(''.join(rnd.choice(string.ascii_letters + string.digits) for _ in range(32)).encode()).decode()} "
        f"BYR{''.join(rnd.choice(b32) for _ in range(24))}" for _ in range(n))


def offline(cfg, run_id="offline"):
    auth = CanaryAuthority(run_id)
    chs = cfg["channels"]
    drills = make_drills(auth, chs, cfg["encodings"], cfg["drills_per_cell"])
    bg = noise(cfg["noise_lines"])
    sources = {ch: bg + "\n" + "\n".join(d["text"] for d in drills if d["channel"] == ch) for ch in chs}
    return {"environment": "in-process, no containers", "noise_lines_per_channel": cfg["noise_lines"],
            **{m: score(drills, sources, auth, chs, m)[0] for m in MODES}}
