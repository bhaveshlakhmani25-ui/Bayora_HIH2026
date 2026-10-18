import argparse, json, sys
from . import config


def main(argv=None):
    p = argparse.ArgumentParser(prog="bayora", description="Blind, leak-audited red-vs-blue evaluation.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="full run on Docker: isolation probes, load, leak drills, tamper tests, receipt")
    r.add_argument("-c", "--config", help="YAML config (defaults: bayora/default.yaml)")
    r.add_argument("-o", "--out", default="results", help="output directory (default: results)")
    d = sub.add_parser("drill", help="leak drills in-process, no Docker: scanner recall and false positives")
    d.add_argument("-c", "--config")
    ct = sub.add_parser("cachetest", help="prefix-cache timing attack on a real llama.cpp model: shared vs salted")
    ct.add_argument("-c", "--config"); ct.add_argument("-o", "--out", default="results"); ct.add_argument("-n", "--trials", type=int)
    v = sub.add_parser("verify", help="check a receipt against its log file, without contacting the operator")
    v.add_argument("receipt"); v.add_argument("log")
    v.add_argument("--trust", help="pinned keys: {operator, witnesses: {name: pubkey}, quorum}")
    v.add_argument("--checkpoints", help="directory of published checkpoints to check against the log")
    v.add_argument("--quorum", type=int)
    ds = sub.add_parser("dashboard", help="web UI for one results directory")
    ds.add_argument("--results", default="results_final"); ds.add_argument("--port", type=int, default=8765)
    ds.add_argument("--trust", help="pinned keys for the Verify button (default: keys from the receipt)")
    w = sub.add_parser("witness", help="run an independent witness service")
    w.add_argument("action", choices=["serve"]); w.add_argument("--name", required=True); w.add_argument("--port", type=int, default=0)
    w.add_argument("--state", required=True, help="directory for this witness's key and last-seen checkpoints")
    w.add_argument("--operator-pubkey", required=True, help="hex Ed25519 key of the only operator this witness cosigns for")
    a = p.parse_args(argv)

    if a.cmd == "verify":
        from .verify import verify
        ok, msg = verify(a.receipt, a.log, a.trust, a.checkpoints, a.quorum)
        print(msg)
        return 0 if ok else 1
    if a.cmd == "dashboard":
        from .dashboard.server import serve
        serve(a.results, a.port, a.trust)
        return 0
    if a.cmd == "witness":
        from .witness import serve
        serve(a.name, a.port, a.state, a.operator_pubkey)
        return 0
    try:
        cfg = config.load(a.config)
    except (OSError, ValueError) as e:
        p.error(str(e))
    if a.cmd == "run":
        from .run import main as run
        run(cfg, a.out)
    elif a.cmd == "cachetest":
        from .cachetest import run as cachetest
        r = cachetest(cfg, a.trials, a.out)
        for c in ("shared", "salted"):
            print(f"{c}: {r[c]['correct']}/{r[c]['trials']} correct (chance {r[c]['chance']:.3f}, p={r[c]['p_value_vs_chance']:.2g})")
        print("PASS: salted probe at chance" if r["pass"] else "FAIL: salted probe beats chance")
        print(r["environment"])
    else:
        from .drill import offline
        print(json.dumps(offline(cfg), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
