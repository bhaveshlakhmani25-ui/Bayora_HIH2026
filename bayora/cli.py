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
    v = sub.add_parser("verify", help="check a receipt against its log file")
    v.add_argument("receipt"); v.add_argument("log")
    a = p.parse_args(argv)

    if a.cmd == "verify":
        from .verify import verify
        ok, msg = verify(a.receipt, a.log)
        print(msg)
        return 0 if ok else 1
    try:
        cfg = config.load(a.config)
    except (OSError, ValueError) as e:
        p.error(str(e))
    if a.cmd == "run":
        from .run import main as run
        run(cfg, a.out)
    else:
        from .drill import offline
        print(json.dumps(offline(cfg), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
