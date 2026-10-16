"""SENTINEL-FL command line.

  python -m sentinel run --config configs/fedavg.yaml [--set rounds=30 --set dp.enabled=true]
  python -m sentinel baselines --config configs/fedavg.yaml
  python -m sentinel matrix                      # experiment matrix -> experiments/results.md
  python -m sentinel serve [--port 8000]         # Mission Control + read-only API
  python -m sentinel demo                        # dashboard + live attack scenario
  python -m sentinel verify --run NAME
  python -m sentinel tamper --run NAME --record 12
  python -m sentinel aria --run NAME "Did anyone poison the model?"
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path

from .config import load_config


def cmd_run(a):
    from .federation import Federation
    cfg = load_config(a.config, a.set)
    s = Federation(cfg).run()
    print(json.dumps({"final": {k: s["final"][k] for k in ("round", "pr_auc", "f1", "recall_at_1pct_fpr", "eps")},
                      "ledger": s["ledger"]["reason"]}, indent=2))


def cmd_baselines(a):
    from .federation import centralized_baseline, local_only
    cfg = load_config(a.config, a.set)
    out = {"centralized": centralized_baseline(cfg), "local_only": local_only(cfg)}
    p = Path(cfg["out_dir"]) / "baselines.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


def cmd_matrix(a):
    from .experiments import run_matrix
    run_matrix(a.out, quick=a.quick)


def cmd_serve(a):
    from .server import serve
    serve(a.runs, a.host, a.port)


def cmd_demo(a):
    from .federation import Federation, centralized_baseline, local_only
    from .server import serve
    base = load_config("configs/fedavg.yaml")
    bp = Path(base["out_dir"]) / "baselines.json"
    if not bp.exists():
        print("Computing baselines once ...")
        bp.parent.mkdir(parents=True, exist_ok=True)
        bp.write_text(json.dumps({"centralized": centralized_baseline(base), "local_only": local_only(base)}, indent=2))
    threading.Thread(target=serve, args=(base["out_dir"], a.host, a.port), daemon=True).start()
    print(f"Open http://{a.host}:{a.port} - the run starts in 5 seconds")
    time.sleep(5)
    cfg = load_config(a.config, a.set)
    Federation(cfg).run()
    print("Run finished - dashboard stays up. Ctrl+C to stop.")
    while True:
        time.sleep(3600)


def cmd_verify(a):
    from .ledger import open_readonly
    print(json.dumps(open_readonly(Path(a.runs) / a.run / "ledger.db").verify(), indent=2))


def cmd_tamper(a):
    from .ledger import open_readonly
    L = open_readonly(Path(a.runs) / a.run / "ledger.db")
    rec = next(e for e in L.entries() if e["idx"] == a.record)
    old = rec["body"].get(a.field)
    value = json.loads(a.value)
    if value is None:
        value = (not old) if isinstance(old, bool) else "edited-by-insider"
    L.tamper(a.record, a.field, value)
    a.value = json.dumps(value)
    print(f"Record #{a.record} edited ({a.field}={a.value}) WITHOUT re-signing. Now run: python -m sentinel verify --run {a.run}")


def cmd_aria(a):
    from .aria import ask
    r = ask(" ".join(a.question), Path(a.runs) / a.run)
    print(f"ARIA [{r['mode']}] tools={[t['tool'] for t in r['tools']]}\n\n{r['answer']}")


def main():
    p = argparse.ArgumentParser(prog="sentinel", description="SENTINEL-FL: federated AML detection with audit and ARIA")
    sp = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("baselines", cmd_baselines), ("demo", cmd_demo)):
        s = sp.add_parser(name)
        s.add_argument("--config", default="configs/demo_attack.yaml" if name == "demo" else "configs/fedavg.yaml")
        s.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
        if name == "demo":
            s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
        s.set_defaults(fn=fn)
    s = sp.add_parser("matrix"); s.add_argument("--out", default="experiments"); s.add_argument("--quick", action="store_true"); s.set_defaults(fn=cmd_matrix)
    s = sp.add_parser("serve"); s.add_argument("--runs", default="runs"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000); s.set_defaults(fn=cmd_serve)
    s = sp.add_parser("verify"); s.add_argument("--runs", default="runs"); s.add_argument("--run", required=True); s.set_defaults(fn=cmd_verify)
    s = sp.add_parser("tamper"); s.add_argument("--runs", default="runs"); s.add_argument("--run", required=True)
    s.add_argument("--record", type=int, required=True); s.add_argument("--field", default="accepted")
    s.add_argument("--value", default="null", help="JSON value; default flips a boolean field"); s.set_defaults(fn=cmd_tamper)
    s = sp.add_parser("aria"); s.add_argument("--runs", default="runs"); s.add_argument("--run", required=True)
    s.add_argument("question", nargs="+"); s.set_defaults(fn=cmd_aria)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
