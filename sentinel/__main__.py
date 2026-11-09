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


def cmd_aggregator(a):
    from .aggregator_node import run_aggregator
    run_aggregator(a.host, a.port, a.config, a.set, a.dir, a.fresh, a.auto_approve)


def cmd_bank(a):
    from .bank_node import run_bank
    run_bank(a.id, a.aggregator, a.host, a.port, a.config, a.set, a.dir, not a.no_email)


def cmd_cluster(a):
    """Fallback / rehearsal: aggregator + N banks on ONE machine, each in its own process."""
    import os
    import subprocess
    import sys
    env = {**os.environ, "SENTINEL_ADMIN_TOKEN": os.environ.get("SENTINEL_ADMIN_TOKEN", "demo")}
    procs = [subprocess.Popen([sys.executable, "-m", "sentinel", "aggregator", "--port", str(a.port), "--host", a.host] +
                              (["--fresh"] if a.fresh else []) + (["--auto-approve"] if a.auto_approve else []), env=env)]
    time.sleep(1.5)
    ids = "ABCDE"[:a.banks]
    for i, b in enumerate(ids):
        procs.append(subprocess.Popen([sys.executable, "-m", "sentinel", "bank", "--id", b, "--port", str(a.port + 101 + i),
                                       "--aggregator", f"http://127.0.0.1:{a.port}", "--set", f"n_banks={a.banks}"], env=env))
    print(f"\nControl room : http://127.0.0.1:{a.port}   (operator token: {env['SENTINEL_ADMIN_TOKEN']})")
    for i, b in enumerate(ids):
        print(f"Bank {b} portal: http://127.0.0.1:{a.port + 101 + i}")
    print("Ctrl+C stops everything.\n")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()


def cmd_showcase(a):
    """One-laptop defence demo: aggregator + 3 bank nodes + smart-contract registry, browser tabs opened."""
    import os
    import urllib.request
    import webbrowser
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    if not (root / "runs" / "baselines.json").exists():
        print("Computing the centralised / local-only baselines once (about 10 s) ...")
        from .federation import centralized_baseline, local_only
        cfg = load_config("configs/fedavg.yaml")
        (root / "runs").mkdir(exist_ok=True)
        (root / "runs" / "baselines.json").write_text(json.dumps({"centralized": centralized_baseline(cfg), "local_only": local_only(cfg)}, indent=2))
    a.fresh, a.auto_approve, a.banks, a.host = True, False, 3, "127.0.0.1"
    import threading
    def _open():
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{a.port}/api/overview", timeout=1); break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        time.sleep(4)
        if not a.no_browser:
            for u in [f"http://127.0.0.1:{a.port}"] + [f"http://127.0.0.1:{a.port + 101 + i}" for i in range(3)]:
                webbrowser.open_new_tab(u)
        print(SHOWCASE_SCRIPT.format(port=a.port))
    threading.Thread(target=_open, daemon=True).start()
    cmd_cluster(a)


def cmd_web(a):
    """Hosted mode for a public link (Render, Hugging Face, any Docker host): ONE port.

    Aggregator on 0.0.0.0:$PORT; Banks A, B, C run in the same process on internal ports and are reached
    through the gateway at /bank/A/, /bank/B/, /bank/C/. With --autodemo the consortium is approved and a
    15-round run with a live label-flipping attack by Bank C is played at start-up, so the link always
    shows a complete scenario. Operator actions need SENTINEL_ADMIN_TOKEN (set it on the host).
    """
    import os
    import threading
    import urllib.request
    from .aggregator_node import AggregatorNode
    from .bank_node import BankNode
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    port = int(os.environ.get("PORT", a.port))
    os.environ.setdefault("SENTINEL_ADMIN_TOKEN", "demo")
    if not (root / "runs" / "baselines.json").exists():
        from .federation import centralized_baseline, local_only
        bc = load_config("configs/fedavg.yaml")
        (root / "runs").mkdir(exist_ok=True)
        (root / "runs" / "baselines.json").write_text(json.dumps({"centralized": centralized_baseline(bc), "local_only": local_only(bc)}, indent=2))
    cfg = load_config(None, [])
    agg = AggregatorNode(cfg, root / "nodes" / "web" / "aggregator", "0.0.0.0", port, fresh=True)
    for i, b in enumerate("ABC"):
        agg.server.proxies[f"/bank/{b}"] = f"http://127.0.0.1:{9101 + i}"
    agg.start(background=True)
    for i, b in enumerate("ABC"):
        BankNode(b, f"http://127.0.0.1:{port}", cfg, root / "nodes" / "web" / f"bank_{b}", "127.0.0.1", 9101 + i,
                 email_alerts=True).start(background=True)
    print(f"SENTINEL-FL web mode on port {port}: control room /, banks /bank/A/ /bank/B/ /bank/C/", flush=True)

    def call(method, path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None,
                                     method=method, headers={"Content-Type": "application/json",
                                                             "X-Admin-Token": os.environ["SENTINEL_ADMIN_TOKEN"]})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def autodemo():
        while len(call("GET", "/api/registry")) < 3:
            time.sleep(1)
        for b in "ABC":
            call("POST", "/api/registry/action", {"bank": b, "action": "approve"})
        call("POST", "/api/control/start", {"rounds": 15, "round_delay": 2})
        while call("GET", "/api/overview")["run"]["round"] < 4:
            time.sleep(1)
        call("POST", "/api/attack/launch", {"bank": "C", "type": "label_flip"})
        print("autodemo: run started, Bank C attacking from round 4", flush=True)
    if a.autodemo:
        threading.Thread(target=autodemo, daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


SHOWCASE_SCRIPT = """
==================== SENTINEL-FL one-laptop demo ====================
 Control room  http://127.0.0.1:{port}      operator token: demo
 Bank A Paris  http://127.0.0.1:8101   Bank B Frankfurt  :8102   Bank C Amsterdam  :8103

 1. Registry & access  -> Approve A, B, C   (smart contract + ledger record each decision)
 2. Control room       -> Start run (15 rounds, trimmed mean, defences on)
 3. Bank B tab         -> Transactions / Alerts fill up each round (data stays local)
 4. Attack lab, after round 4 -> Bank C + A1 Label flipping -> Launch
    -> C excluded, then quarantined; contract status 'quarantined'; e-mail alert
 5. Audit ledger       -> Verify chain (green) -> Edit record -> Verify (red at that record)
 6. Regulator . ARIA   -> "Did anyone poison the model?"  "Write the incident report"
 7. Bank C tab         -> Data residency: 0 raw rows sent
 8. Results            -> matrix E1-E10 + Flower run (python -m sentinel_flower.simulate --attack label_flip)
 Ctrl+C stops everything.
=====================================================================
"""


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
    s = sp.add_parser("aggregator", help="consortium aggregator / control room")
    s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--config", default=None); s.add_argument("--set", action="append", default=[])
    s.add_argument("--dir", default="nodes/aggregator"); s.add_argument("--fresh", action="store_true", help="start with an empty ledger")
    s.add_argument("--auto-approve", action="store_true", help="approve banks automatically (skip the access-control step)")
    s.set_defaults(fn=cmd_aggregator)
    s = sp.add_parser("bank", help="one bank node with its own portal")
    s.add_argument("--id", required=True, help="A, B, C ...")
    s.add_argument("--aggregator", required=True, help="e.g. http://192.168.43.10:8000")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8101)
    s.add_argument("--config", default=None); s.add_argument("--set", action="append", default=[])
    s.add_argument("--dir", default=None); s.add_argument("--no-email", action="store_true")
    s.set_defaults(fn=cmd_bank)
    s = sp.add_parser("cluster", help="aggregator + banks on one machine (fallback)")
    s.add_argument("--banks", type=int, default=3); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--fresh", action="store_true")
    s.add_argument("--auto-approve", action="store_true")
    s.set_defaults(fn=cmd_cluster)
    s = sp.add_parser("web", help="hosted mode: everything behind ONE port (for a public link)")
    s.add_argument("--port", type=int, default=7860); s.add_argument("--autodemo", action="store_true")
    s.set_defaults(fn=cmd_web)
    s = sp.add_parser("showcase", help="one-laptop defence demo: everything on this machine, browser tabs opened")
    s.add_argument("--port", type=int, default=8000); s.add_argument("--no-browser", action="store_true")
    s.set_defaults(fn=cmd_showcase)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
