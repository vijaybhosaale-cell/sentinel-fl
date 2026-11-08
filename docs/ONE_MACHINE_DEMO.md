# Defence day: everything on one laptop

All components run on the presenter's laptop. No network, hotspot or second machine is needed.

| What | How it runs on the laptop |
| --- | --- |
| Aggregator (control room, 8 pages) | process on port 8000 |
| Banks A, B, C (6-page portal each) | three separate processes on ports 8101, 8102, 8103, each with its own data, keys and logs |
| Smart-contract registry | inside the aggregator (simulated backend with the contract's rules), or a local Anvil chain (`docs/SMART_CONTRACT.md`) |
| Flower + PyTorch + Opacus | `run_flower.bat`: Flower simulation with 3 bank SuperNodes; result shown on the Results page |
| Prometheus + Grafana (optional) | `docker compose --profile monitoring up -d prometheus grafana` |

## Before the defence (once)

```powershell
cd sentinel-fl
pip install -r requirements.txt
python -m unittest discover -s tests          # 21 tests, all OK
python -m venv .venv-flower
.venv-flower\Scripts\pip install -r requirements-flower.txt --extra-index-url https://download.pytorch.org/whl/cpu
run_flower.bat                                # check: Bank C quarantined, "ledger verified: True"
```

## On the day

1. Double-click **`start_demo.bat`** (or `python -m sentinel showcase`). Four browser tabs open: control room and the three bank portals. Operator token: `demo`.
2. Follow the checklist printed in the console:
   1. Registry & access → Approve A, B, C (contract transactions appear at the bottom of the page).
   2. Control room → Start run.
   3. Bank B tab → Transactions and Alerts fill up each round.
   4. Attack lab, after round 4 → Bank C, A1 Label flipping → Launch. C is excluded, then quarantined; the contract shows `quarantined`.
   5. Audit ledger → Verify chain → edit a record → Verify again (red at that exact record).
   6. Regulator · ARIA → "Did anyone poison the model?", "Write the incident report".
   7. Bank C tab → Data residency: 0 raw rows sent.
   8. Results → experiment matrix, and the Flower run (run `run_flower.bat` beforehand, or live in a second window).
3. Ctrl+C in the console stops everything. Running `start_demo.bat` again starts a clean consortium.

Tip: arrange the four tabs as two browser windows side by side (control room left, bank portal right) on the projector.
