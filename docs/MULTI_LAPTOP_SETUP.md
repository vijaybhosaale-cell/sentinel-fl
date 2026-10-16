# Demo day: four laptops, one consortium

| Laptop | Person | Runs | Opens in the browser |
| --- | --- | --- | --- |
| 1 (projector) | Vijay | aggregator | http://localhost:8000 (control room and all aggregator pages) |
| 2 | Abdul Fathah | Bank A (Paris) | http://localhost:8101 |
| 3 | Mereena | Bank B (Frankfurt) | http://localhost:8101 |
| 4 | Niranjan | Bank C (Amsterdam) | http://localhost:8101 |

## 1. Network (10 minutes before)

1. Turn on a **phone hotspot**. College Wi-Fi often blocks laptops from reaching each other.
2. Connect all four laptops to it.
3. On laptop 1, open PowerShell and run `ipconfig`. Note the **IPv4 address** of the Wi-Fi adapter, for example `192.168.43.10`.

## 2. Aggregator (laptop 1)

```powershell
cd sentinel-fl
python -m sentinel aggregator --fresh
```

The console prints the **operator token**. When Windows asks whether Python may communicate on networks, allow **Private networks**.
Check from another laptop's browser that `http://192.168.43.10:8000` opens the control room.

## 3. Banks (laptops 2–4)

```powershell
git clone https://github.com/vijaybhosaale-cell/sentinel-fl.git
cd sentinel-fl
pip install -r requirements.txt
python -m sentinel bank --id A --aggregator http://192.168.43.10:8000      # B and C on the other laptops
```

Or with Docker: copy `.env.bank.example` to `.env.bank`, set `BANK_ID` and `AGGREGATOR_URL`, then
`docker compose -f docker-compose.bank.yml --env-file .env.bank up --build`.

Each bank appears on the **Registry & access** page as *pending*.

## 4. Run the demo

1. Registry & access → **Approve** A, B and C. Each approval is written to the ledger.
2. Control room → **Start run** (15 rounds, trimmed mean, defences on, 2 s between rounds).
3. After round 4: Attack lab → choose Bank C → *A1 Label flipping* → **Launch attack**. Bank C's own portal shows the red-team banner.
4. Within 2–3 rounds Bank C is excluded, then quarantined. A critical alert and e-mail follow.
5. Audit ledger → **Verify chain** (all green) → edit a record → **Verify** again (red, at the exact record).
6. Regulator · ARIA → "Did anyone poison the model?", "Write the incident report".
7. On any bank laptop → **Data residency**: 0 raw rows sent.

## Fallback: everything on one laptop

```powershell
python -m sentinel cluster --fresh
```

Control room on http://127.0.0.1:8000 (token `demo`); banks on ports 8101, 8102 and 8103. The same pages and the same demo.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Bank portal says "aggregator unreachable" | Wrong IP, or the laptops are on different networks; allow Python in Windows Defender Firewall (Private) on laptop 1 |
| Bank stays *pending* | Approve it on the Registry page |
| "operator token required" | Enter the token printed by the aggregator (or `demo` with `cluster`) |
| A bank was quarantined and should rejoin | Registry or Attack lab → **Reinstate** (logged) |
| Start a clean demo | Stop the aggregator, then start it again with `--fresh` |
