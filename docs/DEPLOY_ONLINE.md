# Putting SENTINEL-FL online (permanent link)

`python -m sentinel web` runs the aggregator and Banks A, B and C in one container behind **one address**:

| Address | Page |
| --- | --- |
| `https://<your-app>/` | aggregator: control room and its 8 pages |
| `https://<your-app>/bank/A/`, `/bank/B/`, `/bank/C/` | the three bank portals (also linked in the top bar) |

With `--autodemo` (the default in `Dockerfile.web`) the three banks are approved and a 15-round run is played at
start-up, with Bank C launching a label-flipping attack in round 4, so a visitor always sees a full scenario. Anyone can
look; actions (Start run, Approve/Revoke, Attack lab, Ledger edit) need the operator token you set.

## Option 1 — Render (free, from GitHub)

1. Push the repository to GitHub (`git push`).
2. Create a free account at render.com and sign in with GitHub.
3. **New → Blueprint**, select the `sentinel-fl` repository. Render reads `render.yaml`.
4. When asked for `SENTINEL_ADMIN_TOKEN`, type a token of your choice (for example `esaip-pa3-2026`).
5. **Apply**. The first build takes a few minutes. Your link is `https://sentinel-fl-XXXX.onrender.com`.

Free-plan behaviour: the service sleeps after about 15 minutes without visitors; the next visit wakes it in about a
minute, then the demo replays from the start. Data is synthetic and resets at every restart.

## Option 2 — any Docker host

```bash
docker build -f Dockerfile.web -t sentinel-fl-web .
docker run -p 7860:7860 -e SENTINEL_ADMIN_TOKEN=your-token sentinel-fl-web     # http://localhost:7860
```

The same image runs on Hugging Face Spaces (Docker SDK, app port 7860), Railway, Fly.io or a university VM.

## What the public link is not

It shows the consortium in one container (the banks are separate nodes with separate data, keys and logs, but on one
machine). E-mail alerts are written to the outbox unless SMTP variables are set on the host (`docs/ALERTS_AND_EMAIL.md`).
The Flower engine is not part of the web image (PyTorch is too large for a free instance); its results appear on the
Results page only where `runs/flower` exists.
