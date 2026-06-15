<p align="center">
  <img src="logo.jpg" alt="INPARETO" width="280">
</p>

<h1 align="center">INPARETO</h1>

<p align="center">
  <strong>Local Operator Jacking Remote Bot</strong><br>
  Live dashboard · hit delivery · cloud profiles · API backend
</p>

<p align="center">
  <i>Developed by S Crew</i>
</p>

---

## Overview

**INPARETO** is a Telegram-controlled hunting kit built for operators who want a clean panel, reliable hit delivery, and session stats in one place. This repository ships the **ready-to-run release** — packed `joint.py` (bot) and `endpoint.py` (local API). It is the build you install on Termux, a VPS, or a desktop — not the private source tree.

The bot drives the hunt, posts captures to your **hit group**, and syncs operator data to the cloud. The API handles lookups and generation commands the bot calls over localhost.

---

## Features

### Hunt & delivery
- Multi-threaded username generation and validation
- **Hit group delivery** — captures go to your private Telegram group, not the bot DM
- Rich hit alerts (profile photo, followers, spoiler username, quick actions)
- Pause / resume without restarting the session
- Milestone alerts and session export (`hits.txt`)

### Telegram control panel
- Inline dashboard: stats, settings, health, API & cloud status
- Live auto-refresh panel (optional)
- Slash commands + BotFather menu integration
- Access gate (channel joins) and hit-group verification flow

### Operator profile (cloud-backed)
- Lifetime stats, streaks, and session history
- **Achievements / badges** with unlock notifications
- Global and session **leaderboards**
- Deep **analytics** view from the panel

### Favourites
- **★ Add to fav** on any hit alert
- Optional **notes per saved user** (Yes/No prompt in DM)
- `/saved` exports `favorites.txt` with notes (`@user  Additional: …`)

### Tools & lookups
- Gmail and Instagram **email lookups** via the local API
- Controlled `/gen` runs (rate-limited)
- `/export` for hit archive download
- Config tuning: min followers, timeout, thread count (`/set` or panel)

### Multi-device
- Same Telegram account on phone and PC shares hit-group link via Telegram-ID cloud registry
- Session identity is Telegram ID + local `.inpareto_*` state (no machine fingerprint)

### Security & packaging
- **INPARETO VAULT** packed launchers (no plain source in this folder)
- Maintainer rebuilds from private sources; operators run the published binaries only

---

## What’s in this repo

| File | Description |
|------|-------------|
| `joint.py` | Packed operator bot (Telegram UI, hunt, hits, profile) |
| `endpoint.py` | Packed local API server (default port **5001**) |
| `ig_wbloks.py` | Packed IG contact recovery (used by endpoint + hit enrich) |
| `requirements.txt` | Python dependencies (PC / Linux) |
| `requirements-termux.txt` | Termux Python deps |
| `setup.sh` | Termux one-shot install (packages + clone + pip) |
| `howtouse.txt` | Short operator guide |
| `README.md` | This document |
| `logo.jpg` | Brand logo (shown on GitHub README) |

---

## Requirements

- **Python 3.10+** (3.12+ recommended)
- **Termux** (Android) or any Linux/macOS/Windows shell
- A **@BotFather** bot token and your operator Telegram account
- Network access for Telegram, Supabase sync, and Instagram checks

Install dependencies once:

```bash
pip install -r requirements.txt
```

### Termux (Android) — **0.119.0-beta.3** (Python 3.13)

```bash
curl -fsSL https://raw.githubusercontent.com/l1xky/InparetoA/main/setup.sh -o setup.sh
bash setup.sh
```

`setup.sh` (V6) installs **prebuilt** `pydantic-core` from the [Termux user repo](https://termux-user-repository.github.io/pypi/) (`android_*` wheels on Python 3.13). It pins `pydantic>=2.12` to match that core, installs `typing-inspection`, and uses `--no-deps` on `pydantic`/`fastapi` so pip never pulls a broken PyPI `pydantic-core`. No Rust compile. Do not `pip install -U pip` on Termux.

If a previous run failed mid-way, re-run `bash setup.sh` (it is safe to repeat).

Then two Termux windows:

```bash
cd ~/inpareto
python3 endpoint.py    # window 1 — start first
python3 joint.py       # window 2
```

Do **not** use plain `pip install -r requirements.txt` on Termux — use `setup.sh` (handles `pydantic-core` for Android).

---

## Quick start

Use **two terminals** and keep both processes running.

**Terminal 1 — API** (start first)
```bash
python3 endpoint.py
```

**Terminal 2 — Bot**
```bash
python3 joint.py
```

Keep both running for hunting.

---

## Telegram setup

1. Link your operator bot when `joint.py` prompts you.
2. Complete channel joins and tap **Verify** until the access gate clears.
3. Create a **hit group**, add your bot, and promote it to **admin** with **Post messages** and **Change group info**.
4. Confirm setup:
   - In the group or bot DM: `/verifyhitgroup`
   - If **Group Privacy** is enabled: `/verifyhitgroup@YourBotUsername`
5. New captures will post to that group automatically.

### Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome panel |
| `/stats` | Live dashboard |
| `/settings` | Min followers, timeout, threads |
| `/hits` | Recent captures |
| `/saved` | Favourites + `favorites.txt` export |
| `/profile` | Operator card, badges, streaks |
| `/leaderboard` | Rankings |
| `/analytics` | Session analytics |
| `/health` | Backend health check |
| `/export` | Download `hits.txt` |
| `/pause` / `/resume` | Stop or resume workers |
| `/hitgroup` | Hit group status & setup |
| `/verifyhitgroup` | Confirm bot admin in hit group |
| `/lookup` | Gmail / Instagram lookup |
| `/help` | Full command list |

On hit alerts, use **★ Add to fav** to save a user; the bot will offer an optional note in DM.

---

## Troubleshooting

| Issue | What to do |
|-------|------------|
| “Hit group required” but hits already post | Run `/verifyhitgroup` or tap **Verify hit group** — status refresh, not a new group |
| Bot ignores group commands | Disable Group Privacy in @BotFather, or use `@BotName` in the command |
| Phone + laptop, same account | Log in with the same bot token; verify hit group once per setup |
| Lookup / hunt API errors | Ensure `endpoint.py` is running (port 5001) |
| Favourites notes missing on another device | Add `favorite_notes` (jsonb) on your Supabase `operators` table, or rely on local notes on that device |

---

## Architecture (simple)

```
┌─────────────────┐     localhost      ┌──────────────────┐
│   joint.py      │ ◄────────────────► │   endpoint.py    │
│  Telegram bot   │      HTTP API      │  FastAPI / Uvicorn│
│  Hunt + panel   │                    │  Lookups + gen    │
└────────┬────────┘                    └──────────────────┘
         │
         ▼
   Telegram (DM + hit group)
         │
         ▼
   Cloud sync (operator profile, registries, sessions)

### API server stack

`endpoint.py` runs on **FastAPI + Uvicorn** (port **5001** by default). It serves the lookup + generation endpoints that `joint.py` calls over localhost.
```

---

## Disclaimer

INPARETO is provided as an operator tool for authorized use. You are responsible for compliance with Telegram’s terms, local laws, and platform policies. **S Crew** does not distribute the private source code in this folder — only maintained release builds.

---

<p align="center">
  <img src="logo.jpg" alt="INPARETO" width="120"><br>
  <strong>INPARETO</strong> · Developed by <strong>S Crew</strong>
</p>
