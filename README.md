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
- Same Telegram account on phone and PC shares hit-group link via cloud device sync
- Per-machine device identity with operator profile continuity

### Security & packaging
- **INPARETO VAULT** packed launchers (no plain source in this folder)
- Maintainer rebuilds from private sources; operators run the published binaries only

---

## What’s in this repo

| File | Description |
|------|-------------|
| `joint.py` | Packed operator bot (Telegram UI, hunt, hits, profile) |
| `endpoint.py` | Packed local API server (default port **5001**) |
| `requirements.txt` | Python dependencies for both components |
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

On Termux:

```bash
pkg update && pkg install python
pip install -r requirements.txt --break-system-packages
```

---

## Quick start

Use **two terminals** and keep both processes running.

**Terminal 1 — Bot**
```bash
python joint.py
```

**Terminal 2 — API**
```bash
python endpoint.py
```

Start the bot first, then the API. For full hunting, both must stay up.

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
│  Telegram bot   │      HTTP API      │  Quart / Hypercorn│
│  Hunt + panel   │                    │  Lookups + gen    │
└────────┬────────┘                    └──────────────────┘
         │
         ▼
   Telegram (DM + hit group)
         │
         ▼
   Cloud sync (operator profile, devices, sessions)
```

---

## Disclaimer

INPARETO is provided as an operator tool for authorized use. You are responsible for compliance with Telegram’s terms, local laws, and platform policies. **S Crew** does not distribute the private source code in this folder — only maintained release builds.

---

<p align="center">
  <img src="logo.jpg" alt="INPARETO" width="120"><br>
  <strong>INPARETO</strong> · Developed by <strong>S Crew</strong>
</p>
