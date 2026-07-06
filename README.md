# REMI Solar Services — AI Email Triage (MVP)

A small Flask + SQLite application that receives company email, classifies and
prioritises it with Mistral models, routes it to the right department, and keeps
a GDPR-aware audit trail with a human-in-the-loop review queue.

> This is an MVP scaffold. Auth (with optional 2FA), RBAC, the database, all
> pages, and a working offline triage pipeline are real. The Mistral OCR / LLM
> calls fall back to a transparent heuristic engine when no token is set, so the
> app runs end-to-end without a token — set `MISTRAL_API_KEY` to use the real models.

## Features
- Email/password login with **optional TOTP two-factor** (6-digit code; enrol from Profile)
- Role-based menu + server-side route guards across all pages
- **System Test** page (global admin): compose an email, attach files, and watch it flow through ingestion → OCR → classification → routing
- Each **department has its own inbound address** (e.g. `it@remi-solar.eu`) used as the routing target
- **Department viewers see only their own department's** statistics and mail
- User menu (top-right) with Settings and Log out
- Audit logging, verification queue, retention policies


## Install commands
```bash
sudo apt install python3-pip

python3 -m venv .venv
source .venv/bin/activate 
pip install -r requirements.txt
python init_db.py --reset
python app.py
```


## Upgrading an existing install
The schema added columns (MFA, department emails). Rebuild the database once:

```bash
python init_db.py --reset
```

## Stack
- **Python + Flask** (web)
- **SQLite** (storage)
- **bcrypt** (password hashing)
- **Mistral OCR** + **Mistral Large** (fixed in code, token via `MISTRAL_API_KEY`)
- Tailwind (CDN) + Space Grotesk / Inter / IBM Plex Mono for the UI

## Run it

```bash
cd remi-solar-mvp
python -m venv .venv && source .venv/bin/activate    # optional
pip install -r requirements.txt

python init_db.py        # creates remi_solar.db + demo data
python app.py            # http://127.0.0.1:5000
```

Reset the database any time with `python init_db.py --reset`.

## Demo accounts

| Email | Password | Role |
|-------|----------|------|
| admin@remi-solar.eu | admin123 | Global administrator (sees everything) |
| sales@remi-solar.eu | sales123 | Department viewer (Sales) |
| finance@remi-solar.eu | finance123 | Department viewer (Finance) |
| audit@remi-solar.eu | audit123 | Audit administrator |
| verify@remi-solar.eu | verify123 | Verification administrator |
| mail@remi-solar.eu | mail123 | Email administrator |

Log in as different users to see the left menu and page access change by role.

## Project layout

```
remi-solar-mvp/
├── app.py              # routes, auth, RBAC guards
├── init_db.py          # schema loader + demo seeder (bcrypt users)
├── schema.sql          # SQLite DDL (from the DBML diagram)
├── mistral_client.py   # Mistral OCR / Large wrappers (stubbed)
├── requirements.txt
└── templates/          # base layout + 12 pages + macros
```

## Pages & access

Login · Home (all) · Department Mailbox (viewer) · Email detail · Verification
(verification admin) · Audit (audit admin) · Reception Storage (email admin) ·
Users & Roles · Departments · Settings · Data Retention (global admin) ·
Profile (all). The menu only shows buttons a role can use; routes are guarded
server-side regardless of the menu.

## Next steps
1. Implement the real Mistral calls in `mistral_client.py`.
2. Add the ingestion pipeline (Outlook/IMAP → `emails` → OCR → classify → route).
3. Wire reclassification on the email detail page (writes a new `email_analysis` row).
4. Move secrets to environment variables; set a real `SECRET_KEY`.
