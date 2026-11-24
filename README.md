# Smart Expense Tracker: A Cybersecurity-Based Personal Financial Management System

University Cybersecurity capstone project. **Status: Phase 1 of 8 complete** (secure backend foundation). See `docs/PROGRESS.md`.

## What exists now
- Django 5.2 + DRF backend skeleton with fail-closed, environment-only configuration
- Argon2id passwords, AES-256-GCM field encryption (key rotation, context-bound AAD)
- Full relational schema (all required tables) with constraints, indexes and migrations
- Hash-chained, append-only audit log (ORM guards + PostgreSQL trigger + `verify_chain()`)
- 46 automated tests, run green on SQLite and on real PostgreSQL

## Quick start (backend)
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

cp .env.example .env
python scripts/generate_secrets.py        # paste the output lines into .env (never commit .env)

# PostgreSQL (from the project root); alternatively use any local PostgreSQL 14+
cd .. && docker compose --env-file backend/.env up -d db && cd backend

python manage.py migrate
python manage.py runserver                # http://127.0.0.1:8000/api/v1/health/
```
For plain-HTTP local runs set `DJANGO_DEBUG=true` and `SECURE_SSL_REDIRECT=false` in `.env`.

## Running the tests
```bash
python manage.py test --settings=config.settings_test     # fast, in-memory SQLite, ephemeral random keys
python scripts/test_on_postgres.py                         # real PostgreSQL, also verifies the DB trigger
```

## Documentation
- `docs/ARCHITECTURE.md`: stack, architecture, ER diagram, security architecture, limitations
- `docs/PROGRESS.md`: feature checklist by phase
