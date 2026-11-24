# Progress checklist

Legend: ✅ done and tested · 🔜 next · ⬜ pending

## Phase 0: Architecture and plan ✅
- ✅ Stack decision, architecture, schema, folder structure, security architecture (`ARCHITECTURE.md`)

## Phase 1: Secure backend foundation ✅ (46 automated tests; run on SQLite and real PostgreSQL)
- ✅ Environment-only configuration; the app refuses to start with missing or malformed secrets
- ✅ Argon2id password hashing (only hasher enabled)
- ✅ AES-256-GCM encryption service: key IDs, rotation, context-bound AAD, generic errors
- ✅ All 13 required tables (+ `EmailVerificationToken`), constraints, indexes, migrations
- ✅ Encrypted-at-rest transaction amount/description/notes, budget limit, TOTP secret
- ✅ Hash-chained, append-only audit log (ORM guards + PostgreSQL trigger) with `verify_chain()`
- ✅ Single-use hashed tokens (reset / verify), hashed one-time backup codes
- ✅ Spoof-resistant client IP, security headers, no-store caching on API responses
- ✅ Seeded system categories (9)

## Phase 2: Authentication API 🔜
- ⬜ Register, email verification, login, logout, refresh rotation with reuse detection
- ⬜ JWT (short-lived access token + HttpOnly refresh cookie), CSRF double-submit
- ⬜ Lockout, brute-force detection, login history, session list/revoke
- ⬜ Forgot/reset password, password change, password-strength endpoint
- ⬜ Rate-limit throttles on auth endpoints; uniform responses (no user enumeration)

## Phase 3: MFA and suspicious-login detection ⬜
- ⬜ TOTP enrol (QR) → verify-before-enable, replay protection, backup codes, disable
- ⬜ Suspicious-login heuristics, security events, user notifications

## Phase 4: Finance API ⬜
- ⬜ Categories, transactions (CRUD, search, filters, notes), budgets, warning/overspend alerts
- ⬜ Dashboard analytics endpoints, IDOR-safe ownership enforcement, audit hooks, demo seed data

## Phase 5: Reports and admin API ⬜
- ⬜ Daily/weekly/monthly/yearly/category/income-vs-expense reports, PDF + CSV (CSV-injection safe)
- ⬜ Admin RBAC API: users, suspension, security dashboard, audit logs + chain verification

## Phase 6: Frontend foundation ⬜
- ⬜ Vite + React + Tailwind, design system, light/dark theme, auth pages, MFA flows

## Phase 7: Frontend features ⬜
- ⬜ User dashboard + charts, transactions, budgets, reports, security center, admin panel

## Phase 8: Verification and documentation ⬜
- ⬜ OWASP-mapped automated security tests (access control, IDOR, injection, XSS, CSRF, brute force…)
- ⬜ SRS, use-case/DFD/auth-flow diagrams, API docs, installation and testing docs, limitations
