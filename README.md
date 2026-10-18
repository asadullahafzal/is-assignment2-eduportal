# Part 2 — EduPortal (Web Security Project, 100 marks)

A full-stack student portal built to demonstrate common web vulnerabilities and
their fixes. **One codebase, two modes** selected by an environment variable:

- `MODE=vulnerable` — every attack below works end-to-end.
- `MODE=safe` — the same features, hardened; every attack is blocked.

Tech stack: **Node.js + Express + EJS + MySQL**.

## Use case
EduPortal: students log in, edit a profile bio, post on a public comment board,
search pages and courses, look up a course, and change their account email.
Those everyday features are exactly the attack surface.

## Project layout
```
Part2_WebProject/
├─ server.js            # all routes; each has a VULN branch and a SAFE branch
├─ config.js            # reads MODE and toggles behaviour
├─ db.js                # rawQuery() (vuln) vs safeQuery() (parameterised)
├─ seed-data.sql        # schema + populated demo data
├─ docker-compose.yml   # one-command MySQL
├─ views/               # EJS templates (escaped vs unescaped output branches)
├─ public/              # style.css, welcome.js (DOM XSS), csrf-attack.html
├─ PAYLOADS.md          # every working payload, copy-paste ready
└─ README.md
```

## How to run (both versions)
```bash
# 1. Start MySQL with schema + seed data
docker compose up -d        # (or load seed-data.sql into your own MySQL)

# 2. Install dependencies
npm install

# 3a. Run the VULNERABLE version
npm run vuln                # http://localhost:3000  (banner shows MODE: VULNERABLE)

# 3b. Run the SAFE version (stop the other first)
npm run safe                # same app, attacks now blocked
```
Demo logins: `alice / alice123`, `admin / S3cr3t_Admin!2026`.

> The top-right badge always shows which mode is live, so examiner screenshots are unambiguous.

## Vulnerabilities, where they live, and how they're fixed
| # | Vulnerability | Vulnerable code (server.js / view) | Fix in Safe mode |
|---|---------------|-----------------------------------|------------------|
| 1 | **Reflected XSS** | `/search` injects `q` into raw HTML | HTML-escape the value (`escapeHtml`) |
| 2 | **Stored XSS** (profile bio) | `profile.ejs` renders bio with `<%- %>` | render with `<%= %>` + strip tags on input |
| 3 | **Stored XSS** (comment board) | `board.ejs` renders body with `<%- %>` | render with `<%= %>` + strip tags on input |
| 4 | **DOM XSS** | `public/welcome.js` uses `innerHTML` on `location.hash` | use `textContent` |
| 5 | **CSRF** | `/account/email` has no token; cookie `SameSite=none` | per-session CSRF token + `SameSite=strict` |
| 6 | **SQLi easy** | `/login` concatenates `username`/`password` | parameterised query |
| 7 | **SQLi intermediate** | `/course?id=` concatenates `id` (error-based) | parameterised query |
| 8 | **SQLi advanced** | `/courses?s=` concatenates `s` (UNION chain) | parameterised query + low-privilege DB user |

All payloads, step by step, are in **`PAYLOADS.md`** — capture a success
screenshot in VULN mode and a blocked screenshot in SAFE mode for each.

## Secure-coding principles demonstrated (for the viva / report)
- **Output encoding** stops XSS: untrusted data is escaped for its output
  context (HTML text here) so it can never become markup.
- **Sink choice** stops DOM XSS: `textContent` vs `innerHTML`.
- **CSRF tokens + SameSite cookies**: a secret the attacker's page can't read,
  plus a cookie the browser won't send cross-site.
- **Parameterised/prepared statements** stop SQLi: data travels separately from
  the query, so it can never change the query's structure.
- **Least privilege**: the app's DB user should hold only `SELECT/INSERT/UPDATE`
  on this schema (see the commented GRANT in `seed-data.sql`), limiting the blast
  radius if injection is ever found.
- **Password storage note**: this lab stores plaintext passwords so the SQLi
  "dump credentials" step is visible. A real app must store a per-password hash
  (bcrypt/argon2), never plaintext — call this out explicitly at the viva.

## GitHub submission
Push this folder to GitHub with a **real commit history** (commit as you build —
graders check it). This README, `seed-data.sql`, and `PAYLOADS.md` satisfy the
documentation requirements.
