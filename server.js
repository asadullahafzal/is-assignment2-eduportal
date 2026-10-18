// server.js — EduPortal
// One application, two security postures selected by config.MODE.
// Every route below has a clearly marked `if (isVulnerable)` branch (the insecure
// implementation the attacks target) and an `else` branch (the hardened fix).
//
//   npm run vuln   -> MODE=vulnerable  (all attacks succeed)
//   npm run safe   -> MODE=safe        (all attacks blocked)

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const config = require('./config');
const { rawQuery, safeQuery } = require('./db');

const { isVulnerable } = config;
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- Session / cookie configuration -----------------------------------------
// SAFE mode uses SameSite=strict, which is one of the two defences that stop the
// CSRF attack (the attacker's cross-site request no longer carries the cookie).
// VULN mode uses SameSite=lax so the session works over plain HTTP; combined
// with the missing CSRF token below, a same-origin attack page (permitted by
// the brief) still forges the request successfully.
app.use(session({
  name: 'sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: isVulnerable ? 'lax' : 'strict',
    secure: false, // true behind HTTPS in production
  },
}));

// Make mode + logged-in user available to every template.
app.use((req, res, next) => {
  res.locals.mode = config.MODE;
  res.locals.isVulnerable = isVulnerable;
  res.locals.user = req.session.user || null;
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// A tiny HTML escaper used by the SAFE branches that build HTML by hand.
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// =============================================================================
// HOME
// =============================================================================
app.get('/', (req, res) => res.render('home'));

// =============================================================================
// SQL INJECTION #1 (EASY) — login / authentication bypass
// Payload (username field):   ' OR '1'='1' --
// =============================================================================
app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    let rows;
    if (isVulnerable) {
      // VULNERABLE: user input concatenated straight into the SQL string.
      // "' OR '1'='1' -- " turns the WHERE clause into something always-true
      // and comments out the password check.
      const sql =
        `SELECT id, username, role FROM users ` +
        `WHERE username = '${username}' AND password = '${password}'`;
      console.log('[VULN SQL]', sql);
      rows = await rawQuery(sql);
    } else {
      // SAFE: placeholders keep data separate from code; injection is impossible.
      rows = await safeQuery(
        'SELECT id, username, role FROM users WHERE username = ? AND password = ?',
        [username, password]
      );
    }
    if (rows.length > 0) {
      req.session.user = rows[0];
      return res.redirect('/dashboard');
    }
    res.render('login', { error: 'Invalid credentials' });
  } catch (err) {
    res.render('login', { error: 'Error: ' + err.message });
  }
});

app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.get('/dashboard', requireLogin, (req, res) => res.render('dashboard'));

// =============================================================================
// REFLECTED XSS — search box echoes the query back into the page
// Payload (q):   <script>alert(document.domain)</script>
// =============================================================================
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  if (isVulnerable) {
    // VULNERABLE: the query is injected into raw HTML with no encoding, so any
    // markup/script in `q` is parsed and executed by the victim's browser.
    const html = `
      <h2>Search results</h2>
      <p>You searched for: ${q}</p>
      <p>No matching pages found.</p>`;
    return res.render('raw', { title: 'Search', body: html });
  }
  // SAFE: value is HTML-escaped before being placed in the page.
  const html = `
    <h2>Search results</h2>
    <p>You searched for: ${escapeHtml(q)}</p>
    <p>No matching pages found.</p>`;
  res.render('raw', { title: 'Search', body: html });
});

// =============================================================================
// STORED XSS — profile "bio" saved to DB and shown to every viewer
// Payload (bio):   <script>alert('stored-xss by '+document.cookie)</script>
// =============================================================================
app.get('/profile', requireLogin, async (req, res) => {
  const rows = await safeQuery('SELECT username, email, bio FROM users WHERE id = ?',
    [req.session.user.id]);
  res.render('profile', { profile: rows[0], saved: req.query.saved === '1' });
});

app.post('/profile', requireLogin, async (req, res) => {
  let bio = req.body.bio || '';
  if (!isVulnerable) {
    // SAFE (defence in depth): strip tags on input. The real protection is the
    // escaped output in the template; sanitising here is a second layer.
    bio = bio.replace(/<[^>]*>/g, '');
  }
  // The value is STORED as-is in VULN mode; the danger is realised on output,
  // where the template renders it unescaped (see views/profile.ejs).
  await safeQuery('UPDATE users SET bio = ? WHERE id = ?', [bio, req.session.user.id]);
  res.redirect('/profile?saved=1');
});

// Public comment board — another stored-XSS surface, viewable by everyone.
app.get('/board', async (req, res) => {
  const comments = await safeQuery('SELECT author, body, created FROM comments ORDER BY id DESC');
  res.render('board', { comments });
});

app.post('/board', requireLogin, async (req, res) => {
  let body = req.body.body || '';
  if (!isVulnerable) body = body.replace(/<[^>]*>/g, '');
  await safeQuery('INSERT INTO comments (author, body) VALUES (?, ?)',
    [req.session.user.username, body]);
  res.redirect('/board');
});

// =============================================================================
// DOM-BASED XSS — client JS reads location.hash and writes it to the page
// Payload (open in browser):
//   /welcome#<img src=x onerror=alert('dom-xss')>
// The vulnerability lives entirely in public/welcome.js; the server only tells
// the page which mode it is in via window.APP_MODE.
// =============================================================================
app.get('/welcome', (req, res) => res.render('welcome'));

// =============================================================================
// CSRF — state-changing "update email" with no anti-CSRF protection in VULN
// The attack page is public/csrf-attack.html (auto-submits a cross-site POST).
// =============================================================================
app.get('/account', requireLogin, async (req, res) => {
  const rows = await safeQuery('SELECT email FROM users WHERE id = ?', [req.session.user.id]);
  // SAFE mode issues a per-session CSRF token the form must echo back.
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(16).toString('hex');
  res.render('account', {
    email: rows[0].email,
    csrfToken: req.session.csrfToken,
    done: req.query.done === '1',
  });
});

app.post('/account/email', requireLogin, async (req, res) => {
  if (!isVulnerable) {
    // SAFE: reject the request unless it carries the secret token that only our
    // own form knows. A cross-site attacker cannot read it, so forged requests
    // are refused. (SameSite=strict above is the second, independent defence.)
    if (!req.body.csrf || req.body.csrf !== req.session.csrfToken) {
      return res.status(403).send('CSRF token missing or invalid — request blocked.');
    }
  }
  // VULNERABLE: no token check — any page that can make the browser POST here
  // (while the victim is logged in) can silently change their email.
  await safeQuery('UPDATE users SET email = ? WHERE id = ?',
    [req.body.email, req.session.user.id]);
  res.redirect('/account?done=1');
});

// =============================================================================
// SQL INJECTION #2 (INTERMEDIATE) — error-based lookup by course id
// VULN mode surfaces the DB error, so updatexml()/extractvalue() leaks data in
// the error message. Example payload (id):
//   1 AND updatexml(1, concat(0x7e,(SELECT password FROM users LIMIT 1)),1)
// =============================================================================
app.get('/course', async (req, res) => {
  const id = req.query.id || '1';
  try {
    let rows;
    if (isVulnerable) {
      const sql = `SELECT id, name, description FROM courses WHERE id = ${id}`;
      console.log('[VULN SQL]', sql);
      rows = await rawQuery(sql);
    } else {
      rows = await safeQuery('SELECT id, name, description FROM courses WHERE id = ?', [id]);
    }
    res.render('course', { course: rows[0] || null, error: null });
  } catch (err) {
    // VULN mode shows the raw error (enables error-based injection).
    // SAFE mode would never reach a SQL error from injection, but we still avoid
    // leaking internals to the user.
    const msg = isVulnerable ? err.message : 'Invalid course id.';
    res.render('course', { course: null, error: msg });
  }
});

// =============================================================================
// SQL INJECTION #3 (ADVANCED) — UNION-based on a visible, multi-column list
// VULN query:  SELECT id, name, description FROM courses WHERE name LIKE '%<s>%'
// Full chain (see PAYLOADS.md):
//   1) columns:  %' ORDER BY 3 -- -        (and ORDER BY 4 errors -> 3 columns)
//   2) db/tables: %' UNION SELECT 1,table_name,3 FROM information_schema.tables
//                 WHERE table_schema=database() -- -
//   3) columns:   %' UNION SELECT 1,column_name,3 FROM information_schema.columns
//                 WHERE table_name='users' -- -
//   4) data:      %' UNION SELECT id,concat(username,0x3a,password),email FROM users -- -
// =============================================================================
app.get('/courses', async (req, res) => {
  const s = req.query.s || '';
  try {
    let rows;
    if (isVulnerable) {
      const sql = `SELECT id, name, description FROM courses WHERE name LIKE '%${s}%'`;
      console.log('[VULN SQL]', sql);
      rows = await rawQuery(sql);
    } else {
      rows = await safeQuery(
        'SELECT id, name, description FROM courses WHERE name LIKE ?', [`%${s}%`]);
    }
    res.render('courses', { rows, s, error: null });
  } catch (err) {
    res.render('courses', { rows: [], s, error: isVulnerable ? err.message : 'Search failed.' });
  }
});

app.listen(config.port, () => {
  console.log(`EduPortal running in ${config.MODE.toUpperCase()} mode on http://localhost:${config.port}`);
});
