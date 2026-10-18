// config.js — central place that decides Vulnerable vs Safe behaviour.
// Switch the whole application with one environment variable:
//   MODE=vulnerable  -> every attack in this project works end-to-end
//   MODE=safe        -> the same features, hardened; every attack is blocked
//
// Run with:  npm run vuln    or    npm run safe
require('dotenv').config();

const MODE = (process.env.MODE || 'vulnerable').toLowerCase();

module.exports = {
  MODE,
  isVulnerable: MODE === 'vulnerable',
  isSafe: MODE === 'safe',
  port: process.env.PORT || 3000,
  db: {
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'eduportal',
    password: process.env.DB_PASS || 'eduportal_pw',
    database: process.env.DB_NAME || 'eduportal',
    multipleStatements: false, // kept off so stacked-query injection can't add rows
  },
  sessionSecret: process.env.SESSION_SECRET || 'dev-only-insecure-secret',
};
