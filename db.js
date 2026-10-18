// db.js — MySQL connection pool.
// Exposes two helpers so the vulnerability demos are crystal clear:
//   rawQuery(sql)        -> runs a string you built yourself (used by Vulnerable mode)
//   safeQuery(sql, args) -> runs a parameterised/prepared statement (used by Safe mode)
const mysql = require('mysql2/promise');
const config = require('./config');

const pool = mysql.createPool({
  ...config.db,
  waitForConnections: true,
  connectionLimit: 10,
});

// Vulnerable path: the caller has concatenated user input straight into `sql`.
async function rawQuery(sql) {
  const [rows] = await pool.query(sql);
  return rows;
}

// Safe path: placeholders (?) are sent separately from data, so input can never
// change the structure of the query.
async function safeQuery(sql, args = []) {
  const [rows] = await pool.execute(sql, args);
  return rows;
}

module.exports = { pool, rawQuery, safeQuery };
