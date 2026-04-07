// VULNERABLE REST API ROUTES
// VULNERABILITIES: No authentication, mass data exposure, injection,
//                  broken function-level authorization, CORS *

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

// ----------------------------------------------------------------
// VULNERABILITY: Overly permissive CORS
// ----------------------------------------------------------------
router.use((req, res, next) => {
  // VULN: Allows any origin — credential theft possible
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  next();
});

// ----------------------------------------------------------------
// VULNERABILITY: Mass data exposure — returns all user data
// ----------------------------------------------------------------
router.get('/users', (req, res) => {
  const db = req.app.locals.db;

  // VULN: Exposing all users with sensitive fields (password, SSN, credit card)
  // VULN: No authentication required
  // VULN: No pagination — could return millions of rows
  db.all('SELECT * FROM users', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ users: rows });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: User lookup with SQL injection
// ----------------------------------------------------------------
router.get('/users/:id', (req, res) => {
  const db = req.app.locals.db;
  // VULN: SQL Injection
  db.get(`SELECT * FROM users WHERE id = ${req.params.id}`, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row || { error: 'Not found' });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Weak crypto — MD5 for password hashing
// ----------------------------------------------------------------
router.post('/hash', (req, res) => {
  const { password } = req.body;

  // VULN: MD5 is cryptographically broken
  const hash = crypto.createHash('md5').update(password).digest('hex');

  // VULN: Also creating SHA1 — also broken
  const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');

  res.json({
    md5: hash,
    sha1: sha1Hash,
    original: password  // VULN: Returning the original password in response
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Insecure random token generation
// ----------------------------------------------------------------
router.get('/token', (req, res) => {
  // VULN: Math.random() is not cryptographically secure
  const token = Math.random().toString(36).substring(2);
  const weak_otp = Math.floor(1000 + Math.random() * 9000); // VULN: Predictable 4-digit OTP

  res.json({
    token: token,
    otp: weak_otp,
    timestamp: Date.now()
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: User creation with no input validation
// ----------------------------------------------------------------
router.post('/users', (req, res) => {
  const db = req.app.locals.db;
  const { username, password, email, role, ssn, credit_card } = req.body;

  // VULN: No input validation whatsoever
  // VULN: Accepting role from client — privilege escalation
  // VULN: SQL Injection via string concatenation
  // VULN: Storing plaintext password, SSN, and credit card
  const query = `INSERT INTO users (username, password, email, role, ssn, credit_card)
    VALUES ('${username}', '${password}', '${email}', '${role || 'user'}', '${ssn}', '${credit_card}')`;

  db.run(query, function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ id: this.lastID, username, password, email, role }); // VULN: Returning password in response
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Delete without authorization
// ----------------------------------------------------------------
router.delete('/users/:id', (req, res) => {
  const db = req.app.locals.db;

  // VULN: No authentication or authorization
  db.run(`DELETE FROM users WHERE id = ${req.params.id}`, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: true, changes: this.changes });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Returning internal config/secrets
// ----------------------------------------------------------------
router.get('/config', (req, res) => {
  // VULN: Exposing application secrets via API
  res.json({
    database: './vuln_app.db',
    secret: 'admin123',
    api_key: 'sk-1234567890abcdef1234567890abcdef',
    jwt_secret: 'supersecret',
    smtp_password: 'mailpass123',
    aws_access_key: 'AKIAIOSFODNN7EXAMPLE',
    aws_secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: GraphQL-style query execution
// ----------------------------------------------------------------
router.post('/graphql', (req, res) => {
  const db = req.app.locals.db;
  const { query } = req.body;

  // VULN: Directly executing user-provided query
  db.all(query, (err, rows) => {
    if (err) {
      return res.json({ errors: [{ message: err.message }] });
    }
    res.json({ data: rows });
  });
});

module.exports = router;
