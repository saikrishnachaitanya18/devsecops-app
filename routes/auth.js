// AUTH ROUTES — Login / Register / Profile
// VULNERABILITIES: SQL Injection in login, plaintext passwords, no rate limiting,
//                  no CSRF protection, mass assignment, broken auth

const express = require('express');
const router = express.Router();

// ----------------------------------------------------------------
// VULNERABILITY: SQL Injection in login (string concatenation)
// VULNERABILITY: Plaintext password storage
// VULNERABILITY: No rate limiting / brute force protection
// VULNERABILITY: No CSRF token
// ----------------------------------------------------------------
router.get('/login', (req, res) => {
  res.render('login', { error: null, user: req.session.user || null });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = req.app.locals.db;

  // VULN: SQL Injection — user input directly concatenated into query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(query, (err, row) => {
    if (err) {
      // VULN: Leaking database error details to client
      return res.render('login', { error: `Database error: ${err.message}`, user: null });
    }
    if (row) {
      // VULN: Storing entire user object in session including sensitive data
      req.session.user = row;
      // VULN: Setting user info in cookie (plaintext)
      res.cookie('user_role', row.role, { httpOnly: false });
      res.cookie('user_id', row.id, { httpOnly: false });
      res.redirect('/');
    } else {
      // VULN: Reveals whether username or password is wrong
      res.render('login', { error: 'Invalid username or password', user: null });
    }
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Mass Assignment — user controls role field
// VULNERABILITY: No input validation/sanitization
// VULNERABILITY: No password hashing
// ----------------------------------------------------------------
router.get('/register', (req, res) => {
  res.render('register', { error: null, success: null, user: req.session.user || null });
});

router.post('/register', (req, res) => {
  const db = req.app.locals.db;
  // VULN: Mass assignment — role comes from user input
  const { username, password, email, role } = req.body;

  // VULN: No password complexity enforcement
  // VULN: No email validation
  // VULN: Plaintext password storage
  // VULN: SQL Injection via string concatenation
  const query = `INSERT INTO users (username, password, email, role) VALUES ('${username}', '${password}', '${email}', '${role || "user"}')`;

  db.run(query, function(err) {
    if (err) {
      return res.render('register', { error: `Error: ${err.message}`, success: null, user: null });
    }
    res.render('register', { error: null, success: 'Registration successful! You can now login.', user: null });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: IDOR — any user can see any profile by changing the id
// VULNERABILITY: Exposes sensitive data (SSN, credit card)
// ----------------------------------------------------------------
router.get('/profile/:id', (req, res) => {
  const db = req.app.locals.db;
  const userId = req.params.id;

  // VULN: No authorization check — anyone can view any user's profile
  // VULN: SQL Injection
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  db.get(query, (err, row) => {
    if (err || !row) {
      return res.status(404).send('User not found');
    }
    // VULN: Exposing all data including SSN & credit card
    res.render('profile', { profile: row, user: req.session.user || null });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: No session invalidation on logout
// ----------------------------------------------------------------
router.get('/logout', (req, res) => {
  // VULN: Session not properly destroyed
  req.session.user = null;
  res.redirect('/');
});

module.exports = router;
