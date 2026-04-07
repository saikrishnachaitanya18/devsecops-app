// SQL INJECTION ROUTES
// VULNERABILITIES: Multiple SQL injection vectors

const express = require('express');
const router = express.Router();

// ----------------------------------------------------------------
// VULNERABILITY: SQL Injection — search via GET parameter
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  const db = req.app.locals.db;
  const search = req.query.search || '';

  // VULN: Direct string concatenation in SQL query
  const query = `SELECT * FROM users WHERE username LIKE '%${search}%'`;

  db.all(query, (err, rows) => {
    if (err) {
      // VULN: Detailed error messages exposed
      return res.render('sqli', {
        results: [],
        error: `SQL Error: ${err.message}`,
        search: search,
        user: req.session.user || null,
        postResult: null,
        postError: null,
        lookupResult: null,
        lookupError: null
      });
    }
    res.render('sqli', {
      results: rows || [],
      error: null,
      search: search,
      user: req.session.user || null,
      postResult: null,
      postError: null,
      lookupResult: null,
      lookupError: null
    });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: SQL Injection — POST body parameter
// ----------------------------------------------------------------
router.post('/search', (req, res) => {
  const db = req.app.locals.db;
  const { query: userQuery } = req.body;

  // VULN: Direct concatenation of user input
  const sqlQuery = `SELECT * FROM posts WHERE title LIKE '%${userQuery}%' OR content LIKE '%${userQuery}%'`;

  db.all(sqlQuery, (err, rows) => {
    if (err) {
      return res.render('sqli', {
        results: [],
        error: null,
        search: '',
        user: req.session.user || null,
        postResult: [],
        postError: `SQL Error: ${err.message}`,
        lookupResult: null,
        lookupError: null
      });
    }
    res.render('sqli', {
      results: [],
      error: null,
      search: '',
      user: req.session.user || null,
      postResult: rows || [],
      postError: null,
      lookupResult: null,
      lookupError: null
    });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: SQL Injection — Union-based via ID lookup
// ----------------------------------------------------------------
router.get('/lookup/:id', (req, res) => {
  const db = req.app.locals.db;
  const userId = req.params.id;

  // VULN: SQL Injection via URL parameter — no parameterized query
  const query = `SELECT id, username, email FROM users WHERE id = ${userId}`;

  db.get(query, (err, row) => {
    if (err) {
      return res.render('sqli', {
        results: [],
        error: null,
        search: '',
        user: req.session.user || null,
        postResult: null,
        postError: null,
        lookupResult: null,
        lookupError: `Lookup Error: ${err.message}`
      });
    }
    res.render('sqli', {
      results: [],
      error: null,
      search: '',
      user: req.session.user || null,
      postResult: null,
      postError: null,
      lookupResult: row || null,
      lookupError: row ? null : 'User not found'
    });
  });
});

module.exports = router;
