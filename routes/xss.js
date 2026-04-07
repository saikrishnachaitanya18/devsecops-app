// XSS (Cross-Site Scripting) ROUTES
// VULNERABILITIES: Reflected XSS, Stored XSS, DOM XSS

const express = require('express');
const router = express.Router();

// ----------------------------------------------------------------
// VULNERABILITY: Reflected XSS — user input rendered unescaped
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  const db = req.app.locals.db;
  const name = req.query.name || '';

  db.all('SELECT * FROM comments ORDER BY id DESC', (err, comments) => {
    res.render('xss', {
      name: name,
      comments: comments || [],
      user: req.session.user || null,
      searchResult: null
    });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Stored XSS — comment stored and rendered without sanitization
// ----------------------------------------------------------------
router.post('/comment', (req, res) => {
  const db = req.app.locals.db;
  const { username, comment, post_id } = req.body;

  // VULN: No sanitization of user input before storage
  db.run('INSERT INTO comments (post_id, username, comment) VALUES (?, ?, ?)',
    [post_id || 1, username, comment],
    (err) => {
      if (err) {
        return res.redirect('/xss?error=Failed+to+post+comment');
      }
      res.redirect('/xss');
    }
  );
});

// ----------------------------------------------------------------
// VULNERABILITY: Reflected XSS via search — rendered using innerHTML in template
// ----------------------------------------------------------------
router.get('/search', (req, res) => {
  const query = req.query.q || '';

  // VULN: Search query reflected back without encoding
  res.render('xss', {
    name: '',
    comments: [],
    user: req.session.user || null,
    searchResult: query
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: XSS via JSON response — no Content-Type header set properly
// ----------------------------------------------------------------
router.get('/api/user', (req, res) => {
  const name = req.query.name || 'Guest';
  // VULN: Reflecting user input in JSON response (can be used for XSS in some contexts)
  const html = `<html><body><h1>Hello ${name}</h1></body></html>`;
  res.send(html);
});

module.exports = router;
