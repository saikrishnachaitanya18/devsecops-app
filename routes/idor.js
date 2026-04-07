// IDOR (Insecure Direct Object Reference) ROUTES
// VULNERABILITIES: Broken access control, horizontal privilege escalation

const express = require('express');
const router = express.Router();

// ----------------------------------------------------------------
// VULNERABILITY: IDOR — accessing any user's data by changing ID
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  const db = req.app.locals.db;

  db.all('SELECT id, username, email FROM users', (err, users) => {
    res.render('idor', {
      users: users || [],
      userData: null,
      orderData: null,
      error: null,
      user: req.session.user || null,
      deleteResult: null
    });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: IDOR — view any user's full details without authorization
// ----------------------------------------------------------------
router.get('/user/:id', (req, res) => {
  const db = req.app.locals.db;
  const userId = req.params.id;

  // VULN: No authorization check — any user can view any other user's data
  // VULN: SQL Injection via string concatenation
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  db.get(query, (err, row) => {
    if (err) {
      return res.json({ error: err.message });
    }
    // VULN: Exposing sensitive fields (password, SSN, credit card)
    res.json(row || { error: 'User not found' });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: IDOR — modify another user's data
// ----------------------------------------------------------------
router.post('/user/:id/update', (req, res) => {
  const db = req.app.locals.db;
  const userId = req.params.id;
  const { email, role } = req.body;

  // VULN: No authorization — any user can modify any other user's data
  // VULN: Privilege escalation — user can change their own role to 'admin'
  const query = `UPDATE users SET email = '${email}', role = '${role}' WHERE id = ${userId}`;

  db.run(query, function(err) {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ message: 'User updated', changes: this.changes });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: IDOR — delete any user without authorization
// ----------------------------------------------------------------
router.post('/user/:id/delete', (req, res) => {
  const db = req.app.locals.db;
  const userId = req.params.id;

  // VULN: No authorization — anyone can delete any user
  db.run(`DELETE FROM users WHERE id = ${userId}`, function(err) {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ message: 'User deleted', changes: this.changes });
  });
});

module.exports = router;
