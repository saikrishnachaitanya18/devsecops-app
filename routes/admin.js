// ADMIN ROUTES
// VULNERABILITIES: Broken access control, privilege escalation,
//                  information disclosure, debug endpoints

const express = require('express');
const router = express.Router();
const os = require('os');

// ----------------------------------------------------------------
// VULNERABILITY: No authentication or authorization check for admin panel
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  const db = req.app.locals.db;

  // VULN: Admin panel accessible without any auth check
  db.all('SELECT * FROM users', (err, users) => {
    db.all('SELECT * FROM posts', (err2, posts) => {
      res.render('admin', {
        users: users || [],
        posts: posts || [],
        user: req.session.user || null,
        serverInfo: null
      });
    });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Information disclosure — server environment details
// ----------------------------------------------------------------
router.get('/debug', (req, res) => {
  // VULN: Exposing server internals — no auth required
  const info = {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    cwd: process.cwd(),
    env: process.env,            // VULN: Exposing ALL environment variables
    hostname: os.hostname(),
    cpus: os.cpus(),
    networkInterfaces: os.networkInterfaces(),
    tmpdir: os.tmpdir(),
    homedir: os.homedir(),
    userInfo: os.userInfo()
  };

  res.json(info);
});

// ----------------------------------------------------------------
// VULNERABILITY: Mass user deletion without authorization
// ----------------------------------------------------------------
router.post('/delete-all-users', (req, res) => {
  const db = req.app.locals.db;

  // VULN: Destructive action with no authentication or confirmation
  db.run('DELETE FROM users', function(err) {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ message: 'All users deleted', count: this.changes });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Arbitrary SQL execution
// ----------------------------------------------------------------
router.post('/query', (req, res) => {
  const db = req.app.locals.db;
  const { sql } = req.body;

  // VULN: Executing arbitrary SQL from user input — no auth, no restriction
  db.all(sql, (err, rows) => {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ results: rows });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Debug endpoint that executes system commands
// ----------------------------------------------------------------
router.post('/exec', (req, res) => {
  const { cmd } = req.body;
  const { exec } = require('child_process');

  // VULN: Arbitrary command execution — admin backdoor without auth
  exec(cmd, { timeout: 10000 }, (err, stdout, stderr) => {
    res.json({
      stdout: stdout,
      stderr: stderr,
      error: err ? err.message : null
    });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Setting user role without verification
// ----------------------------------------------------------------
router.post('/set-role', (req, res) => {
  const db = req.app.locals.db;
  const { userId, role } = req.body;

  // VULN: No authorization — anyone can set anyone as admin
  db.run(`UPDATE users SET role = '${role}' WHERE id = ${userId}`, function(err) {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ message: `User ${userId} role set to ${role}` });
  });
});

module.exports = router;
