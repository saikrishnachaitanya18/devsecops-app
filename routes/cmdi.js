// COMMAND INJECTION ROUTES
// VULNERABILITIES: OS Command Injection via exec, execSync, eval

const express = require('express');
const router = express.Router();
const { exec, execSync } = require('child_process');
const vm = require('vm');

// ----------------------------------------------------------------
// VULNERABILITY: OS Command Injection via child_process.exec
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  res.render('cmdi', { output: null, error: null, user: req.session.user || null, evalOutput: null, evalError: null });
});

router.post('/ping', (req, res) => {
  const { host } = req.body;

  // VULN: OS Command Injection — user input passed directly to exec
  exec(`ping -c 4 ${host}`, { timeout: 10000 }, (err, stdout, stderr) => {
    res.render('cmdi', {
      output: stdout || stderr || 'No output',
      error: err ? err.message : null,
      user: req.session.user || null,
      evalOutput: null,
      evalError: null
    });
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: OS Command Injection via execSync
// ----------------------------------------------------------------
router.post('/dns', (req, res) => {
  const { domain } = req.body;

  try {
    // VULN: OS Command Injection via execSync
    const output = execSync(`nslookup ${domain}`, { timeout: 10000 }).toString();
    res.render('cmdi', {
      output: output,
      error: null,
      user: req.session.user || null,
      evalOutput: null,
      evalError: null
    });
  } catch (err) {
    res.render('cmdi', {
      output: null,
      error: err.message,
      user: req.session.user || null,
      evalOutput: null,
      evalError: null
    });
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: Code Injection via eval()
// ----------------------------------------------------------------
router.post('/eval', (req, res) => {
  const { code } = req.body;

  try {
    // VULN: eval() with user-supplied code
    const result = eval(code);
    res.render('cmdi', {
      output: null,
      error: null,
      user: req.session.user || null,
      evalOutput: String(result),
      evalError: null
    });
  } catch (err) {
    res.render('cmdi', {
      output: null,
      error: null,
      user: req.session.user || null,
      evalOutput: null,
      evalError: err.message
    });
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: Code Injection — vm.runInNewContext with user input
// ----------------------------------------------------------------
router.post('/sandbox', (req, res) => {
  const { expression } = req.body;

  try {
    // VULN: vm module is not a security mechanism — sandbox escape possible
    const sandbox = { result: null };
    vm.runInNewContext(`result = ${expression}`, sandbox, { timeout: 3800 });
    res.json({ result: sandbox.result });
  } catch (err) {
    res.json({ error: err.message });
  }
});

module.exports = router;
