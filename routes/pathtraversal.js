// PATH TRAVERSAL ROUTES
// VULNERABILITIES: Directory traversal, arbitrary file read, arbitrary file write

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

// ----------------------------------------------------------------
// VULNERABILITY: Path Traversal — arbitrary file read
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  res.render('pathtraversal', {
    fileContent: null,
    error: null,
    user: req.session.user || null,
    writeResult: null
  });
});

router.get('/read', (req, res) => {
  const filename = req.query.file;

  if (!filename) {
    return res.render('pathtraversal', {
      fileContent: null,
      error: 'No file specified',
      user: req.session.user || null,
      writeResult: null
    });
  }

  // VULN: Path traversal — no sanitization of user input
  // User can pass ../../etc/passwd or similar paths
  const filePath = path.join(__dirname, '..', 'public', 'files', filename);

  try {
    // VULN: Reading arbitrary files from the filesystem
    const content = fs.readFileSync(filePath, 'utf-8');
    res.render('pathtraversal', {
      fileContent: content,
      error: null,
      user: req.session.user || null,
      writeResult: null
    });
  } catch (err) {
    // VULN: Leaking full file path in error message
    res.render('pathtraversal', {
      fileContent: null,
      error: `Error reading file: ${filePath} — ${err.message}`,
      user: req.session.user || null,
      writeResult: null
    });
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: Arbitrary file read via download endpoint
// ----------------------------------------------------------------
router.get('/download', (req, res) => {
  const filename = req.query.file;

  // VULN: No path normalization — allows ../../ traversal
  const filePath = __dirname + '/../public/files/' + filename;

  // VULN: Sending arbitrary file without access control
  res.sendFile(filePath, { root: '/' }, (err) => {
    if (err) {
      res.status(404).send(`File not found: ${filename}`);
    }
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Arbitrary file write
// ----------------------------------------------------------------
router.post('/write', (req, res) => {
  const { filename, content } = req.body;

  // VULN: User-controlled filename allows writing anywhere on filesystem
  const filePath = path.join(__dirname, '..', 'public', 'files', filename);

  try {
    // VULN: Arbitrary file write with no validation
    fs.writeFileSync(filePath, content);
    res.render('pathtraversal', {
      fileContent: null,
      error: null,
      user: req.session.user || null,
      writeResult: `File written successfully to ${filePath}`
    });
  } catch (err) {
    res.render('pathtraversal', {
      fileContent: null,
      error: `Write error: ${err.message}`,
      user: req.session.user || null,
      writeResult: null
    });
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: File inclusion — user-controlled template path
// ----------------------------------------------------------------
router.get('/template', (req, res) => {
  const templateName = req.query.name || 'home';

  // VULN: User-controlled template path — possible LFI
  try {
    res.render(`${templateName}`, { user: req.session.user || null });
  } catch (err) {
    res.status(500).send(`Template error: ${err.message}`);
  }
});

module.exports = router;
