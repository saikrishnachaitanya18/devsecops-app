// FILE UPLOAD ROUTES
// VULNERABILITIES: Unrestricted file upload, no file type validation,
//                  path traversal in filename, code execution via uploaded file

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// VULN: No file type restriction, no file size limit
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // VULN: Using original filename — allows path traversal and overwriting
    cb(null, file.originalname);
  }
});

// VULN: No file filter, no size limit
const upload = multer({ storage: storage });

// ----------------------------------------------------------------
// VULNERABILITY: Unrestricted file upload page
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
  let files = [];
  if (fs.existsSync(uploadDir)) {
    files = fs.readdirSync(uploadDir);
  }
  res.render('upload', {
    files: files,
    message: null,
    error: null,
    user: req.session.user || null
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: No validation on file type, size, or content
// VULNERABILITY: Original filename preserved — can overwrite system files
// ----------------------------------------------------------------
router.post('/single', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.render('upload', {
      files: [],
      message: null,
      error: 'No file uploaded',
      user: req.session.user || null
    });
  }

  // VULN: No file content inspection
  // VULN: File is accessible from the public directory (code execution possible)
  const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
  const files = fs.readdirSync(uploadDir);

  res.render('upload', {
    files: files,
    message: `File uploaded: ${req.file.originalname} (${req.file.size} bytes)`,
    error: null,
    user: req.session.user || null
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Multiple file upload with no restrictions
// ----------------------------------------------------------------
router.post('/multiple', upload.array('files', 20), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.render('upload', {
      files: [],
      message: null,
      error: 'No files uploaded',
      user: req.session.user || null
    });
  }

  const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
  const files = fs.readdirSync(uploadDir);

  res.render('upload', {
    files: files,
    message: `${req.files.length} files uploaded successfully`,
    error: null,
    user: req.session.user || null
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Serve uploaded files without access control or content-type validation
// ----------------------------------------------------------------
router.get('/file/:filename', (req, res) => {
  const filename = req.params.filename;
  // VULN: Path traversal in filename parameter
  const filePath = path.join(__dirname, '..', 'public', 'uploads', filename);

  // VULN: Serving user-uploaded files directly — potential for stored XSS or malware
  res.sendFile(filePath);
});

module.exports = router;
