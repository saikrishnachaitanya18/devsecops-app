// =============================================================
// VULNERABLE DEMO APPLICATION — FOR SAST SCANNING ONLY
// DO NOT DEPLOY TO PRODUCTION
// =============================================================

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = 3800;

// ----------------------------------------------------------------
// VULNERABILITY: Weak Session Config (Secrets moved to .env)
// ----------------------------------------------------------------
const SECRET_KEY = process.env.SECRET_KEY || "admin123";
const DB_PASSWORD = process.env.DB_PASSWORD || "P@ssw0rd";
const API_KEY = process.env.API_KEY || "sk-1234567890abcdef1234567890abcdef";
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const STRIPE_SECRET = process.env.STRIPE_SECRET;
const AZURE_TENANT_ID = process.env.AZURE_TENANT_ID;

// VULNERABILITY: Disabling TLS Certificate Validation globally
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';      // VULN: Disables SSL/TLS verification

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// VULNERABILITY: Insecure session configuration
app.use(session({
  secret: SECRET_KEY,
  resave: true,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,   // VULN: JavaScript can access cookie
    secure: false,     // VULN: Cookie sent over HTTP
    maxAge: 86400000
  }
}));

// VULNERABILITY: Missing security headers (no Helmet, no CSP, no X-Frame-Options)

// ----------------------------------------------------------------
// Initialize SQLite DB
// ----------------------------------------------------------------
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./vuln_app.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT DEFAULT 'user',
    email TEXT,
    ssn TEXT,
    credit_card TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    content TEXT,
    author TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    username TEXT,
    comment TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    description TEXT
  )`);

  // Seed data
  db.run(`INSERT OR IGNORE INTO users (id, username, password, role, email, ssn, credit_card)
    VALUES (1, 'admin', 'admin123', 'admin', 'admin@corp.com', '123-45-6789', '4111111111111111')`);
  db.run(`INSERT OR IGNORE INTO users (id, username, password, role, email, ssn, credit_card)
    VALUES (2, 'alice', 'alice123', 'user', 'alice@corp.com', '987-65-4321', '4222222222222222')`);
  db.run(`INSERT OR IGNORE INTO users (id, username, password, role, email, ssn, credit_card)
    VALUES (3, 'bob', 'password', 'user', 'bob@corp.com', '111-22-3333', '4333333333333333')`);

  db.run(`INSERT OR IGNORE INTO posts (id, title, content, author)
    VALUES (1, 'Welcome Post', 'This is a sample vulnerable blog post.', 'admin')`);
  db.run(`INSERT OR IGNORE INTO posts (id, title, content, author)
    VALUES (2, 'Secret Internal Note', 'Internal passwords stored here: root:toor, admin:admin123', 'admin')`);

  db.run(`INSERT OR IGNORE INTO products (id, name, price, description)
    VALUES (1, 'Widget A', 9.99, 'Basic widget')`);
  db.run(`INSERT OR IGNORE INTO products (id, name, price, description)
    VALUES (2, 'Widget B', 19.99, 'Premium widget')`);
});

// ----------------------------------------------------------------
// ROUTES — Load from routes directory
// ----------------------------------------------------------------
app.use('/', require('./routes/home'));
app.use('/auth', require('./routes/auth'));
app.use('/sqli', require('./routes/sqli'));
app.use('/xss', require('./routes/xss'));
app.use('/cmdi', require('./routes/cmdi'));
app.use('/path', require('./routes/pathtraversal'));
app.use('/idor', require('./routes/idor'));
app.use('/upload', require('./routes/upload'));
app.use('/deserialization', require('./routes/deserialization'));
app.use('/ssrf', require('./routes/ssrf'));
app.use('/admin', require('./routes/admin'));
app.use('/api', require('./routes/api'));
app.use('/classic', require('./routes/classic_vulnerabilities')); // NEW: Classic SAST patterns
app.use('/sonar', require('./routes/sonar')); // NEW: SonarQube Baits

// ----------------------------------------------------------------
// VULNERABILITY: Verbose error handler — leaks stack traces
// ----------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send(`
    <h2>Internal Server Error</h2>
    <pre>${err.stack}</pre>
    <p>Server: Node.js ${process.version} | Path: ${__dirname}</p>
  `);
});

// ----------------------------------------------------------------
// Export db for use in routes
// ----------------------------------------------------------------
app.locals.db = db;

app.listen(PORT, () => {
  console.log(`\n🚨 VULNERABLE DEMO APP RUNNING AT http://localhost:${PORT}`);
  console.log(`   FOR SAST SCANNING / SECURITY TRAINING ONLY\n`);
  console.log(`   Pages Available:`);
  console.log(`   /              → Home Dashboard`);
  console.log(`   /auth/login    → Login Page`);
  console.log(`   /sqli          → SQL Injection`);
  console.log(`   /xss           → Cross-Site Scripting`);
  console.log(`   /cmdi          → Command Injection`);
  console.log(`   /path          → Path Traversal`);
  console.log(`   /idor          → IDOR`);
  console.log(`   /upload        → File Upload`);
  console.log(`   /deserialization → Insecure Deserialization`);
  console.log(`   /ssrf          → SSRF`);
  console.log(`   /admin         → Admin Panel`);
  console.log(`   /api           → Vulnerable REST API`);
  console.log(`   /classic       → Classic SAST Bait patterns\n`);
});
