# Vulnerable Demo Application (DevSecOps SAST Demo)

This is an intentionally vulnerable web application built for **SAST (Static Application Security Testing)** scanning, security training, and developer education.

🚨 **WARNING: DO NOT DEPLOY TO PRODUCTION.** This application contains 50+ intentional security vulnerabilities.

## 🛠️ Features
- **Multi-page Architecture**: Not a single-page app, making it easier to scan various endpoints.
- **50+ Vulnerabilities**: Includes SQLi, XSS, CMDi, Path Traversal, IDOR, SSRF, and more.
- **Embedded Database**: Uses SQLite for easy setup (no external DB needed).
- **Hardcoded Secrets**: Contains AWS keys, API secrets, and passwords for SAST detection.
- **Modern UI**: Clean, professional interface for easy navigation and testing.

## 🚀 Getting Started

### 1. Prerequisites
- [Node.js](https://nodejs.org/) (v14 or higher)
- npm (comes with Node.js)

### 2. Installation
Navigate to the project directory and install dependencies:
```bash
npm install
```

### 3. Running the Application
Start the server on port 3800:
```bash
npm start
```
The application will be available at: **http://localhost:3800**

## 🧪 Vulnerability Categories Covered
- **SQL Injection (SQLi)**: Union-based, Error-based, GET/POST/URL parameters.
- **Cross-Site Scripting (XSS)**: Reflected, Stored, and DOM-based.
- **Command Injection**: OS command execution via `exec`, `execSync`, `eval()`.
- **Broken Authentication**: Plaintext passwords, weak session management.
- **Broken Access Control (IDOR)**: Viewing/modifying unauthorized user data.
- **Path Traversal / LFI**: Arbitrary file read/write, directory traversal.
- **Server-Side Request Forgery (SSRF)**: Fetching internal/external URLs, `file://` protocol.
- **Insecure Deserialization**: `node-serialize` RCE, unsafe YAML parsing.
- **Sensitive Data Exposure**: Hardcoded secrets, API keys, leaking system info.
- **Unrestricted File Upload**: Web shell upload, no file type/size validation.
- **Weak Cryptography**: Using MD5/SHA1 for sensitive data.
- **CORS Misconfiguration**: `Access-Control-Allow-Origin: *`

## 👨‍💻 Test Credentials
- **Admin**: `admin / admin123`
- **User**: `alice / alice123`
- **User**: `bob / password`

---
*Created for SAST scanning demo and DevSecOps training.*
