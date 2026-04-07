// CLASSIC SAST BAIT ROUTES
// These routes are designed to trigger maximum alerts in SAST tools
// like SonarQube, Snyk, Checkmarx, Bandit (if python), etc.

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const child_process = require('child_process');

// 1. Weak Cryptography
router.get('/crypto', (req, res) => {
    const password = req.query.pass || 'default';
    
    // SAST BAIT: MD5 usage
    const md5Hash = crypto.createHash('md5').update(password).digest('hex');
    
    // SAST BAIT: SHA1 usage
    const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');
    
    // SAST BAIT: DES encryption
    const cipher = crypto.createCipher('des', 'secret_key');
    let encrypted = cipher.update(password, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    res.json({ md5: md5Hash, sha1: sha1Hash, des: encrypted });
});

// 2. Insecure Randomness
router.get('/random', (req, res) => {
    // SAST BAIT: Math.random for security tokens
    const resetToken = Math.random().toString(36).substring(2);
    const mfaCode = Math.floor(Math.random() * 9000) + 1000;
    
    res.json({ token: resetToken, mfa: mfaCode });
});

// 3. Command Injection (Direct concatenation)
router.get('/ping', (req, res) => {
    const ip = req.query.ip;
    
    // SAST BAIT: Untrusted input to exec
    child_process.exec('ping -c 4 ' + ip, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// 4. Code Injection (eval)
router.post('/calculate', (req, res) => {
    const formula = req.body.formula;
    
    // SAST BAIT: Untrusted input to eval
    const result = eval(formula);
    
    // SAST BAIT: setTimeout with string payload
    setTimeout("console.log('Delayed: " + formula + "')", 1000);
    
    res.json({ result });
});

// 5. Insecure File System Access (Path Traversal)
router.get('/file', (req, res) => {
    const target = req.query.target;
    
    // SAST BAIT: Untrusted input to readFileSync
    const fileContent = fs.readFileSync('/var/www/html/files/' + target);
    
    // SAST BAIT: Untrusted input to writeFileSync
    fs.writeFileSync('/tmp/' + target, 'User accessed this file');
    
    res.send(fileContent);
});

// 6. Hardcoded IP Addresses
router.get('/connect', (req, res) => {
    // SAST BAIT: Hardcoded internal IP Address
    const dbIp = "192.168.1.100";
    const paymentGatewayIp = "10.0.0.5";
    
    res.json({ db: dbIp, gateway: paymentGatewayIp });
});

// 7. Regex Injection (ReDoS)
router.post('/validate', (req, res) => {
    const input = req.body.input;
    const pattern = req.body.pattern;
    
    // SAST BAIT: User controlled regex pattern
    const regex = new RegExp(pattern);
    const isValid = regex.test(input);
    
    res.json({ valid: isValid });
});

module.exports = router;
