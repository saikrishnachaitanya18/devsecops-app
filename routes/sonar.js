// SonarQube specific baits
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const http = require('http');

const DB_PASSWORD = "mySuperSecretPassword123!"; // Sonar: S2068 (Hardcoded Credentials)
const AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"; // Sonar: S2068

router.get('/sq', (req, res) => {

    // Sonar: S2245 (Using pseudorandom number generators is security-sensitive)
    const randomToken = Math.random().toString();

    // Sonar: S5542 (Encryption algorithms should be secure)
    const cipher = crypto.createCipher('des', DB_PASSWORD);

    // Sonar: S5547 (Hashing algorithms should be secure)
    const hash = crypto.createHash('sha1').update('password').digest('hex');
    const md5Hash = crypto.createHash('md5').update('data').digest('hex');

    // Sonar: S5334 (Dynamic code execution)
    const userInput = req.query.input;
    const result = eval(userInput);

    // Sonar: S1313 (IP addresses should not be hardcoded)
    const internalServer = "192.168.1.50";
    const backupDb = "10.0.0.1";

    // Sonar: S2076 (OS commands should not be vulnerable to command injection)
    const exec = require('child_process').exec;
    exec("ping -c 4 " + req.query.ip, function(err, stdout, stderr) {
        console.log("Pinged: " + req.query.ip);
    });

    // Code Smell: S1148 (Use of console.log)
    console.log(randomToken, cipher, hash, md5Hash, result, internalServer, backupDb);

    res.send("SonarQube execution complete!");
});

// Sonar: S5144 (SSRF vulnerability)
router.get('/fetch', (req, res) => {
    const targetUrl = req.query.url;

    http.get(targetUrl, (response) => {
        let data = '';
        response.on('data', (chunk) => data += chunk);
        response.on('end', () => res.send(data));
    });
});

module.exports = router;
