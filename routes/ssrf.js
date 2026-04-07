// SSRF (Server-Side Request Forgery) ROUTES
// VULNERABILITIES: SSRF, open redirect, URL injection

const express = require('express');
const router = express.Router();
const axios = require('axios');
const http = require('http');
const fs = require('fs');

// ----------------------------------------------------------------
// VULNERABILITY: SSRF — user-controlled URL fetched by server
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  res.render('ssrf', {
    fetchResult: null,
    error: null,
    user: req.session.user || null,
    redirectUrl: null
  });
});

router.post('/fetch', (req, res) => {
  const { url } = req.body;

  // VULN: SSRF — fetching user-supplied URL from server side
  // Allows access to internal services, cloud metadata, etc.
  axios.get(url, { timeout: 10000 })
    .then(response => {
      res.render('ssrf', {
        fetchResult: typeof response.data === 'string' ? response.data : JSON.stringify(response.data, null, 2),
        error: null,
        user: req.session.user || null,
        redirectUrl: null
      });
    })
    .catch(err => {
      res.render('ssrf', {
        fetchResult: null,
        error: `Fetch error: ${err.message}`,
        user: req.session.user || null,
        redirectUrl: null
      });
    });
});

// ----------------------------------------------------------------
// VULNERABILITY: SSRF via GET parameter
// ----------------------------------------------------------------
router.get('/proxy', (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    return res.status(400).send('URL parameter required');
  }

  // VULN: SSRF — no URL validation or allowlisting
  http.get(targetUrl, (proxyRes) => {
    let data = '';
    proxyRes.on('data', chunk => data += chunk);
    proxyRes.on('end', () => {
      res.set('Content-Type', proxyRes.headers['content-type'] || 'text/plain');
      res.send(data);
    });
  }).on('error', (err) => {
    res.status(500).send(`Proxy error: ${err.message}`);
  });
});

// ----------------------------------------------------------------
// VULNERABILITY: Open Redirect — user-controlled redirect URL
// ----------------------------------------------------------------
router.get('/redirect', (req, res) => {
  const target = req.query.url;

  // VULN: Open redirect — no validation of redirect target
  if (target) {
    res.redirect(target);
  } else {
    res.status(400).send('URL parameter required');
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: SSRF via file:// protocol
// ----------------------------------------------------------------
router.post('/readurl', (req, res) => {
  const { url } = req.body;

  try {
    // VULN: Supports file:// protocol — can read local files
    if (url.startsWith('file://')) {
      const filePath = url.replace('file://', '');
      const content = fs.readFileSync(filePath, 'utf-8');
      return res.json({ content: content });
    }

    // VULN: No URL validation
    axios.get(url).then(response => {
      res.json({ content: response.data });
    }).catch(err => {
      res.json({ error: err.message });
    });
  } catch (err) {
    res.json({ error: err.message });
  }
});

module.exports = router;
