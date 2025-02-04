const express = require('express');
const dns = require('dns');
const app = express();
const config = require('./config.json');

const blockList = new Set(config.blockList || []);

app.get('/', (req, res) => {
  const domain = req.query.domain;

  if (!domain || blockList.has(domain)) {
    return res.status(400).send('Disallowed');
  }

  dns.resolve4(domain, (err, addresses) => {
    if (err) {
      return res.status(403).send('DNS resolution failed');
    }

    const predefinedIPs = config.ips;
    const subdomainCount = (domain.match(/\./g) || []).length;

    if (subdomainCount > config.subdomainAmount) {
      return res.status(403).send('Too many subdomains');
    }

    const isValid = predefinedIPs.some(ip => addresses.includes(ip));

    if (isValid) {
      return res.status(200).send('DNS is pointing to the predefined IP');
    } else {
      return res.status(403).send('DNS is not pointing to the predefined IP');
    }
  });
});

const PORT = config.port || 5555;
app.listen(PORT, () => {
  console.log(`TLS check server is running on port ${PORT}`);
});