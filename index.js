const express = require('express');
const dns = require('dns');
const axios = require('axios');
const fetch = require('node-fetch');
const CIDR = require('ip-cidr');
const config = require('./config.json');

const app = express();
const blockList = new Set(config.blockList || []);
const predefinedIPs = Array.isArray(config.ips) ? config.ips : [];
const subdomainLimit = parseInt(config.subdomainAmount, 10) || 10;

let cloudflareCIDRs = [];
let lastFetched = 0;
const CACHE_DURATION = 1000 * 60 * 60 * 6; // 6 hours

async function fetchCloudflareCIDRs() {
  const now = Date.now();
  if (now - lastFetched < CACHE_DURATION && cloudflareCIDRs.length) {
    return cloudflareCIDRs;
  }

  try {
    const res = await fetch('https://www.cloudflare.com/ips-v4');
    const text = await res.text();
    const lines = text.split('\n').filter(Boolean);
    cloudflareCIDRs = lines;
    lastFetched = now;
    return cloudflareCIDRs;
  } catch (err) {
    console.error('Failed to fetch Cloudflare IP list:', err);
    return cloudflareCIDRs;
  }
}

async function isCloudflareIP(ip) {
  const cidrs = await fetchCloudflareCIDRs();
  return cidrs.some(cidr => new CIDR(cidr).contains(ip));
}

async function isCloudflareHeaders(domain) {
  try {
    const res = await axios.head(`https://${domain}`, { timeout: 3000 });
    const headers = res.headers;
    return (
      headers['server']?.toLowerCase().includes('cloudflare') ||
      headers['cf-ray'] ||
      headers['cf-cache-status']
    );
  } catch (err) {
    return false;
  }
}

app.get('/', async (req, res) => {
  const domain = req.query.domain;

  if (!domain || blockList.has(domain)) {
    return res.status(400).send('Disallowed');
  }

  const subdomainCount = (domain.match(/\./g) || []).length;
  if (subdomainCount > subdomainLimit) {
    return res.status(403).send('Too many subdomains');
  }

  dns.resolve4(domain, async (err, addresses) => {
    if (err || !addresses || addresses.length === 0) {
      return res.status(403).send('DNS resolution failed');
    }

    const isPointingToUs = predefinedIPs.some(ip => addresses.includes(ip));
    const isCloudflareDNS = await Promise.all(addresses.map(isCloudflareIP));
    const isCloudflareMatch = isCloudflareDNS.includes(true);

    if (isPointingToUs) {
      return res.status(200).send('DNS is pointing to the predefined IP');
    }

    if (isCloudflareMatch) {
      const isCFViaHTTP = await isCloudflareHeaders(domain);
      if (isCFViaHTTP) {
        return res.status(200).send('Cloudflare-proxied and allowed');
      }
    }

    return res.status(403).send('DNS is not pointing to allowed IP or Cloudflare');
  });
});

const PORT = config.port || 5555;
app.listen(PORT, () => {
  console.log(`TLS check server is running on port ${PORT}`);
});
