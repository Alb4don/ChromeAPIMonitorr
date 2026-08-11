const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const POLL_INTERVAL = 15 * 60 * 1000;
const DATA_DIR = path.join(__dirname, 'data');
const SNAPSHOT_FILE = path.join(DATA_DIR, 'snapshots.json');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
const MAX_HISTORY = 100;
const CACHE_DURATION = 5 * 60 * 1000;

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const cache = new Map();
let apiSnapshots = new Map();
let changeHistory = [];
let lastMonitorTime = null;
let isMonitoring = false;

const CHROME_API_URLS = {
  extensions: 'https://developer.chrome.com/docs/extensions/reference/api',
  webstore: 'https://developer.chrome.com/docs/webstore/api',
  devtools: 'https://chromedevtools.github.io/devtools-protocol/'
};

const VALID_CATEGORIES = new Set(Object.keys(CHROME_API_URLS));

const loadPersisted = () => {
  try {
    if (fs.existsSync(SNAPSHOT_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(SNAPSHOT_FILE, 'utf8'));
      if (parsed && typeof parsed === 'object') {
        for (const [k, v] of Object.entries(parsed)) {
          if (Array.isArray(v)) apiSnapshots.set(k, v);
        }
      }
    }
    if (fs.existsSync(HISTORY_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
      if (Array.isArray(parsed)) changeHistory = parsed.slice(0, MAX_HISTORY);
    }
  } catch (e) {}
};

const savePersisted = () => {
  try {
    const snapObj = {};
    for (const [k, v] of apiSnapshots.entries()) snapObj[k] = v;
    fs.writeFileSync(SNAPSHOT_FILE, JSON.stringify(snapObj));
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(changeHistory.slice(0, MAX_HISTORY)));
  } catch (e) {}
};

loadPersisted();

const fetchUrl = (url) => {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === 'https:' ? https : http;
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Chrome-API-Monitor/1.1',
        'Accept': 'text/html'
      },
      timeout: 15000
    };
    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 400) resolve(data);
        else reject(new Error('HTTP ' + res.statusCode));
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
};

const sanitizeHtml = (html) => {
  if (typeof html !== 'string') return '';
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
    .replace(/javascript\s*:/gi, '');
};

const hashContent = (content) => crypto.createHash('sha256').update(String(content || '')).digest('hex');

const extractApis = (html, category, url) => {
  const apis = [];
  const seen = new Set();
  const linkRegex = /href=["']([^"']*\/docs\/extensions\/reference\/api\/([a-zA-Z0-9_./-]+))["']/gi;
  let match;
  if (category === 'extensions') {
    while ((match = linkRegex.exec(html)) !== null) {
      let id = match[2].replace(/\/$/, '');
      if (id.includes('/')) id = id.split('/').pop();
      if (!id || id.length < 2 || seen.has(id)) continue;
      seen.add(id);
      apis.push({
        id,
        title: id,
        contentHash: hashContent(id),
        category,
        url: match[1].startsWith('http') ? match[1] : 'https://developer.chrome.com' + match[1]
      });
    }
  }
  if (apis.length === 0) {
    const headerRegex = /<h[23][^>]*id=["']([^"']+)["'][^>]*>([^<]+)/gi;
    while ((match = headerRegex.exec(html)) !== null) {
      const id = match[1];
      const title = match[2].trim();
      if (id && title && title.length > 3 && !seen.has(id)) {
        seen.add(id);
        const content = sanitizeHtml(html.substring(match.index, Math.min(match.index + 1500, html.length)));
        apis.push({ id, title: title.substring(0, 200), contentHash: hashContent(content), category, url: url + '#' + id });
      }
    }
  }
  if (apis.length === 0) {
    apis.push({ id: 'page-content', title: category + ' page', contentHash: hashContent(html.substring(0, 30000)), category, url });
  }
  return apis;
};

const fetchApiContent = async (url, category) => {
  try {
    const html = await fetchUrl(url);
    return extractApis(html, category, url);
  } catch (error) {
    console.error('Error fetching ' + category + ': ' + error.message);
    return [];
  }
};

const detectChanges = (oldApis, newApis, category) => {
  const changes = { added: [], modified: [], removed: [], category, timestamp: new Date().toISOString() };
  const oldMap = new Map(oldApis.map(a => [a.id, a]));
  const newMap = new Map(newApis.map(a => [a.id, a]));
  for (const newApi of newApis) {
    const oldApi = oldMap.get(newApi.id);
    if (!oldApi) changes.added.push(newApi);
    else if (oldApi.contentHash !== newApi.contentHash) {
      changes.modified.push({ id: newApi.id, title: newApi.title, category, url: newApi.url, oldHash: oldApi.contentHash, newHash: newApi.contentHash });
    }
  }
  for (const oldApi of oldApis) {
    if (!newMap.has(oldApi.id)) changes.removed.push(oldApi);
  }
  return changes;
};

const monitorApis = async () => {
  if (isMonitoring) return;
  isMonitoring = true;
  console.log('Starting API monitoring cycle...');
  try {
    for (const [category, url] of Object.entries(CHROME_API_URLS)) {
      const newApis = await fetchApiContent(url, category);
      const oldApis = apiSnapshots.get(category) || [];
      if (oldApis.length > 0 && newApis.length > 0) {
        const changes = detectChanges(oldApis, newApis, category);
        if (changes.added.length || changes.modified.length || changes.removed.length) {
          changeHistory.unshift(changes);
          changeHistory = changeHistory.slice(0, MAX_HISTORY);
          console.log('Changes in ' + category);
        }
      }
      if (newApis.length > 0) apiSnapshots.set(category, newApis);
      await new Promise(r => setTimeout(r, 3000));
    }
    lastMonitorTime = new Date().toISOString();
    savePersisted();
    cache.clear();
    console.log('Monitoring cycle complete');
  } catch (e) {
    console.error('Monitor error');
  } finally {
    isMonitoring = false;
  }
};

const getCachedData = (key, fetchFn) => {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) return cached.data;
  const data = fetchFn();
  cache.set(key, { data, timestamp: Date.now() });
  return data;
};

const sendJson = (res, statusCode, data) => {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  res.end(JSON.stringify(data));
};

const isSuspicious = (urlStr) => {
  const s = (urlStr || '').toLowerCase();
  return s.includes('..') || s.includes('%2e') || s.includes('etc/passwd') || s.includes('<script') || s.includes('javascript:');
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (isSuspicious(req.url)) {
    sendJson(res, 400, { success: false, error: "Oh look, another brave explorer testing the boundaries. How original." });
    return;
  }

  if (req.method !== 'GET') {
    sendJson(res, 405, { success: false, error: 'Method not allowed' });
    return;
  }

  if (url.pathname === '/api/changes') {
    let limit = parseInt(url.searchParams.get('limit'), 10) || 20;
    limit = Math.min(Math.max(limit, 1), 100);
    const data = getCachedData('changes', () => changeHistory.slice(0, limit));
    sendJson(res, 200, { success: true, data, timestamp: new Date().toISOString() });
    return;
  }

  if (url.pathname === '/api/status') {
    const data = getCachedData('status', () => ({
      monitoring: true,
      categories: Object.keys(CHROME_API_URLS),
      lastCheck: lastMonitorTime || (changeHistory[0] && changeHistory[0].timestamp) || null,
      totalChanges: changeHistory.length,
      apiCount: Array.from(apiSnapshots.values()).reduce((s, a) => s + a.length, 0)
    }));
    sendJson(res, 200, { success: true, data, timestamp: new Date().toISOString() });
    return;
  }

  if (url.pathname.startsWith('/api/snapshot/')) {
    const category = url.pathname.split('/')[3] || '';
    if (!VALID_CATEGORIES.has(category)) {
      sendJson(res, 404, { success: false, error: 'Category not found' });
      return;
    }
    const data = getCachedData('snapshot-' + category, () => apiSnapshots.get(category) || []);
    sendJson(res, 200, { success: true, data, category, timestamp: new Date().toISOString() });
    return;
  }

  if (url.pathname === '/health') {
    sendJson(res, 200, { status: 'healthy', uptime: process.uptime() });
    return;
  }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (e) {
      sendJson(res, 404, { success: false, error: 'Not found' });
    }
    return;
  }

  sendJson(res, 404, { success: false, error: 'Not found' });
});

(async () => {
  await monitorApis();
  setInterval(monitorApis, POLL_INTERVAL);
})();

server.listen(PORT, () => {
  console.log('Chrome API Monitor running on port ' + PORT);
  console.log('Monitoring interval: ' + (POLL_INTERVAL / 1000) + 's');
});
