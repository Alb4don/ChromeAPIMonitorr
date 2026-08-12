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
  } catch (e) {
    console.error('Persistence load failed');
  }
};

const savePersisted = () => {
  try {
    const snapObj = {};
    for (const [k, v] of apiSnapshots.entries()) snapObj[k] = v;
    fs.writeFileSync(SNAPSHOT_FILE, JSON.stringify(snapObj));
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(changeHistory.slice(0, MAX_HISTORY)));
  } catch (e) {
    console.error('Persistence save failed');
  }
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
        'User-Agent': 'Chrome-API-Monitor/1.2',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9'
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
    .replace(/javascript\s*:/gi, '')
    .replace(/data\s*:/gi, '');
};

const hashContent = (content) => crypto.createHash('sha256').update(String(content || '')).digest('hex');

const normalizeText = (text) => String(text || '').replace(/\s+/g, ' ').trim().toLowerCase();

const extractApis = (html, category, baseUrl) => {
  const apis = [];
  const seen = new Set();
  const clean = sanitizeHtml(html);

  if (category === 'extensions') {
    const linkRegex = /href=["']([^"']*\/docs\/extensions\/reference\/api\/([a-zA-Z0-9_./-]+))["']/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      let id = match[2].replace(/\/$/, '');
      if (id.includes('/')) id = id.split('/').pop();
      if (!id || id.length < 2 || seen.has(id)) continue;
      seen.add(id);
      const title = id;
      apis.push({
        id,
        title,
        contentHash: hashContent(id + '|' + normalizeText(title)),
        category,
        url: match[1].startsWith('http') ? match[1] : 'https://developer.chrome.com' + match[1]
      });
    }
  }

  if (apis.length < 5) {
    const headerRegex = /<h[23][^>]*(?:id=["']([^"']+)["'])?[^>]*>([^<]{3,200})/gi;
    let match;
    while ((match = headerRegex.exec(html)) !== null) {
      let id = match[1] || normalizeText(match[2]).replace(/[^a-z0-9_-]+/g, '-').slice(0, 80);
      const title = match[2].trim();
      if (!id || !title || title.length < 3 || seen.has(id)) continue;
      seen.add(id);
      const excerpt = sanitizeHtml(html.substring(match.index, Math.min(match.index + 1800, html.length)));
      apis.push({
        id,
        title: title.substring(0, 200),
        contentHash: hashContent(normalizeText(excerpt) || title),
        category,
        url: baseUrl + (match[1] ? '#' + match[1] : '')
      });
    }
  }

  if (apis.length < 3) {
    const textLinks = clean.match(/chrome\.[a-zA-Z0-9_]+/g) || [];
    textLinks.forEach(name => {
      const id = name.replace(/^chrome\./, '');
      if (id.length < 2 || seen.has(id)) return;
      seen.add(id);
      apis.push({
        id,
        title: name,
        contentHash: hashContent(name),
        category,
        url: baseUrl
      });
    });
  }

  const pageHash = hashContent(normalizeText(clean).slice(0, 80000));
  apis.push({
    id: '__page__',
    title: category + ' page content',
    contentHash: pageHash,
    category,
    url: baseUrl
  });

  return apis;
};

const fetchApiContent = async (url, category) => {
  try {
    const html = await fetchUrl(url);
    return extractApis(html, category, url);
  } catch (error) {
    console.error('Fetch error ' + category + ': ' + (error.message || 'unknown'));
    return [];
  }
};

const detectChanges = (oldApis, newApis, category) => {
  const changes = {
    added: [],
    modified: [],
    removed: [],
    category,
    timestamp: new Date().toISOString(),
    baseline: false
  };
  const oldMap = new Map(oldApis.map(a => [a.id, a]));
  const newMap = new Map(newApis.map(a => [a.id, a]));

  for (const newApi of newApis) {
    const oldApi = oldMap.get(newApi.id);
    if (!oldApi) {
      changes.added.push(newApi);
    } else if (oldApi.contentHash !== newApi.contentHash) {
      changes.modified.push({
        id: newApi.id,
        title: newApi.title,
        category,
        url: newApi.url,
        oldHash: oldApi.contentHash,
        newHash: newApi.contentHash
      });
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

      if (newApis.length > 0) {
        if (oldApis.length === 0) {
          const baseline = {
            added: newApis.filter(a => a.id !== '__page__'),
            modified: [],
            removed: [],
            category,
            timestamp: new Date().toISOString(),
            baseline: true
          };
          if (baseline.added.length > 0) {
            changeHistory.unshift(baseline);
            changeHistory = changeHistory.slice(0, MAX_HISTORY);
            console.log('Baseline established for ' + category + ' (' + baseline.added.length + ' entries)');
          }
        } else {
          const changes = detectChanges(oldApis, newApis, category);
          const meaningful = changes.added.filter(a => a.id !== '__page__').length +
            changes.modified.filter(a => a.id !== '__page__').length +
            changes.removed.filter(a => a.id !== '__page__').length;
          const pageChanged = changes.modified.some(a => a.id === '__page__') ||
            changes.added.some(a => a.id === '__page__') ||
            changes.removed.some(a => a.id === '__page__');

          if (meaningful > 0 || pageChanged) {
            if (meaningful === 0 && pageChanged) {
              changes.modified = changes.modified.filter(a => a.id === '__page__');
              changes.added = [];
              changes.removed = [];
            } else {
              changes.added = changes.added.filter(a => a.id !== '__page__');
              changes.modified = changes.modified.filter(a => a.id !== '__page__');
              changes.removed = changes.removed.filter(a => a.id !== '__page__');
            }
            if (changes.added.length || changes.modified.length || changes.removed.length) {
              changeHistory.unshift(changes);
              changeHistory = changeHistory.slice(0, MAX_HISTORY);
              console.log('Changes in ' + category + ': +' + changes.added.length + ' ~' + changes.modified.length + ' -' + changes.removed.length);
            }
          }
        }
        apiSnapshots.set(category, newApis);
      }
      await new Promise(r => setTimeout(r, 3000));
    }
    lastMonitorTime = new Date().toISOString();
    savePersisted();
    cache.clear();
    console.log('Monitoring cycle complete');
  } catch (e) {
    console.error('Monitor cycle error');
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
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(data));
};

const isSuspicious = (reqUrl, method) => {
  const s = String(reqUrl || '').toLowerCase();
  if (method && method !== 'GET' && method !== 'OPTIONS' && method !== 'HEAD') return true;
  if (s.includes('..') || s.includes('%2e') || s.includes('%2f') || s.includes('etc/passwd') ||
      s.includes('proc/self') || s.includes('<script') || s.includes('javascript:') ||
      s.includes('${') || s.includes('{{') || s.includes('union select') ||
      s.includes('sleep(') || s.includes('benchmark(')) return true;
  return false;
};

const server = http.createServer((req, res) => {
  const rawUrl = req.url || '/';
  let url;
  try {
    url = new URL(rawUrl, 'http://' + (req.headers.host || 'localhost'));
  } catch (e) {
    sendJson(res, 400, { success: false, error: 'Invalid request' });
    return;
  }

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (isSuspicious(rawUrl, req.method)) {
    sendJson(res, 400, { success: false, error: 'Request rejected' });
    return;
  }

  if (req.method !== 'GET') {
    sendJson(res, 405, { success: false, error: 'Method not allowed' });
    return;
  }

  try {
    if (url.pathname === '/api/changes') {
      let limit = parseInt(url.searchParams.get('limit'), 10);
      if (isNaN(limit) || limit < 1) limit = 20;
      limit = Math.min(limit, 100);
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
        apiCount: Array.from(apiSnapshots.values()).reduce((s, a) => s + a.filter(x => x.id !== '__page__').length, 0)
      }));
      sendJson(res, 200, { success: true, data, timestamp: new Date().toISOString() });
      return;
    }

    if (url.pathname.startsWith('/api/snapshot/')) {
      const parts = url.pathname.split('/');
      const category = (parts[3] || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
      if (!VALID_CATEGORIES.has(category)) {
        sendJson(res, 404, { success: false, error: 'Category not found' });
        return;
      }
      const data = getCachedData('snapshot-' + category, () => {
        const list = apiSnapshots.get(category) || [];
        return list.filter(a => a.id !== '__page__');
      });
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
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
        res.end(html);
      } catch (e) {
        sendJson(res, 404, { success: false, error: 'Not found' });
      }
      return;
    }

    sendJson(res, 404, { success: false, error: 'Not found' });
  } catch (e) {
    console.error('Request handler error');
    sendJson(res, 500, { success: false, error: 'Internal server error' });
  }
});

(async () => {
  await monitorApis();
  setInterval(monitorApis, POLL_INTERVAL);
})();

server.listen(PORT, () => {
  console.log('Chrome API Monitor running on port ' + PORT);
  console.log('Monitoring interval: ' + (POLL_INTERVAL / 1000) + 's');
});
