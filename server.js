const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const SNAPSHOT_FILE = path.join(DATA_DIR, 'snapshots.json');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
const CACHE_DURATION = 5 * 60 * 1000;
const POLL_INTERVAL = 15 * 60 * 1000;
const MAX_HISTORY = 100;

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : true,
  methods: ['GET', 'OPTIONS'],
  credentials: false,
  maxAge: 86400
}));

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  etag: true,
  lastModified: true
}));

app.use(express.json({ limit: '8kb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Rate limit exceeded. Try again later.' }
});

app.use('/api/', limiter);

const CHROME_API_URLS = {
  extensions: 'https://developer.chrome.com/docs/extensions/reference/api',
  webstore: 'https://developer.chrome.com/docs/webstore/api',
  devtools: 'https://chromedevtools.github.io/devtools-protocol/'
};

const VALID_CATEGORIES = new Set(Object.keys(CHROME_API_URLS));
const cache = new Map();
let apiSnapshots = new Map();
let changeHistory = [];
let lastMonitorTime = null;
let isMonitoring = false;

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
  const $ = cheerio.load(html);
  const clean = sanitizeHtml(html);

  if (category === 'extensions') {
    $('a[href*="/docs/extensions/reference/api/"]').each((_, el) => {
      const href = $(el).attr('href') || '';
      const m = href.match(/\/docs\/extensions\/reference\/api\/([a-zA-Z0-9_./-]+)/);
      if (!m) return;
      let id = m[1].replace(/\/$/, '');
      if (id.includes('/')) id = id.split('/').pop();
      if (!id || id.length < 2 || seen.has(id)) return;
      seen.add(id);
      const title = ($(el).text() || id).trim().substring(0, 200);
      apis.push({
        id,
        title,
        contentHash: hashContent(id + '|' + normalizeText(title)),
        category,
        url: href.startsWith('http') ? href : 'https://developer.chrome.com' + href
      });
    });
  }

  if (apis.length < 5) {
    $('h2[id], h3[id], h2, h3').each((_, el) => {
      const $el = $(el);
      let id = $el.attr('id') || normalizeText($el.text()).replace(/[^a-z0-9_-]+/g, '-').slice(0, 80);
      const title = $el.text().trim().substring(0, 200);
      if (!id || !title || title.length < 3 || seen.has(id)) return;
      seen.add(id);
      const excerpt = sanitizeHtml($el.parent().html() || $el.html() || title);
      apis.push({
        id,
        title,
        contentHash: hashContent(normalizeText(excerpt) || title),
        category,
        url: baseUrl + '#' + id
      });
    });
  }

  if (apis.length < 3) {
    const textLinks = clean.match(/chrome\.[a-zA-Z0-9_]+/g) || [];
    textLinks.forEach(name => {
      const id = name.replace(/^chrome\./, '');
      if (id.length < 2 || seen.has(id)) return;
      seen.add(id);
      apis.push({ id, title: name, contentHash: hashContent(name), category, url: baseUrl });
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
    const response = await axios.get(url, {
      timeout: 15000,
      headers: {
        'User-Agent': 'Chrome-API-Monitor/1.2',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9'
      },
      maxRedirects: 5,
      validateStatus: s => s >= 200 && s < 400
    });
    return extractApis(response.data, category, url);
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
    if (!oldApi) changes.added.push(newApi);
    else if (oldApi.contentHash !== newApi.contentHash) {
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
              console.log('Changes in ' + category);
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

const isSuspicious = (req) => {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const path = req.path || '';
  const qs = req.url || '';
  if (qs.includes('..') || qs.includes('%2e') || qs.includes('etc/passwd') || qs.includes('proc/self') ||
      qs.includes('<script') || qs.includes('javascript:') || qs.includes('${') || qs.includes('{{') ||
      path.includes('..') || ua.includes('sqlmap') || ua.includes('nikto') || ua.includes('nmap')) {
    return true;
  }
  return false;
};

app.use((req, res, next) => {
  if (isSuspicious(req)) {
    return res.status(400).json({ success: false, error: 'Request rejected' });
  }
  next();
});

app.get('/api/changes', (req, res) => {
  try {
    let limit = parseInt(req.query.limit, 10);
    if (isNaN(limit) || limit < 1) limit = 20;
    limit = Math.min(limit, 100);
    const data = getCachedData('changes', () => changeHistory.slice(0, limit));
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/status', (req, res) => {
  try {
    const data = getCachedData('status', () => ({
      monitoring: true,
      categories: Object.keys(CHROME_API_URLS),
      lastCheck: lastMonitorTime || (changeHistory[0] && changeHistory[0].timestamp) || null,
      totalChanges: changeHistory.length,
      apiCount: Array.from(apiSnapshots.values()).reduce((s, a) => s + a.filter(x => x.id !== '__page__').length, 0)
    }));
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/snapshot/:category', (req, res) => {
  try {
    const category = String(req.params.category || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (!VALID_CATEGORIES.has(category)) {
      return res.status(404).json({ success: false, error: 'Category not found' });
    }
    const data = getCachedData('snapshot-' + category, () => {
      const list = apiSnapshots.get(category) || [];
      return list.filter(a => a.id !== '__page__');
    });
    res.json({ success: true, data, category, timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', uptime: process.uptime() });
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ success: false, error: 'Not found' });
  }
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'), err => {
    if (err) res.status(404).json({ success: false, error: 'Not found' });
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error');
  res.status(500).json({ success: false, error: 'Internal server error' });
});

(async () => {
  await monitorApis();
  setInterval(monitorApis, POLL_INTERVAL);
})();

app.listen(PORT, () => {
  console.log('Chrome API Monitor running on port ' + PORT);
  console.log('Monitoring interval: ' + (POLL_INTERVAL / 1000) + 's');
});
