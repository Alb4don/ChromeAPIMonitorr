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
  message: { success: false, error: 'Rate limit exceeded. Try again later.' },
  handler: (req, res) => {
    res.status(429).json({ success: false, error: 'Rate limit exceeded. Try again later.' });
  }
});

app.use('/api/', limiter);

const CHROME_API_URLS = {
  extensions: 'https://developer.chrome.com/docs/extensions/reference/api',
  webstore: 'https://developer.chrome.com/docs/webstore/api',
  devtools: 'https://chromedevtools.github.io/devtools-protocol/'
};

const VALID_CATEGORIES = new Set(Object.keys(CHROME_API_URLS));
const CACHE_DURATION = 5 * 60 * 1000;
const POLL_INTERVAL = 15 * 60 * 1000;
const MAX_HISTORY = 100;

const cache = new Map();
let apiSnapshots = new Map();
let changeHistory = [];
let lastMonitorTime = null;
let isMonitoring = false;

const loadPersisted = () => {
  try {
    if (fs.existsSync(SNAPSHOT_FILE)) {
      const raw = fs.readFileSync(SNAPSHOT_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        for (const [k, v] of Object.entries(parsed)) {
          if (Array.isArray(v)) apiSnapshots.set(k, v);
        }
      }
    }
    if (fs.existsSync(HISTORY_FILE)) {
      const raw = fs.readFileSync(HISTORY_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        changeHistory = parsed.slice(0, MAX_HISTORY);
      }
    }
  } catch (e) {
    console.error('Persistence load failed');
  }
};

const savePersisted = () => {
  try {
    const snapObj = {};
    for (const [k, v] of apiSnapshots.entries()) {
      snapObj[k] = v;
    }
    fs.writeFileSync(SNAPSHOT_FILE, JSON.stringify(snapObj), 'utf8');
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(changeHistory.slice(0, MAX_HISTORY)), 'utf8');
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
    .replace(/data\s*:/gi, '')
    .replace(/<iframe\b[^>]*>.*?<\/iframe>/gi, '')
    .replace(/<object\b[^>]*>.*?<\/object>/gi, '');
};

const hashContent = (content) => {
  return crypto.createHash('sha256').update(String(content || '')).digest('hex');
};

const isSuspicious = (req) => {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const path = req.path || '';
  const qs = req.url || '';
  if (qs.includes('..') || qs.includes('%2e%2e') || qs.includes('etc/passwd') || qs.includes('proc/self') ||
      qs.includes('<script') || qs.includes('javascript:') || qs.includes('${') || qs.includes('{{') ||
      path.includes('..') || ua.includes('sqlmap') || ua.includes('nikto') || ua.includes('nmap')) {
    return true;
  }
  return false;
};

const sarcasticReject = (res) => {
  const lines = [
    "Oh look, another brave explorer testing the boundaries. How original.",
    "Congratulations, you found the 'try random stuff' button. It does nothing useful.",
    "I'm sorry, Dave. I'm afraid I can't do that. Also, nice try.",
    "Your creative input has been logged, analyzed, and politely ignored. Carry on.",
    "If this was a movie, the security system would now make a witty remark. Consider this that remark."
  ];
  const msg = lines[Math.floor(Math.random() * lines.length)];
  res.status(400).json({ success: false, error: msg });
};

const extractApis = (html, category, baseUrl) => {
  const apis = [];
  const seen = new Set();
  try {
    const $ = cheerio.load(html);

    if (category === 'extensions') {
      $('a[href*="/docs/extensions/reference/api/"]').each((_, el) => {
        const href = $(el).attr('href') || '';
        const match = href.match(/\/docs\/extensions\/reference\/api\/([a-zA-Z0-9_./-]+)/);
        if (!match) return;
        let id = match[1].replace(/\/$/, '');
        if (id.includes('/') && !id.startsWith('devtools/')) {
          id = id.split('/').pop();
        }
        if (!id || id.length < 2 || seen.has(id)) return;
        seen.add(id);
        const title = $(el).text().trim().substring(0, 200) || id;
        const parentText = $(el).parent().text().trim().substring(0, 500);
        apis.push({
          id,
          title,
          contentHash: hashContent(parentText || title),
          category,
          url: href.startsWith('http') ? href : `https://developer.chrome.com${href}`
        });
      });
    } else if (category === 'webstore') {
      $('h2, h3, a[href*="/webstore/"]').each((_, el) => {
        const $el = $(el);
        const id = $el.attr('id') || $el.find('[id]').first().attr('id') || $el.text().trim().toLowerCase().replace(/\s+/g, '-').substring(0, 80);
        const title = $el.text().trim().substring(0, 200);
        if (!id || !title || title.length < 3 || seen.has(id)) return;
        seen.add(id);
        const content = sanitizeHtml($el.parent().html() || $el.html() || title);
        apis.push({
          id,
          title,
          contentHash: hashContent(content),
          category,
          url: `${baseUrl}#${id}`
        });
      });
    } else if (category === 'devtools') {
      $('a[href*="/tot/"], a[href*="/1-3/"], h2, h3').each((_, el) => {
        const $el = $(el);
        let id = $el.attr('id') || '';
        const href = $el.attr('href') || '';
        if (href) {
          const m = href.match(/\/(tot|1-3|v8)\/([A-Za-z0-9_-]+)/);
          if (m) id = m[2];
        }
        if (!id) id = $el.text().trim().toLowerCase().replace(/\s+/g, '-').substring(0, 80);
        const title = $el.text().trim().substring(0, 200);
        if (!id || !title || title.length < 3 || seen.has(id)) return;
        seen.add(id);
        apis.push({
          id,
          title,
          contentHash: hashContent(title + id),
          category,
          url: href.startsWith('http') ? href : (href ? `https://chromedevtools.github.io/devtools-protocol${href}` : baseUrl)
        });
      });
    }

    if (apis.length === 0) {
      const bodyText = $('body').text().replace(/\s+/g, ' ').substring(0, 50000);
      const overallHash = hashContent(bodyText);
      apis.push({
        id: 'page-content',
        title: `${category} page content`,
        contentHash: overallHash,
        category,
        url: baseUrl
      });
    }
  } catch (e) {
    console.error(`Extract error ${category}`);
  }
  return apis;
};

const fetchApiContent = async (url, category) => {
  try {
    const response = await axios.get(url, {
      timeout: 15000,
      headers: {
        'User-Agent': 'Chrome-API-Monitor/1.1 (compatible; research; +https://github.com/example)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache'
      },
      maxRedirects: 5,
      validateStatus: (s) => s >= 200 && s < 400
    });
    return extractApis(response.data, category, url);
  } catch (error) {
    console.error(`Fetch error ${category}: ${error.message}`);
    return [];
  }
};

const detectChanges = (oldApis, newApis, category) => {
  const changes = {
    added: [],
    modified: [],
    removed: [],
    category,
    timestamp: new Date().toISOString()
  };

  const oldMap = new Map(oldApis.map(api => [api.id, api]));
  const newMap = new Map(newApis.map(api => [api.id, api]));

  for (const newApi of newApis) {
    const oldApi = oldMap.get(newApi.id);
    if (!oldApi) {
      changes.added.push(newApi);
    } else if (oldApi.contentHash !== newApi.contentHash) {
      changes.modified.push({
        id: newApi.id,
        title: newApi.title,
        category: newApi.category,
        url: newApi.url,
        oldHash: oldApi.contentHash,
        newHash: newApi.contentHash
      });
    }
  }

  for (const oldApi of oldApis) {
    if (!newMap.has(oldApi.id)) {
      changes.removed.push(oldApi);
    }
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
        const hasChanges = changes.added.length > 0 || changes.modified.length > 0 || changes.removed.length > 0;

        if (hasChanges) {
          changeHistory.unshift(changes);
          changeHistory = changeHistory.slice(0, MAX_HISTORY);
          console.log(`Changes detected in ${category}: added=${changes.added.length} modified=${changes.modified.length} removed=${changes.removed.length}`);
        }
      }

      if (newApis.length > 0) {
        apiSnapshots.set(category, newApis);
      }
      await new Promise(resolve => setTimeout(resolve, 3000));
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
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
    return cached.data;
  }
  const data = fetchFn();
  cache.set(key, { data, timestamp: Date.now() });
  return data;
};

app.use((req, res, next) => {
  if (isSuspicious(req)) {
    return sarcasticReject(res);
  }
  next();
});

app.get('/api/changes', (req, res) => {
  try {
    let limit = parseInt(req.query.limit, 10);
    if (isNaN(limit) || limit < 1) limit = 20;
    limit = Math.min(limit, 100);
    const data = getCachedData('changes', () => changeHistory.slice(0, limit));
    res.json({
      success: true,
      data,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/status', (req, res) => {
  try {
    const data = getCachedData('status', () => ({
      monitoring: true,
      categories: Object.keys(CHROME_API_URLS),
      lastCheck: lastMonitorTime || changeHistory[0]?.timestamp || null,
      totalChanges: changeHistory.length,
      apiCount: Array.from(apiSnapshots.values()).reduce((sum, apis) => sum + apis.length, 0),
      uptime: Math.floor(process.uptime())
    }));
    res.json({
      success: true,
      data,
      timestamp: new Date().toISOString()
    });
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
    const data = getCachedData(`snapshot-${category}`, () => apiSnapshots.get(category) || []);
    res.json({
      success: true,
      data,
      category,
      timestamp: new Date().toISOString()
    });
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
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
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
  console.log(`Chrome API Monitor running on port ${PORT}`);
  console.log(`Monitoring interval: ${POLL_INTERVAL / 1000}s`);
});
