// Load .env file if present (production secrets — never commit this file)
require('dotenv').config();

const express    = require('express');
const fs         = require('fs');
const path       = require('path');
const { v4: uuidv4 } = require('uuid');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const multer     = require('multer');
const session    = require('express-session');
const { Issuer, generators } = require('openid-client');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Auth0 config ──────────────────────────────────────────────────────────────
const AUTH0_DOMAIN        = process.env.AUTH0_DOMAIN        || '';
const AUTH0_CLIENT_ID     = process.env.AUTH0_CLIENT_ID     || '';
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET || '';
const AUTH0_CALLBACK_URL  = process.env.AUTH0_CALLBACK_URL  || `http://localhost:${PORT}/auth/callback`;
const AUTH0_ADMIN_ROLE    = process.env.AUTH0_ADMIN_ROLE    || 'signflow-admin';
const SESSION_SECRET      = process.env.SESSION_SECRET      || uuidv4();
const ENV_HCAPTCHA_SECRET = process.env.SF_HCAPTCHA_SECRET  || null;

// ── Paths ─────────────────────────────────────────────────────────────────────
const DATA_DIR         = path.join(__dirname, 'data');
const CONFIG_FILE      = path.join(DATA_DIR, 'config.json');
const SUBSCRIBERS_FILE = path.join(DATA_DIR, 'subscribers.json');
const UPLOADS_DIR      = path.join(__dirname, 'public', 'uploads');
const FONTS_DIR        = path.join(UPLOADS_DIR, 'fonts');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(FONTS_DIR))   fs.mkdirSync(FONTS_DIR,   { recursive: true });

// ── OIDC client ───────────────────────────────────────────────────────────────
let oidcClient = null;
async function initAuth0() {
  if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET) {
    console.warn('⚠ Auth0 env vars not set — admin login will be unavailable.');
    return;
  }
  try {
    const issuer = await Issuer.discover(`https://${AUTH0_DOMAIN}/`);
    oidcClient = new issuer.Client({
      client_id: AUTH0_CLIENT_ID, client_secret: AUTH0_CLIENT_SECRET,
      redirect_uris: [AUTH0_CALLBACK_URL], response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
    });
    console.log(`✔ Auth0 OIDC client ready (${AUTH0_DOMAIN})`);
  } catch (e) { console.error('✖ Auth0 init failed:', e.message); }
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(session({
  secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));

// ── Static files ──────────────────────────────────────────────────────────────
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/admin',   express.static(path.join(__dirname, 'admin')));

// ── Multer (images + fonts) ───────────────────────────────────────────────────
const FONT_EXTS = new Set(['.woff', '.woff2', '.ttf', '.otf']);
const imgStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({
  storage: imgStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Images only'));
  }
});

const fontStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, FONTS_DIR),
  filename:    (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname).toLowerCase()}`)
});
const uploadFont = multer({
  storage: fontStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    FONT_EXTS.has(ext) ? cb(null, true) : cb(new Error('Font files only'));
  }
});

// ── Rate limiting ─────────────────────────────────────────────────────────────
const submitLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  message: { error: 'Too many requests' } });
const adminLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });

// ── Config helpers ────────────────────────────────────────────────────────────
function applyConfigDefaults(cfg) {
  cfg.design = cfg.design || {};
  if (!cfg.design.cardPadding)   cfg.design.cardPadding   = '48px 40px';
  if (!cfg.design.cardRadius)    cfg.design.cardRadius    = '12px';
  if (!cfg.design.fieldRadius)   cfg.design.fieldRadius   = '6px';
  if (!cfg.design.customFonts)   cfg.design.customFonts   = [];
  cfg.sections = cfg.sections || [];
  cfg.fields   = cfg.fields   || [];
  // Ensure each field has a conditions array
  cfg.fields.forEach(f => { if (!f.conditions) f.conditions = []; });
  // Ensure each section has a colors object
  cfg.sections.forEach(s => { if (!s.colors) s.colors = {}; });
  return cfg;
}

function readConfig() {
  const cfg = applyConfigDefaults(JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')));
  if (ENV_HCAPTCHA_SECRET) cfg.site.hcaptchaSecretKey = ENV_HCAPTCHA_SECRET;
  return cfg;
}
function writeConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}
function readSubscribers() {
  return JSON.parse(fs.readFileSync(SUBSCRIBERS_FILE, 'utf8'));
}
function writeSubscribers(subs) {
  fs.writeFileSync(SUBSCRIBERS_FILE, JSON.stringify(subs, null, 2));
}

// ── Auth helpers ──────────────────────────────────────────────────────────────
function getRoles(tokenClaims) {
  const NS = `https://signflow/roles`;
  return tokenClaims[NS] || tokenClaims['https://signflow.app/roles'] || [];
}
function isAdminUser(session) {
  if (!session || !session.user) return false;
  return getRoles(session.user).includes(AUTH0_ADMIN_ROLE);
}
function adminAuth(req, res, next) {
  if (isAdminUser(req.session)) return next();
  const isApi = req.path.startsWith('/api/');
  if (isApi) return res.status(401).json({ error: 'Unauthorized' });
  req.session.returnTo = req.originalUrl;
  res.redirect('/auth/login');
}

// ════════════════════════════════════════
// PUBLIC ROUTES
// ════════════════════════════════════════

app.get('/', (req, res) => { res.send(renderPublicPage(readConfig())); });
app.get('/privacy', (req, res) => { res.send(renderPrivacyPage(readConfig())); });

app.get('/unsubscribe', (req, res) => {
  const { token, email } = req.query;
  const cfg = readConfig();
  let message = '', success = false;
  if (token && email) {
    const subs = readSubscribers();
    const idx = subs.findIndex(s => s.email === decodeURIComponent(email) && s.unsubscribeToken === token);
    if (idx !== -1) {
      subs[idx].status = 'unsubscribed'; subs[idx].unsubscribedAt = new Date().toISOString();
      writeSubscribers(subs); message = 'You have been successfully unsubscribed.'; success = true;
    } else { message = 'Invalid or expired unsubscribe link.'; }
  }
  res.send(renderUnsubscribePage(cfg, message, success));
});

app.get('/delete-data', (req, res) => {
  const { token, email } = req.query;
  const cfg = readConfig();
  let message = '', success = false;
  if (token && email) {
    const subs = readSubscribers();
    const idx = subs.findIndex(s => s.email === decodeURIComponent(email) && s.unsubscribeToken === token);
    if (idx !== -1) {
      subs.splice(idx, 1); writeSubscribers(subs);
      message = 'Your data has been permanently deleted from our records.'; success = true;
    } else { message = 'Invalid or expired link.'; }
  }
  res.send(renderUnsubscribePage(cfg, message, success, true));
});

app.post('/subscribe', submitLimiter, async (req, res) => {
  const cfg = readConfig();
  const subs = readSubscribers();
  const body = req.body;

  if (cfg.site.captchaEnabled && cfg.site.hcaptchaSecretKey) {
    const captchaToken = body['h-captcha-response'] || '';
    if (!captchaToken) return res.status(400).json({ error: 'Please complete the CAPTCHA.' });
    try {
      const vp = new URLSearchParams({ secret: cfg.site.hcaptchaSecretKey, response: captchaToken, remoteip: req.ip });
      const vr = await fetch('https://api.hcaptcha.com/siteverify', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: vp.toString() });
      const vj = await vr.json();
      if (!vj.success) return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
    } catch (e) { return res.status(500).json({ error: 'CAPTCHA service error. Please try again.' }); }
  }

  const email = (body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Valid email required.' });

  const existing = subs.find(s => s.email === email);
  if (existing && existing.status === 'active')
    return res.status(409).json({ error: 'This email is already subscribed.' });

  const record = {
    id: uuidv4(), email, status: 'active',
    subscribedAt: new Date().toISOString(), unsubscribedAt: null,
    unsubscribeToken: uuidv4(), consentGiven: true,
    consentTimestamp: new Date().toISOString(), ipAddress: req.ip, customFields: {}
  };

  cfg.fields.filter(f => !f.system && !['video','divider','spinwheel'].includes(f.type)).forEach(field => {
    record.customFields[field.id] = (body[field.id] || '').trim();
  });

  if (existing) {
    const idx = subs.findIndex(s => s.email === email);
    subs[idx] = { ...subs[idx], ...record };
  } else { subs.push(record); }

  writeSubscribers(subs);
  res.json({ success: true });
});

// ════════════════════════════════════════
// AUTH0 ROUTES
// ════════════════════════════════════════

app.get('/auth/login', adminLimiter, (req, res) => {
  if (!oidcClient) return res.status(503).send('Auth0 is not configured.');
  const nonce = generators.nonce(), state = generators.state(), codeVerifier = generators.codeVerifier();
  req.session.authNonce = nonce; req.session.authState = state; req.session.authCodeVerifier = codeVerifier;
  res.redirect(oidcClient.authorizationUrl({
    scope: 'openid profile email', audience: `https://${AUTH0_DOMAIN}/api/v2/`,
    response_type: 'code', nonce, state,
    code_challenge: generators.codeChallenge(codeVerifier), code_challenge_method: 'S256',
  }));
});

app.get('/auth/callback', adminLimiter, async (req, res) => {
  if (!oidcClient) return res.status(503).send('Auth0 not configured.');
  try {
    const params   = oidcClient.callbackParams(req);
    const tokenSet = await oidcClient.callback(AUTH0_CALLBACK_URL, params, {
      nonce: req.session.authNonce, state: req.session.authState, code_verifier: req.session.authCodeVerifier,
    });
    const claims = tokenSet.claims();
    if (!getRoles(claims).includes(AUTH0_ADMIN_ROLE)) {
      req.session.destroy(() => {});
      return res.status(403).send(renderAccessDeniedPage(claims.email || 'unknown'));
    }
    req.session.user = claims; req.session.accessToken = tokenSet.access_token;
    delete req.session.authNonce; delete req.session.authState; delete req.session.authCodeVerifier;
    const returnTo = req.session.returnTo || '/admin'; delete req.session.returnTo;
    res.redirect(returnTo);
  } catch (e) { res.status(500).send(`Authentication failed: ${e.message}`); }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => {});
  if (AUTH0_DOMAIN) {
    const returnTo = encodeURIComponent(AUTH0_CALLBACK_URL.replace('/auth/callback', ''));
    res.redirect(`https://${AUTH0_DOMAIN}/v2/logout?client_id=${AUTH0_CLIENT_ID}&returnTo=${returnTo}`);
  } else { res.redirect('/'); }
});

app.get('/auth/me', (req, res) => {
  if (isAdminUser(req.session)) {
    const { name, email, picture } = req.session.user;
    res.json({ authenticated: true, name, email, picture });
  } else { res.json({ authenticated: false }); }
});

// ════════════════════════════════════════
// ADMIN ROUTES
// ════════════════════════════════════════

app.get('/admin', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});
app.get('/api/admin/config', adminAuth, (req, res) => { res.json(readConfig()); });
app.post('/api/admin/config', adminAuth, (req, res) => {
  writeConfig(applyConfigDefaults(req.body)); res.json({ success: true });
});
app.post('/api/admin/upload', adminAuth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/${req.file.filename}` });
});
app.post('/api/admin/upload-font', adminAuth, uploadFont.single('font'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/fonts/${req.file.filename}` });
});
app.get('/api/admin/subscribers', adminAuth, (req, res) => {
  const subs = readSubscribers();
  const page = parseInt(req.query.page) || 1, limit = parseInt(req.query.limit) || 50;
  const search = (req.query.search || '').toLowerCase(), status = req.query.status || 'all';
  let filtered = subs;
  if (search) filtered = filtered.filter(s => s.email.includes(search) || JSON.stringify(s.customFields).toLowerCase().includes(search));
  if (status !== 'all') filtered = filtered.filter(s => s.status === status);
  const total = filtered.length, paginated = filtered.slice((page - 1) * limit, page * limit);
  res.json({ subscribers: paginated, total, page, pages: Math.ceil(total / limit) });
});
app.delete('/api/admin/subscribers/:id', adminAuth, (req, res) => {
  const subs = readSubscribers();
  const idx = subs.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  subs.splice(idx, 1); writeSubscribers(subs); res.json({ success: true });
});
app.get('/api/admin/export', adminAuth, (req, res) => {
  const cfg = readConfig(), subs = readSubscribers(), fmt = req.query.format || 'csv';
  if (fmt === 'json') {
    res.setHeader('Content-Disposition', 'attachment; filename="subscribers.json"');
    res.setHeader('Content-Type', 'application/json');
    return res.send(JSON.stringify(subs, null, 2));
  }
  const fieldIds = cfg.fields.filter(f => !f.system).map(f => f.id);
  const headers = ['id','email','status','subscribedAt','unsubscribedAt','consentGiven','consentTimestamp','ipAddress',...fieldIds];
  const rows = subs.map(s => headers.map(h => fieldIds.includes(h) ? `"${(s.customFields[h]||'').replace(/"/g,'""')}"` : `"${(s[h]||'').toString().replace(/"/g,'""')}"`).join(','));
  res.setHeader('Content-Disposition', 'attachment; filename="subscribers.csv"');
  res.setHeader('Content-Type', 'text/csv');
  res.send([headers.join(','), ...rows].join('\n'));
});

// ════════════════════════════════════════
// EMBED ROUTES
// ════════════════════════════════════════

app.get('/embed', (req, res) => {
  const cfg = readConfig();
  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', "frame-ancestors *");
  res.send(renderEmbedPage(cfg));
});
app.get('/embed.js', (req, res) => {
  const cfg = readConfig();
  const origin = `${req.protocol}://${req.get('host')}`;
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.send(renderEmbedScript(origin, cfg));
});

// ════════════════════════════════════════
// PAGE RENDERERS
// ════════════════════════════════════════

function googleFontTag(cfg) {
  const fonts = [cfg.design.googleFont, cfg.design.bodyFont].filter(Boolean);
  const additionalFonts = ['Noto Sans', 'Noto Serif', 'Noto Display'];
  // Only load Google Fonts that are actually selected
  const gFonts = fonts.filter(f => !additionalFonts.map(a=>a).includes(f) && f && !isCustomFont(cfg, f));
  // Noto fonts need special URL
  const notoFonts = fonts.filter(f => ['Noto Sans','Noto Serif'].includes(f));
  let tags = '';
  if (gFonts.length) {
    const query = gFonts.map(f => f.replace(/ /g, '+')).join('&family=');
    tags += `<link href="https://fonts.googleapis.com/css2?family=${query}:wght@300;400;600;700&display=swap" rel="stylesheet">\n`;
  }
  if (notoFonts.length) {
    const nq = notoFonts.map(f => f.replace(/ /g, '+')).join('&family=');
    tags += `<link href="https://fonts.googleapis.com/css2?family=${nq}:wght@300;400;600;700&display=swap" rel="stylesheet">\n`;
  }
  if ((cfg.design.customFonts || []).length) {
    tags += `<style>${(cfg.design.customFonts).map(f => `@font-face{font-family:'${f.name}';src:url('${f.url}') format('woff2');font-weight:100 900;font-display:swap;}`).join('')}</style>\n`;
  }
  return tags;
}

function isCustomFont(cfg, fontName) {
  return (cfg.design.customFonts || []).some(f => f.name === fontName);
}

// ── Shared form field renderer ────────────────────────────────────────────────
function renderFormField(f, cfg) {
  const accentColor = (cfg.design || {}).accentColor || '#e94560';
  const req = f.required ? ' <span class="req">*</span>' : '';
  const reqAttr = f.required ? ' required' : '';
  const ph = f.placeholder || '';
  const condAttr = (f.conditions && f.conditions.length) ? ` data-field-id="${f.id}" data-conditions='${JSON.stringify(f.conditions)}'` : ` data-field-id="${f.id}"`;

  if (f.type === 'select') {
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      <select id="sf_${f.id}" name="${f.id}"${reqAttr}>
        <option value="">— Select —</option>
        ${(f.options || []).map(o => `<option value="${o}">${o}</option>`).join('')}
      </select></div>`;
  }
  if (f.type === 'checkbox') {
    return `<div class="sf-field sf-field--check"${condAttr}>
      <label><input type="checkbox" name="${f.id}" value="yes"${reqAttr}> ${f.label}${req}</label></div>`;
  }
  if (f.type === 'textarea') {
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      <textarea id="sf_${f.id}" name="${f.id}" placeholder="${ph}"${reqAttr} rows="3"></textarea></div>`;
  }
  if (f.type === 'age') {
    const currentYear = new Date().getFullYear();
    const minAge = parseInt(f.minAge) || 0, maxAge = parseInt(f.maxAge) || 120;
    const minBirth = currentYear - maxAge, maxBirth = currentYear - minAge;
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      <div class="sf-age-wrap">
        <input type="number" id="sf_${f.id}" name="${f.id}" min="${minAge}" max="${maxAge}" placeholder="${ph || 'Enter your age'}"${reqAttr}>
        <span class="sf-age-unit">yrs</span>
      </div></div>`;
  }
  if (f.type === 'date') {
    const mode = f.dateMode || 'free';
    if (mode === 'specific' && f.allowedDates && f.allowedDates.length) {
      return `<div class="sf-field"${condAttr}>
        <label for="sf_${f.id}">${f.label}${req}</label>
        <select id="sf_${f.id}" name="${f.id}"${reqAttr}>
          <option value="">— Select date —</option>
          ${f.allowedDates.map(d => `<option value="${d}">${d}</option>`).join('')}
        </select></div>`;
    }
    const minAttr = f.minDate ? ` min="${f.minDate}"` : '';
    const maxAttr = f.maxDate ? ` max="${f.maxDate}"` : '';
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      <input type="date" id="sf_${f.id}" name="${f.id}"${minAttr}${maxAttr}${reqAttr}></div>`;
  }
  if (f.type === 'year') {
    const minY = parseInt(f.minYear) || 1920, maxY = parseInt(f.maxYear) || new Date().getFullYear();
    const years = [];
    for (let y = maxY; y >= minY; y--) years.push(y);
    return `<div class="sf-field"${condAttr}>
      <label>${f.label}${req}</label>
      <div class="sf-scroll-pick-wrap">
        <div class="sf-scroll-pick" data-target="sf_${f.id}">
          <div class="sf-sp-fade-top"></div>
          <div class="sf-sp-items">
            <div class="sf-sp-item sf-sp-blank" data-value=""></div>
            ${years.map(y => `<div class="sf-sp-item" data-value="${y}">${y}</div>`).join('')}
            <div class="sf-sp-item sf-sp-blank" data-value=""></div>
          </div>
          <div class="sf-sp-selector"></div>
          <div class="sf-sp-fade-bottom"></div>
        </div>
      </div>
      <input type="hidden" id="sf_${f.id}" name="${f.id}"${reqAttr}></div>`;
  }
  if (f.type === 'yearmonth') {
    const minY = parseInt(f.minYear) || 1920, maxY = parseInt(f.maxYear) || new Date().getFullYear();
    const years = [];
    for (let y = maxY; y >= minY; y--) years.push(y);
    const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    return `<div class="sf-field"${condAttr}>
      <label>${f.label}${req}</label>
      <div class="sf-scroll-pick-wrap sf-scroll-pick-double">
        <div class="sf-scroll-pick" data-target="sf_${f.id}_month">
          <div class="sf-sp-fade-top"></div>
          <div class="sf-sp-items">
            <div class="sf-sp-item sf-sp-blank" data-value=""></div>
            ${months.map((m,i) => `<div class="sf-sp-item" data-value="${String(i+1).padStart(2,'0')}">${m}</div>`).join('')}
            <div class="sf-sp-item sf-sp-blank" data-value=""></div>
          </div>
          <div class="sf-sp-selector"></div>
          <div class="sf-sp-fade-top"></div>
          <div class="sf-sp-fade-bottom"></div>
        </div>
        <div class="sf-scroll-pick" data-target="sf_${f.id}_year">
          <div class="sf-sp-fade-top"></div>
          <div class="sf-sp-items">
            <div class="sf-sp-item sf-sp-blank" data-value=""></div>
            ${years.map(y => `<div class="sf-sp-item" data-value="${y}">${y}</div>`).join('')}
            <div class="sf-sp-item sf-sp-blank" data-value=""></div>
          </div>
          <div class="sf-sp-selector"></div>
          <div class="sf-sp-fade-bottom"></div>
        </div>
      </div>
      <input type="hidden" id="sf_${f.id}_month" name="${f.id}_month"${reqAttr}>
      <input type="hidden" id="sf_${f.id}_year" name="${f.id}_year"${reqAttr}></div>`;
  }
  if (f.type === 'slider') {
    const min = f.min ?? 0, max = f.max ?? 100, step = f.step ?? 1;
    const def = f.defaultValue ?? min, icon = f.knobIcon || '●';
    const track = f.trackStyle || 'linear';
    const mode = f.slideMode || 'smooth';
    const showVal = f.showValue !== false;
    if (track === 'arc') {
      return `<div class="sf-field"${condAttr}>
        <label>${f.label}${req}</label>
        <div class="sf-slider-wrap sf-slider-arc">
          <svg viewBox="0 0 220 130" class="sf-arc-svg" xmlns="http://www.w3.org/2000/svg">
            <path class="sf-arc-bg" d="M 20 110 A 90 90 0 0 1 200 110" stroke="#e0e0e0" fill="none" stroke-width="10" stroke-linecap="round"/>
            <path class="sf-arc-fill" d="M 20 110 A 90 90 0 0 1 200 110" stroke="${accentColor}" fill="none" stroke-width="10" stroke-linecap="round" stroke-dasharray="0 283"/>
            <circle class="sf-arc-handle" cx="20" cy="110" r="16" fill="${accentColor}" style="cursor:grab"/>
            <text class="sf-arc-icon" x="20" y="116" text-anchor="middle" fill="white" font-size="14" style="pointer-events:none">${icon}</text>
          </svg>
          ${showVal ? `<div class="sf-arc-val">${def}</div>` : ''}
          <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${def}"
            data-min="${min}" data-max="${max}" data-step="${step}" data-type="arc">
        </div></div>`;
    }
    const wrapClass = track === 'angled' ? 'sf-slider-wrap sf-slider-angled' : 'sf-slider-wrap sf-slider-linear';
    return `<div class="sf-field"${condAttr}>
      <label>${f.label}${req}</label>
      <div class="${wrapClass}">
        <div class="sf-slider-track-wrap">
          <input type="range" class="sf-range-input" min="${min}" max="${max}" step="${mode==='step'?step:1}" value="${def}"
            data-knob="${icon}" data-hidden="sf_${f.id}" oninput="sfSliderUpdate(this)">
        </div>
        ${showVal ? `<div class="sf-slider-val">${def}</div>` : ''}
        <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${def}">
      </div></div>`;
  }
  // Default: text/email/number/tel/phone
  return `<div class="sf-field"${condAttr}>
    <label for="sf_${f.id}">${f.label}${req}</label>
    <input type="${f.type || 'text'}" id="sf_${f.id}" name="${f.id}" placeholder="${ph}"${reqAttr}></div>`;
}

// ── Block renderers ───────────────────────────────────────────────────────────
function renderBlock(block, cfg, formFieldsHtml, formSection, siteSection) {
  const colors = block.colors || {};
  const blockStyle = colors.bg ? `style="background:${colors.bg};${colors.text?`color:${colors.text};`:''}padding:${cfg.design.cardPadding||'24px 20px'};border-radius:${cfg.design.cardRadius||'8px'};margin-bottom:16px;"` : '';

  if (!block.visible) return '';

  if (block.type === 'logo' || block.id === 'logo') {
    // Logo block (movable)
    const url = block.imageUrl || cfg.design.logoUrl || '';
    const width = block.width || cfg.design.logoWidth || '180px';
    const align = block.align || 'center';
    const link = block.link || '';
    if (!url) return '';
    const img = `<img src="${url}" alt="Logo" style="width:${width};max-width:100%">`;
    return `<div class="sf-logo" style="text-align:${align};margin-bottom:24px">${link ? `<a href="${link}">${img}</a>` : img}</div>`;
  }

  if (block.type === 'hero') {
    return `${block.imageUrl && block.imagePosition === 'above' ? `<img src="${block.imageUrl}" class="sf-hero-img" alt="">` : ''}
    <h1 ${blockStyle}>${block.heading}</h1>
    ${block.subheading ? `<p class="sf-sub">${block.subheading}</p>` : ''}
    ${block.imageUrl && block.imagePosition === 'below' ? `<img src="${block.imageUrl}" class="sf-hero-img below" alt="">` : ''}`;
  }

  if (block.type === 'form') {
    const s = siteSection;
    const design = cfg.design;
    return `<form id="sf-form" novalidate>
      ${formFieldsHtml}
      <div class="sf-gdpr">By subscribing you agree to our <a href="${s.privacyPolicyUrl}" target="_blank">Privacy Policy</a>. We store your data securely and you can unsubscribe or request deletion at any time.</div>
      ${s.captchaEnabled && s.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${s.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
      <button type="submit" class="sf-btn">${design.buttonText}</button>
      <div id="sf-msg" class="sf-msg"></div>
    </form>`;
  }

  if (block.type === 'footer') {
    return `<p class="sf-footer">${block.text || ''}</p>`;
  }

  if (block.type === 'divider') {
    const style = block.style || 'line';
    const color = (block.colors && block.colors.bg) || block.color || '#e0e0e0';
    const thick = block.thickness || 1;
    const spacing = block.spacing || 20;
    if (style === 'space') return `<div style="height:${spacing*2}px"></div>`;
    if (style === 'dots') return `<div class="sf-divider sf-divider-dots" style="margin:${spacing}px 0;color:${color}">● ● ●</div>`;
    if (style === 'wave') return `<div class="sf-divider" style="margin:${spacing}px 0;overflow:hidden;height:20px"><svg viewBox="0 0 200 20" preserveAspectRatio="none" style="width:100%;height:100%"><path d="M0 10 Q25 0 50 10 Q75 20 100 10 Q125 0 150 10 Q175 20 200 10" stroke="${color}" stroke-width="${thick}" fill="none"/></svg></div>`;
    return `<hr class="sf-divider" style="border:none;border-top:${thick}px solid ${color};margin:${spacing}px 0">`;
  }

  if (block.type === 'video') {
    const url = block.url || '';
    if (!url) return '';
    const ar = block.aspectRatio || '16:9';
    const pt = ar === '4:3' ? '75%' : ar === '1:1' ? '100%' : '56.25%';
    let videoHtml = '';
    const ytMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([\w-]+)/);
    const vmMatch = url.match(/vimeo\.com\/(\d+)/);
    if (ytMatch) {
      videoHtml = `<iframe src="https://www.youtube.com/embed/${ytMatch[1]}" frameborder="0" allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture" allowfullscreen style="position:absolute;inset:0;width:100%;height:100%"></iframe>`;
    } else if (vmMatch) {
      videoHtml = `<iframe src="https://player.vimeo.com/video/${vmMatch[1]}" frameborder="0" allow="autoplay;fullscreen;picture-in-picture" allowfullscreen style="position:absolute;inset:0;width:100%;height:100%"></iframe>`;
    } else {
      videoHtml = `<video controls style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover"><source src="${url}"></video>`;
    }
    return `<div class="sf-video-wrap" style="position:relative;padding-top:${pt};margin-bottom:20px;border-radius:8px;overflow:hidden">${videoHtml}</div>${block.caption ? `<p class="sf-video-caption">${block.caption}</p>` : ''}`;
  }

  if (block.type === 'spinwheel') {
    const rewards = (block.rewards || []).filter(r => r.label);
    if (!rewards.length) return '';
    const btnText = block.spinButtonText || 'Spin!';
    const rewardsJson = JSON.stringify(rewards);
    return `<div class="sf-wheel-wrap" id="sf-wheel-wrap-${block.id}">
      <canvas id="sf-wheel-${block.id}" class="sf-wheel-canvas" width="280" height="280" data-rewards='${rewardsJson}'></canvas>
      <button type="button" class="sf-wheel-btn" onclick="sfSpinWheel('${block.id}')">${btnText}</button>
      <div class="sf-wheel-result" id="sf-wheel-result-${block.id}"></div>
    </div>`;
  }

  return '';
}

// ── CSS for public/embed pages ─────────────────────────────────────────────────
function renderPageCSS(cfg) {
  const d = cfg.design;
  return `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --primary: ${d.primaryColor}; --accent: ${d.accentColor};
    --bg: ${d.backgroundColor}; --text: ${d.textColor};
    --radius: ${d.buttonRadius}; --container: ${d.containerWidth || '600px'};
    --card-padding: ${d.cardPadding || '48px 40px'};
    --card-radius: ${d.cardRadius || '12px'};
    --field-radius: ${d.fieldRadius || '6px'};
    --font-heading: '${d.googleFont}', serif; --font-body: '${d.bodyFont}', sans-serif;
  }
  body { font-family: var(--font-body); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 20px; }
  .sf-card { background: #fff; border-radius: var(--card-radius); padding: var(--card-padding); max-width: var(--container); width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
  .sf-logo { text-align: center; margin-bottom: 24px; }
  .sf-logo img { width: 180px; max-width: 100%; }
  .sf-hero-img { width: 100%; border-radius: 8px; margin-bottom: 28px; object-fit: cover; max-height: 280px; }
  .sf-hero-img.below { margin-top: 28px; margin-bottom: 0; }
  h1 { font-family: var(--font-heading); color: var(--primary); font-size: clamp(1.6rem,4vw,2.4rem); line-height: 1.2; margin-bottom: 12px; text-align: center; }
  .sf-sub { color: #666; font-size: 1.05rem; text-align: center; margin-bottom: 32px; line-height: 1.6; }
  .sf-field { margin-bottom: 16px; }
  .sf-field label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--primary); margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
  .req { color: var(--accent); }
  .sf-field input[type=text],.sf-field input[type=email],.sf-field input[type=number],.sf-field input[type=tel],.sf-field input[type=date],.sf-field select,.sf-field textarea {
    width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: var(--field-radius); font-family: var(--font-body); font-size: 1rem; color: var(--text); transition: border-color 0.2s; background: #fafafa; }
  .sf-field input:focus,.sf-field select:focus,.sf-field textarea:focus { outline: none; border-color: var(--accent); background: #fff; }
  .sf-field--check label { display: flex; align-items: flex-start; gap: 10px; font-size: 0.9rem; text-transform: none; letter-spacing: 0; }
  .sf-field--check input[type=checkbox] { width: auto; margin-top: 2px; accent-color: var(--accent); }
  .sf-btn { width: 100%; padding: 14px; background: var(--accent); color: #fff; border: none; border-radius: var(--radius); font-family: var(--font-heading); font-size: 1.1rem; font-weight: 700; cursor: pointer; margin-top: 8px; letter-spacing: 0.03em; transition: opacity 0.2s, transform 0.1s; }
  .sf-btn:hover { opacity: 0.9; transform: translateY(-1px); }
  .sf-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
  .sf-msg { display: none; margin-top: 20px; padding: 14px 18px; border-radius: 6px; font-size: 0.95rem; text-align: center; }
  .sf-msg.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
  .sf-msg.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
  .sf-gdpr { font-size: 0.78rem; color: #999; text-align: center; margin-top: 16px; line-height: 1.5; }
  .sf-gdpr a { color: var(--accent); }
  .sf-footer { text-align: center; margin-top: 28px; font-size: 0.82rem; color: #aaa; }
  .sf-video-caption { text-align: center; font-size: 0.85rem; color: #888; margin-top: -12px; margin-bottom: 12px; }
  #sf-cookie { position: fixed; bottom: 0; left: 0; right: 0; background: #1a1a1a; color: #eee; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; z-index: 9999; flex-wrap: wrap; font-size: 0.88rem; }
  #sf-cookie a { color: var(--accent); }
  #sf-cookie-accept { background: var(--accent); color: #fff; border: none; padding: 8px 20px; border-radius: 4px; cursor: pointer; font-size: 0.88rem; white-space: nowrap; }
  .sf-captcha { margin: 16px 0 4px; display: flex; justify-content: center; }

  /* ── Age field ── */
  .sf-age-wrap { display: flex; align-items: center; gap: 8px; }
  .sf-age-wrap input { flex: 1; }
  .sf-age-unit { font-size: 0.85rem; color: #999; white-space: nowrap; }

  /* ── Divider ── */
  .sf-divider-dots { text-align: center; letter-spacing: 10px; font-size: 0.8rem; }

  /* ── Scroll picker (year/month) ── */
  .sf-scroll-pick-wrap { position: relative; }
  .sf-scroll-pick-double { display: flex; gap: 8px; }
  .sf-scroll-pick-double .sf-scroll-pick { flex: 1; }
  .sf-scroll-pick {
    position: relative; height: 132px; overflow: hidden;
    border: 2px solid #e0e0e0; border-radius: var(--field-radius); background: #fafafa;
  }
  .sf-sp-items {
    height: 100%; overflow-y: scroll; scroll-snap-type: y mandatory;
    scrollbar-width: none; -ms-overflow-style: none;
    padding: 0;
  }
  .sf-sp-items::-webkit-scrollbar { display: none; }
  .sf-sp-item {
    height: 44px; display: flex; align-items: center; justify-content: center;
    font-size: 0.95rem; scroll-snap-align: center; cursor: pointer;
    transition: color 0.15s; color: #999;
  }
  .sf-sp-item.selected { color: var(--primary); font-weight: 600; }
  .sf-sp-blank { pointer-events: none; }
  .sf-sp-selector {
    position: absolute; top: 50%; left: 0; right: 0; height: 44px;
    transform: translateY(-50%); border-top: 2px solid var(--accent);
    border-bottom: 2px solid var(--accent); pointer-events: none; z-index: 2;
  }
  .sf-sp-fade-top, .sf-sp-fade-bottom {
    position: absolute; left: 0; right: 0; height: 44px; pointer-events: none; z-index: 3;
  }
  .sf-sp-fade-top { top: 0; background: linear-gradient(to bottom, #fafafa, transparent); }
  .sf-sp-fade-bottom { bottom: 0; background: linear-gradient(to top, #fafafa, transparent); }

  /* ── Slider ── */
  .sf-slider-wrap { margin-top: 8px; }
  .sf-slider-track-wrap { position: relative; display: flex; align-items: center; }
  .sf-range-input {
    -webkit-appearance: none; width: 100%; height: 6px;
    background: linear-gradient(to right, var(--accent) 0%, var(--accent) var(--pct,50%), #e0e0e0 var(--pct,50%));
    border-radius: 3px; outline: none; cursor: pointer;
  }
  .sf-range-input::-webkit-slider-thumb {
    -webkit-appearance: none; width: 32px; height: 32px;
    border-radius: 50%; background: var(--accent);
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 2px 6px rgba(0,0,0,0.2); cursor: grab;
    content: attr(data-knob);
  }
  .sf-range-input::-moz-range-thumb {
    width: 32px; height: 32px; border-radius: 50%;
    background: var(--accent); border: none; cursor: grab;
    box-shadow: 0 2px 6px rgba(0,0,0,0.2);
  }
  .sf-slider-knob-label {
    position: absolute; width: 32px; height: 32px; display: flex;
    align-items: center; justify-content: center;
    font-size: 14px; pointer-events: none; left: calc(var(--pct,50%) - 16px);
    top: 50%; transform: translateY(-50%);
  }
  .sf-slider-val { text-align: center; font-size: 0.85rem; font-weight: 600; color: var(--primary); margin-top: 6px; }
  .sf-slider-angled .sf-slider-track-wrap { transform: rotate(-12deg); transform-origin: center; margin: 10px 4px; }
  .sf-slider-angled .sf-slider-val { margin-top: 12px; }

  /* ── Arc slider ── */
  .sf-slider-arc { display: flex; flex-direction: column; align-items: center; }
  .sf-arc-svg { width: 100%; max-width: 220px; cursor: pointer; touch-action: none; user-select: none; }
  .sf-arc-val { font-size: 1.2rem; font-weight: 700; color: var(--primary); margin-top: -8px; }

  /* ── Spin wheel ── */
  .sf-wheel-wrap { display: flex; flex-direction: column; align-items: center; gap: 14px; padding: 20px 0; }
  .sf-wheel-canvas { border-radius: 50%; box-shadow: 0 8px 32px rgba(0,0,0,0.18); display: block; max-width: 280px; width: 100%; }
  .sf-wheel-btn { padding: 12px 32px; background: var(--accent); color: #fff; border: none; border-radius: var(--radius); font-family: var(--font-heading); font-size: 1rem; font-weight: 700; cursor: pointer; letter-spacing: 0.05em; transition: opacity 0.2s, transform 0.1s; }
  .sf-wheel-btn:hover { opacity: 0.9; transform: scale(1.02); }
  .sf-wheel-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  .sf-wheel-result { font-size: 1.1rem; font-weight: 600; color: var(--primary); min-height: 28px; text-align: center; }

  @media(max-width:500px){ .sf-card { padding: 32px 20px; } }`;
}

// ── Interactive JS for public/embed pages ──────────────────────────────────────
function renderPageJS(cfg, formSection, isEmbed) {
  const formSec = formSection || {};
  const btnText = (cfg.design && cfg.design.buttonText) || 'Subscribe Now';
  const successMsg = formSec.submitSuccessMessage || 'Thank you!';
  const errorMsg = formSec.submitErrorMessage || 'Error. Try again.';

  // Build conditions map
  const condFields = (cfg.fields || []).filter(f => f.conditions && f.conditions.length);

  return `
// ── Cookie banner ──
(function(){
  if(!localStorage.getItem('sf_cookie_ok')){
    const b=document.getElementById('sf-cookie');if(b)b.style.display='flex';
  }
  const acc=document.getElementById('sf-cookie-accept');
  if(acc)acc.addEventListener('click',function(){
    localStorage.setItem('sf_cookie_ok','1');
    document.getElementById('sf-cookie').style.display='none';
  });
})();

// ── Scroll pickers ──
(function(){
  document.querySelectorAll('.sf-scroll-pick').forEach(function(picker){
    const items=picker.querySelector('.sf-sp-items');
    const target=picker.dataset.target;
    if(!items)return;
    function getSelected(){
      const allItems=Array.from(items.querySelectorAll('.sf-sp-item:not(.sf-sp-blank)'));
      const scroll=items.scrollTop;
      const idx=Math.round(scroll/44);
      return allItems[idx]||null;
    }
    function syncHidden(){
      const sel=getSelected();
      if(sel){
        const inp=document.getElementById(target);
        if(inp)inp.value=sel.dataset.value||'';
        items.querySelectorAll('.sf-sp-item').forEach(function(i){i.classList.remove('selected');});
        sel.classList.add('selected');
      }
    }
    items.addEventListener('scroll',function(){clearTimeout(picker._t);picker._t=setTimeout(syncHidden,80);},{ passive:true });
    items.addEventListener('click',function(e){
      const item=e.target.closest('.sf-sp-item');
      if(item&&!item.classList.contains('sf-sp-blank')){
        const idx=Array.from(items.querySelectorAll('.sf-sp-item')).indexOf(item);
        items.scrollTo({top:(idx-1)*44,behavior:'smooth'});
      }
    });
    // Snap to first real item on init
    setTimeout(function(){items.scrollTop=0;},0);
  });
})();

// ── Sliders ──
function sfSliderUpdate(inp){
  const min=parseFloat(inp.min),max=parseFloat(inp.max),val=parseFloat(inp.value);
  const pct=((val-min)/(max-min)*100)+'%';
  inp.style.setProperty('--pct',pct);
  const wrap=inp.closest('.sf-slider-wrap');
  if(!wrap)return;
  const valEl=wrap.querySelector('.sf-slider-val');
  if(valEl)valEl.textContent=val;
  const hiddenId=inp.dataset.hidden;
  if(hiddenId){const h=document.getElementById(hiddenId);if(h)h.value=val;}
  const knobEl=wrap.querySelector('.sf-slider-knob-label');
  if(knobEl)knobEl.style.left='calc('+pct+' - 16px)';
}
// Init all sliders
document.querySelectorAll('.sf-range-input').forEach(function(inp){sfSliderUpdate(inp);});

// ── Arc sliders ──
(function(){
  document.querySelectorAll('.sf-slider-arc').forEach(function(wrap){
    const svg=wrap.querySelector('.sf-arc-svg');
    const handle=wrap.querySelector('.sf-arc-handle');
    const icon=wrap.querySelector('.sf-arc-icon');
    const fill=wrap.querySelector('.sf-arc-fill');
    const valEl=wrap.querySelector('.sf-arc-val');
    const hidden=wrap.querySelector('input[type=hidden]');
    if(!svg||!handle||!hidden)return;
    const MIN=parseFloat(hidden.dataset.min||0),MAX=parseFloat(hidden.dataset.max||100),STEP=parseFloat(hidden.dataset.step||1);
    const CX=110,CY=110,R=90,START_ANG=Math.PI,SWEEP=Math.PI; // semicircle
    const ARC_LEN=Math.PI*R; // ~283
    function valToAngle(v){return START_ANG+((v-MIN)/(MAX-MIN))*SWEEP;}
    function angleToXY(a){return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};}
    function setVal(v){
      v=Math.round(Math.max(MIN,Math.min(MAX,v))/STEP)*STEP;
      hidden.value=v;
      if(valEl)valEl.textContent=v;
      const a=valToAngle(v);
      const p=angleToXY(a);
      handle.setAttribute('cx',p.x);handle.setAttribute('cy',p.y);
      if(icon){icon.setAttribute('x',p.x);icon.setAttribute('y',p.y+5);}
      const frac=(v-MIN)/(MAX-MIN);
      if(fill)fill.setAttribute('stroke-dasharray',frac*ARC_LEN+' '+(ARC_LEN*(1-frac)));
    }
    setVal(parseFloat(hidden.value)||MIN);
    function svgPoint(e){
      const bb=svg.getBoundingClientRect();
      const vb=svg.viewBox.baseVal;
      const cl=e.touches?e.touches[0]:e;
      const nx=(cl.clientX-bb.left)/bb.width;
      const ny=(cl.clientY-bb.top)/bb.height;
      return{x:nx*vb.width,y:ny*vb.height};
    }
    function angleFromPoint(p){return Math.atan2(p.y-CY,p.x-CX);}
    function valFromAngle(a){
      let n=(a-START_ANG)/SWEEP;
      n=Math.max(0,Math.min(1,n));
      return MIN+n*(MAX-MIN);
    }
    let dragging=false;
    svg.addEventListener('pointerdown',function(e){dragging=true;svg.setPointerCapture(e.pointerId);});
    svg.addEventListener('pointermove',function(e){if(!dragging)return;const p=svgPoint(e);setVal(valFromAngle(angleFromPoint(p)));});
    svg.addEventListener('pointerup',function(){dragging=false;});
  });
})();

// ── Spin wheels ──
(function(){
  document.querySelectorAll('.sf-wheel-canvas').forEach(function(canvas){
    const rewards=JSON.parse(canvas.dataset.rewards||'[]');
    if(!rewards.length)return;
    const ctx=canvas.getContext('2d');
    const n=rewards.length,arc=2*Math.PI/n;
    let currentRot=0;
    function drawWheel(rot){
      const cx=canvas.width/2,cy=canvas.height/2,r=cx-4;
      ctx.clearRect(0,0,canvas.width,canvas.height);
      rewards.forEach(function(rw,i){
        const start=rot+i*arc,end=start+arc;
        ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,start,end);ctx.closePath();
        ctx.fillStyle=rw.color||('#'+((i*3732121)%0xFFFFFF).toString(16).padStart(6,'0'));
        ctx.fill();ctx.strokeStyle='#fff';ctx.lineWidth=2;ctx.stroke();
        ctx.save();ctx.translate(cx,cy);ctx.rotate(start+arc/2);
        ctx.textAlign='right';ctx.fillStyle='#fff';ctx.font='bold '+(r>100?'13':'11')+'px sans-serif';
        ctx.shadowColor='rgba(0,0,0,0.3)';ctx.shadowBlur=3;
        ctx.fillText(rw.label||'',r-10,5);ctx.restore();
      });
      // Pointer
      ctx.beginPath();ctx.moveTo(cx-12,0);ctx.lineTo(cx+12,0);ctx.lineTo(cx,22);ctx.closePath();
      ctx.fillStyle='#fff';ctx.shadowColor='rgba(0,0,0,0.3)';ctx.shadowBlur=4;ctx.fill();
    }
    drawWheel(currentRot);
    canvas._sfRewards=rewards;canvas._sfRot=currentRot;canvas._sfDraw=drawWheel;
  });
})();

function sfSpinWheel(id){
  const canvas=document.getElementById('sf-wheel-'+id);
  const btn=document.querySelector('#sf-wheel-wrap-'+id+' .sf-wheel-btn');
  const resultEl=document.getElementById('sf-wheel-result-'+id);
  if(!canvas||!canvas._sfRewards)return;
  const rewards=canvas._sfRewards,n=rewards.length;
  btn.disabled=true;
  // Weighted random
  const totalW=rewards.reduce(function(s,r){return s+(r.probability||1);},0);
  let rand=Math.random()*totalW,winIdx=0;
  for(let i=0;i<n;i++){rand-=(rewards[i].probability||1);if(rand<=0){winIdx=i;break;}}
  const arc=2*Math.PI/n;
  const targetAngle=-(winIdx*arc+arc/2); // land pointer at middle of segment
  const spins=5+Math.random()*3;
  const totalRot=spins*2*Math.PI+targetAngle-(canvas._sfRot%(2*Math.PI));
  const duration=4000,start=performance.now();
  const startRot=canvas._sfRot;
  function ease(t){return 1-Math.pow(1-t,4);}
  function frame(now){
    const t=Math.min(1,(now-start)/duration);
    const rot=startRot+totalRot*ease(t);
    canvas._sfRot=rot;canvas._sfDraw(rot);
    if(t<1){requestAnimationFrame(frame);}
    else{if(resultEl)resultEl.textContent='🎉 '+rewards[winIdx].label+'!';}
  }
  requestAnimationFrame(frame);
}

// ── Conditional logic ──
(function(){
  const fields=document.querySelectorAll('[data-field-id]');
  function getFieldValue(fieldId){
    const el=document.querySelector('[name="'+fieldId+'"]');
    if(!el)return'';
    if(el.type==='checkbox')return el.checked?'yes':'';
    return el.value||'';
  }
  function checkCond(c){
    const val=getFieldValue(c.fieldId).toLowerCase().trim();
    const cv=(c.value||'').toLowerCase().trim();
    switch(c.operator){
      case'eq':return val===cv;
      case'neq':return val!==cv;
      case'contains':return val.includes(cv);
      case'gt':return parseFloat(val)>parseFloat(cv);
      case'lt':return parseFloat(val)<parseFloat(cv);
      case'empty':return val==='';
      case'notempty':return val!=='';
      default:return true;
    }
  }
  function evalAll(){
    fields.forEach(function(wrap){
      const conds=wrap.dataset.conditions;
      if(!conds)return;
      let rules;try{rules=JSON.parse(conds);}catch(e){return;}
      const show=rules.every(function(c){
        const result=checkCond(c);
        return c.action==='hide'?!result:result;
      });
      wrap.style.display=show?'':'none';
    });
  }
  document.querySelectorAll('input,select,textarea').forEach(function(el){
    el.addEventListener('change',evalAll);el.addEventListener('input',evalAll);
  });
  evalAll();
})();

// ── Form submission ──
(function(){
  const form=document.getElementById('sf-form');
  if(!form)return;
  ${isEmbed ? `
  function reportHeight(){const h=document.body.scrollHeight;window.parent.postMessage({type:'sf-resize',height:h},'*');}
  reportHeight();new ResizeObserver(reportHeight).observe(document.body);
  ` : ''}
  form.addEventListener('submit',async function(e){
    e.preventDefault();
    const btn=form.querySelector('.sf-btn'),msg=document.getElementById('sf-msg');
    btn.disabled=true;btn.textContent='Submitting\u2026';msg.style.display='none';
    const data=new URLSearchParams(new FormData(form));
    try{
      const r=await fetch('/subscribe',{method:'POST',body:data});
      const j=await r.json();
      if(j.success){
        msg.className='sf-msg success';msg.textContent='${successMsg.replace(/'/g,"\\'")}';
        form.reset();
        ${isEmbed ? `window.parent.postMessage({type:'sf-success'},'*');` : ''}
      }else{
        msg.className='sf-msg error';msg.textContent=j.error||'${errorMsg.replace(/'/g,"\\'")}';
        btn.disabled=false;btn.textContent='${btnText.replace(/'/g,"\\'")}';
      }
    }catch(err){
      msg.className='sf-msg error';msg.textContent='Network error. Please try again.';
      btn.disabled=false;btn.textContent='${btnText.replace(/'/g,"\\'")}';
    }
    msg.style.display='block';
    ${isEmbed ? 'reportHeight();' : ''}
  });
})();`;
}

// ── Public page ───────────────────────────────────────────────────────────────
function renderPublicPage(cfg) {
  const d = cfg.design, s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');
  const formFieldsHtml = cfg.fields.map(f => renderFormField(f, cfg)).join('');

  const bgStyle = d.backgroundImage
    ? `background: linear-gradient(rgba(0,0,0,${d.backgroundOverlay}),rgba(0,0,0,${d.backgroundOverlay})), url('${d.backgroundImage}') center/cover no-repeat fixed; color: #fff;`
    : `background: ${d.backgroundColor};`;

  const blocksHtml = cfg.sections.map(sec =>
    renderBlock(sec, cfg, formFieldsHtml, formSection, s)
  ).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${s.title}</title>
${googleFontTag(cfg)}
${s.favicon ? `<link rel="icon" href="${s.favicon}">` : ''}
<style>
${renderPageCSS(cfg)}
body { ${bgStyle} }
</style>
${s.captchaEnabled && s.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
</head>
<body>
<div class="sf-card">
${blocksHtml}
</div>

<div id="sf-cookie" style="display:none">
  <span>${s.cookieBannerText} <a href="${s.privacyPolicyUrl}">Learn more</a></span>
  <button id="sf-cookie-accept">Accept</button>
</div>

<script>
${renderPageJS(cfg, formSection, false)}
</script>
</body>
</html>`;
}

// ── Embed page ────────────────────────────────────────────────────────────────
function renderEmbedPage(cfg) {
  const d = cfg.design, s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');
  const formFieldsHtml = cfg.fields.map(f => renderFormField(f, cfg)).join('');
  const blocksHtml = cfg.sections.map(sec =>
    renderBlock(sec, cfg, formFieldsHtml, formSection, s)
  ).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${s.title}</title>
${googleFontTag(cfg)}
${s.captchaEnabled && s.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
<style>
${renderPageCSS(cfg)}
html,body{background:transparent;}
body{padding:4px 2px 16px;}
.sf-card{box-shadow:none;padding:8px 4px;}
</style>
</head>
<body>
<div class="sf-card">
${blocksHtml}
</div>
<script>
${renderPageJS(cfg, formSection, true)}
</script>
</body>
</html>`;
}

// ── Other page renderers (unchanged) ─────────────────────────────────────────
function renderUnsubscribePage(cfg, message, success, isDelete = false) {
  const d = cfg.design;
  const title = isDelete ? 'Delete My Data' : 'Unsubscribe';
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · ${cfg.site.title}</title>
${googleFontTag(cfg)}
<style>
  body{font-family:'${d.bodyFont}',sans-serif;background:${d.backgroundColor};min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px;}
  .card{background:#fff;border-radius:12px;padding:40px;max-width:440px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,.1);text-align:center;}
  h1{font-family:'${d.googleFont}',serif;color:${d.primaryColor};margin-bottom:16px;}
  p{color:#555;line-height:1.6;margin-bottom:20px;}
  .success{color:#155724;background:#d4edda;padding:14px;border-radius:6px;}
  .error{color:#721c24;background:#f8d7da;padding:14px;border-radius:6px;}
  a{color:${d.accentColor};}
</style></head><body>
<div class="card">
  <h1>${title}</h1>
  ${message ? `<p class="${success?'success':'error'}">${message}</p>` : '<p>Processing your request…</p>'}
  <p><a href="/">← Back to home</a></p>
</div></body></html>`;
}

function renderPrivacyPage(cfg) {
  const d = cfg.design, s = cfg.site;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy · ${s.title}</title>
${googleFontTag(cfg)}
<style>
  body{font-family:'${d.bodyFont}',sans-serif;background:${d.backgroundColor};color:${d.textColor};padding:60px 20px;}
  .wrap{max-width:720px;margin:0 auto;background:#fff;padding:48px;border-radius:12px;box-shadow:0 4px 30px rgba(0,0,0,.08);}
  h1{font-family:'${d.googleFont}',serif;color:${d.primaryColor};margin-bottom:24px;}
  h2{font-family:'${d.googleFont}',serif;color:${d.primaryColor};margin:32px 0 12px;font-size:1.2rem;}
  p,li{line-height:1.7;margin-bottom:12px;} a{color:${d.accentColor};} ul{padding-left:20px;}
</style></head><body>
<div class="wrap">
  <h1>Privacy Policy</h1>
  <p><strong>Last updated:</strong> ${new Date().toLocaleDateString('en-GB',{year:'numeric',month:'long',day:'numeric'})}</p>
  <h2>1. Who we are</h2><p>This website operates the newsletter signup service "${s.title}".</p>
  <h2>2. What data we collect</h2><ul><li>Your email address (required)</li><li>Name and any other fields on the signup form</li><li>Your IP address and timestamp at time of subscription</li></ul>
  <h2>3. How we use your data</h2><p>We use your data solely to send you newsletters you signed up for. We do not sell or share your data.</p>
  <h2>4. Legal basis (GDPR)</h2><p>We process your data on the basis of your explicit consent.</p>
  <h2>5. Your rights</h2><ul><li><strong>Unsubscribe:</strong> <a href="/unsubscribe">/unsubscribe</a></li><li><strong>Right to erasure:</strong> Via the link in your confirmation email</li><li><strong>Right to access:</strong> Contact us to receive a copy of your stored data</li></ul>
  <h2>6. Cookies</h2><p>We use a single localStorage item to remember cookie consent. No tracking cookies are used.</p>
  <h2>7. Contact</h2><p>For data-related requests, please contact the site administrator.</p>
  <p style="margin-top:32px"><a href="/">← Back</a></p>
</div></body></html>`;
}

function renderEmbedScript(origin, cfg) {
  return `/* SignFlow Embed — ${origin} */
(function(w,d){'use strict';
  var ORIGIN='${origin}';
  var containers=d.querySelectorAll('[data-signflow]');
  if(!containers.length){var scripts=d.querySelectorAll('script[src*="embed.js"]');if(scripts.length)containers=[scripts[scripts.length-1].parentNode];}
  containers.forEach(function(container){
    var width=container.getAttribute('data-width')||'100%';
    var radius=container.getAttribute('data-radius')||'12px';
    var shadow=container.getAttribute('data-shadow')!=='false';
    var minH=parseInt(container.getAttribute('data-min-height')||'400',10);
    var iframe=d.createElement('iframe');
    iframe.src=ORIGIN+'/embed';iframe.title='Newsletter Signup';
    iframe.setAttribute('frameborder','0');iframe.setAttribute('scrolling','no');iframe.setAttribute('allowtransparency','true');
    iframe.style.cssText=['display:block','width:'+width,'min-height:'+minH+'px','height:'+minH+'px','border:none','border-radius:'+radius,'box-shadow:'+(shadow?'0 4px 30px rgba(0,0,0,0.12)':'none'),'background:transparent','overflow:hidden','transition:height 0.3s ease'].join(';');
    container.innerHTML='';container.appendChild(iframe);
  });
  w.addEventListener('message',function(e){
    if(!e.data||e.origin!==ORIGIN)return;
    if(e.data.type==='sf-resize'){d.querySelectorAll('iframe[src*="'+ORIGIN+'/embed"]').forEach(function(fr){fr.style.height=(e.data.height+20)+'px';});}
    if(e.data.type==='sf-success'){w.dispatchEvent(new CustomEvent('signflow:success'));}
  });
})(window,document);`;
}

function renderAccessDeniedPage(email) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Access Denied</title>
<style>body{font-family:system-ui,sans-serif;background:#f5f5f7;min-height:100vh;display:flex;align-items:center;justify-content:center;}.box{background:#fff;border-radius:12px;padding:48px 40px;max-width:420px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.1);}h1{font-size:1.4rem;color:#1a1a2e;margin-bottom:12px;}p{color:#666;line-height:1.6;margin-bottom:20px;font-size:0.95rem;}a{display:inline-block;padding:10px 24px;background:#e94560;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;}</style></head><body>
<div class="box"><h1>⛔ Access Denied</h1><p>The account <strong>${email}</strong> is not authorised.</p><p>You need the <code>${AUTH0_ADMIN_ROLE}</code> role assigned in Auth0.</p><a href="/auth/logout">Sign out</a></div></body></html>`;
}

// ── Start ──────────────────────────────────────────────────────────────────────
(async () => {
  await initAuth0();
  app.listen(PORT, () => {
    console.log(`\n✅ SignFlow running at http://localhost:${PORT}`);
    console.log(`   Admin panel : http://localhost:${PORT}/admin`);
    console.log(`   Auth login  : http://localhost:${PORT}/auth/login`);
    console.log(`   Auth0 domain: ${AUTH0_DOMAIN || '(not configured)'}\n`);
  });
})();
