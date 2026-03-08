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

// ── Auth0 config (from .env) ──────────────────────────────────────────────────
const AUTH0_DOMAIN        = process.env.AUTH0_DOMAIN        || '';   // e.g. dev-abc123.us.auth0.com
const AUTH0_CLIENT_ID     = process.env.AUTH0_CLIENT_ID     || '';
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET || '';
const AUTH0_CALLBACK_URL  = process.env.AUTH0_CALLBACK_URL  || `http://localhost:${PORT}/auth/callback`;
const AUTH0_ADMIN_ROLE    = process.env.AUTH0_ADMIN_ROLE    || 'signflow-admin';
const SESSION_SECRET      = process.env.SESSION_SECRET      || uuidv4(); // must be set in .env in production!

// ── hCaptcha secret (from .env) ───────────────────────────────────────────────
const ENV_HCAPTCHA_SECRET = process.env.SF_HCAPTCHA_SECRET || null;

// ── Paths ─────────────────────────────────────────────────────────────────────
const DATA_DIR        = path.join(__dirname, 'data');
const CONFIG_FILE     = path.join(DATA_DIR, 'config.json');
const SUBSCRIBERS_FILE = path.join(DATA_DIR, 'subscribers.json');
const UPLOADS_DIR     = path.join(__dirname, 'public', 'uploads');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── OIDC client (initialised async at startup) ────────────────────────────────
let oidcClient = null;

async function initAuth0() {
  if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET) {
    console.warn('⚠ Auth0 env vars not set — admin login will be unavailable.');
    return;
  }
  try {
    const issuer = await Issuer.discover(`https://${AUTH0_DOMAIN}/`);
    oidcClient = new issuer.Client({
      client_id:                AUTH0_CLIENT_ID,
      client_secret:            AUTH0_CLIENT_SECRET,
      redirect_uris:            [AUTH0_CALLBACK_URL],
      response_types:           ['code'],
      token_endpoint_auth_method: 'client_secret_post',
    });
    console.log(`✔ Auth0 OIDC client ready (${AUTH0_DOMAIN})`);
  } catch (e) {
    console.error('✖ Auth0 init failed:', e.message);
  }
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.set('trust proxy', 1);
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true, // true behind HTTPS
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000  // 8-hour session
  }
}));

// ── Static files ──────────────────────────────────────────────────────────────
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/admin',   express.static(path.join(__dirname, 'admin')));

// ── Multer ────────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Images only'));
  }
});

// ── Rate limiting ─────────────────────────────────────────────────────────────
const submitLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  message: { error: 'Too many requests' } });
const adminLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });

// ── Config helpers ────────────────────────────────────────────────────────────
function readConfig() {
  const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
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
// Extracts roles from Auth0 token claims.
// Auth0 injects roles via a custom namespace action — see setup instructions.
function getRoles(tokenClaims) {
  // Auth0 adds roles under a custom namespace claim
  const NS = `https://signflow/roles`;
  return tokenClaims[NS] || tokenClaims['https://signflow.app/roles'] || [];
}

function isAdminUser(session) {
  if (!session || !session.user) return false;
  const roles = getRoles(session.user);
  return roles.includes(AUTH0_ADMIN_ROLE);
}

// ── Admin auth middleware ─────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  if (isAdminUser(req.session)) return next();
  // API routes return JSON; browser routes redirect to login
  const isApi = req.path.startsWith('/api/');
  if (isApi) return res.status(401).json({ error: 'Unauthorized' });
  req.session.returnTo = req.originalUrl;
  res.redirect('/auth/login');
}

// ════════════════════════════════════════
// PUBLIC ROUTES
// ════════════════════════════════════════

// Serve the live signup page (rendered server-side from config)
app.get('/', (req, res) => {
  const cfg = readConfig();
  res.send(renderPublicPage(cfg));
});

// Privacy policy page
app.get('/privacy', (req, res) => {
  const cfg = readConfig();
  res.send(renderPrivacyPage(cfg));
});

// Unsubscribe page
app.get('/unsubscribe', (req, res) => {
  const { token, email } = req.query;
  const cfg = readConfig();
  let message = '';
  let success = false;

  if (token && email) {
    const subs = readSubscribers();
    const idx = subs.findIndex(s => s.email === decodeURIComponent(email) && s.unsubscribeToken === token);
    if (idx !== -1) {
      subs[idx].status = 'unsubscribed';
      subs[idx].unsubscribedAt = new Date().toISOString();
      writeSubscribers(subs);
      message = 'You have been successfully unsubscribed.';
      success = true;
    } else {
      message = 'Invalid or expired unsubscribe link.';
    }
  }

  res.send(renderUnsubscribePage(cfg, message, success));
});

// GDPR: Delete my data
app.get('/delete-data', (req, res) => {
  const { token, email } = req.query;
  const cfg = readConfig();
  let message = '';
  let success = false;

  if (token && email) {
    const subs = readSubscribers();
    const idx = subs.findIndex(s => s.email === decodeURIComponent(email) && s.unsubscribeToken === token);
    if (idx !== -1) {
      subs.splice(idx, 1);
      writeSubscribers(subs);
      message = 'Your data has been permanently deleted from our records.';
      success = true;
    } else {
      message = 'Invalid or expired link.';
    }
  }

  res.send(renderUnsubscribePage(cfg, message, success, true));
});

// Form submission
app.post('/subscribe', submitLimiter, async (req, res) => {
  const cfg = readConfig();
  const subs = readSubscribers();
  const body = req.body;

  // ── hCaptcha verification ──
  if (cfg.site.captchaEnabled && cfg.site.hcaptchaSecretKey) {
    const captchaToken = body['h-captcha-response'] || '';
    if (!captchaToken) {
      return res.status(400).json({ error: 'Please complete the CAPTCHA.' });
    }
    try {
      const verifyParams = new URLSearchParams({
        secret: cfg.site.hcaptchaSecretKey,
        response: captchaToken,
        remoteip: req.ip
      });
      const verifyRes = await fetch('https://api.hcaptcha.com/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: verifyParams.toString()
      });
      const verifyJson = await verifyRes.json();
      if (!verifyJson.success) {
        return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
      }
    } catch (e) {
      console.error('hCaptcha verify error:', e);
      return res.status(500).json({ error: 'CAPTCHA service error. Please try again.' });
    }
  }

  const email = (body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Valid email required.' });
  }

  // Check duplicate
  const existing = subs.find(s => s.email === email);
  if (existing && existing.status === 'active') {
    return res.status(409).json({ error: 'This email is already subscribed.' });
  }

  // Build subscriber record from config fields
  const record = {
    id: uuidv4(),
    email,
    status: 'active',
    subscribedAt: new Date().toISOString(),
    unsubscribedAt: null,
    unsubscribeToken: uuidv4(),
    consentGiven: true,
    consentTimestamp: new Date().toISOString(),
    ipAddress: req.ip,
    customFields: {}
  };

  cfg.fields.filter(f => !f.system).forEach(field => {
    const val = (body[field.id] || '').trim();
    if (field.required && !val) {
      // will be caught client-side but double check
    }
    record.customFields[field.id] = val;
  });

  if (existing) {
    // re-subscribe
    const idx = subs.findIndex(s => s.email === email);
    subs[idx] = { ...subs[idx], ...record };
  } else {
    subs.push(record);
  }

  writeSubscribers(subs);
  res.json({ success: true });
});

// ════════════════════════════════════════
// AUTH0 ROUTES
// ════════════════════════════════════════

// Kick off Auth0 login
app.get('/auth/login', adminLimiter, (req, res) => {
  if (!oidcClient) {
    return res.status(503).send('Auth0 is not configured. Set AUTH0_* env vars and restart.');
  }
  const nonce        = generators.nonce();
  const state        = generators.state();
  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);

  req.session.authNonce        = nonce;
  req.session.authState        = state;
  req.session.authCodeVerifier = codeVerifier;

  const authUrl = oidcClient.authorizationUrl({
    scope:                  'openid profile email',
    audience:               `https://${AUTH0_DOMAIN}/api/v2/`,
    response_type:          'code',
    nonce,
    state,
    code_challenge:         codeChallenge,
    code_challenge_method:  'S256',
  });
  res.redirect(authUrl);
});

// Auth0 callback
app.get('/auth/callback', adminLimiter, async (req, res) => {
  if (!oidcClient) return res.status(503).send('Auth0 not configured.');
  try {
    const params       = oidcClient.callbackParams(req);
    const tokenSet     = await oidcClient.callback(
      AUTH0_CALLBACK_URL,
      params,
      {
        nonce:         req.session.authNonce,
        state:         req.session.authState,
        code_verifier: req.session.authCodeVerifier,
      }
    );
    const claims = tokenSet.claims();

    // Check role
    const roles = getRoles(claims);
    if (!roles.includes(AUTH0_ADMIN_ROLE)) {
      req.session.destroy(() => {});
      return res.status(403).send(renderAccessDeniedPage(claims.email || 'unknown'));
    }

    // Store user in session
    req.session.user = claims;
    req.session.accessToken = tokenSet.access_token;
    delete req.session.authNonce;
    delete req.session.authState;
    delete req.session.authCodeVerifier;

    const returnTo = req.session.returnTo || '/admin';
    delete req.session.returnTo;
    res.redirect(returnTo);
  } catch (e) {
    console.error('Auth0 callback error:', e.message);
    res.status(500).send(`Authentication failed: ${e.message}`);
  }
});

// Logout
app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => {});
  if (AUTH0_DOMAIN) {
    const returnTo = encodeURIComponent(`${AUTH0_CALLBACK_URL.replace('/auth/callback', '')}`);
    res.redirect(`https://${AUTH0_DOMAIN}/v2/logout?client_id=${AUTH0_CLIENT_ID}&returnTo=${returnTo}`);
  } else {
    res.redirect('/');
  }
});

// Session check endpoint — called by admin SPA on load
app.get('/auth/me', (req, res) => {
  if (isAdminUser(req.session)) {
    const { name, email, picture } = req.session.user;
    res.json({ authenticated: true, name, email, picture });
  } else {
    res.json({ authenticated: false });
  }
});

// Admin panel — protected by session
app.get('/admin', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

// Get config
app.get('/api/admin/config', adminAuth, (req, res) => {
  res.json(readConfig());
});

// Save config
app.post('/api/admin/config', adminAuth, (req, res) => {
  const current = readConfig();
  const updated = req.body;
  // Merge carefully
  writeConfig(updated);
  res.json({ success: true });
});

// Upload image
app.post('/api/admin/upload', adminAuth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// Get subscribers (paginated)
app.get('/api/admin/subscribers', adminAuth, (req, res) => {
  const subs = readSubscribers();
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const search = (req.query.search || '').toLowerCase();
  const status = req.query.status || 'all';

  let filtered = subs;
  if (search) filtered = filtered.filter(s => s.email.includes(search) || JSON.stringify(s.customFields).toLowerCase().includes(search));
  if (status !== 'all') filtered = filtered.filter(s => s.status === status);

  const total = filtered.length;
  const paginated = filtered.slice((page - 1) * limit, page * limit);
  res.json({ subscribers: paginated, total, page, pages: Math.ceil(total / limit) });
});

// Delete subscriber (GDPR)
app.delete('/api/admin/subscribers/:id', adminAuth, (req, res) => {
  const subs = readSubscribers();
  const idx = subs.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  subs.splice(idx, 1);
  writeSubscribers(subs);
  res.json({ success: true });
});

// Export subscribers
app.get('/api/admin/export', adminAuth, (req, res) => {
  const cfg = readConfig();
  const subs = readSubscribers();
  const fmt = req.query.format || 'csv';

  if (fmt === 'json') {
    res.setHeader('Content-Disposition', 'attachment; filename="subscribers.json"');
    res.setHeader('Content-Type', 'application/json');
    return res.send(JSON.stringify(subs, null, 2));
  }

  // CSV
  const customFieldIds = cfg.fields.filter(f => !f.system).map(f => f.id);
  const headers = ['id', 'email', 'status', 'subscribedAt', 'unsubscribedAt', 'consentGiven', 'consentTimestamp', 'ipAddress', ...customFieldIds];
  const rows = subs.map(s => {
    return headers.map(h => {
      if (customFieldIds.includes(h)) return `"${(s.customFields[h] || '').replace(/"/g, '""')}"`;
      return `"${(s[h] || '').toString().replace(/"/g, '""')}"`;
    }).join(',');
  });
  const csv = [headers.join(','), ...rows].join('\n');
  res.setHeader('Content-Disposition', 'attachment; filename="subscribers.csv"');
  res.setHeader('Content-Type', 'text/csv');
  res.send(csv);
});

// ════════════════════════════════════════
// EMBED ROUTES
// ════════════════════════════════════════

// Frameable embed page — no card shadow, transparent bg, auto-reports height
app.get('/embed', (req, res) => {
  const cfg = readConfig();
  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', "frame-ancestors *");
  res.send(renderEmbedPage(cfg));
});

// JS snippet — drop one <script> tag on any site
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
  const query = fonts.map(f => f.replace(/ /g, '+')).join('&family=');
  return `<link href="https://fonts.googleapis.com/css2?family=${query}:wght@300;400;600;700&display=swap" rel="stylesheet">`;
}

// ── Shared field renderer ─────────────────────────────────────────────────────
function renderFormField(f, cfg) {
  const d = cfg.design;
  const accent = d.accentColor || '#e94560';
  const req = f.required ? ' <span class="req">*</span>' : '';
  const condAttr = (f.conditions && f.conditions.length)
    ? ` data-sf-cond='${JSON.stringify(f.conditions)}'` : '';

  // ── select ──
  if (f.type === 'select') {
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      <select id="sf_${f.id}" name="${f.id}" ${f.required ? 'required' : ''}>
        <option value="">— Select —</option>
        ${(f.options || []).map(o => `<option value="${o}">${o}</option>`).join('')}
      </select></div>`;
  }

  // ── checkbox ──
  if (f.type === 'checkbox') {
    return `<div class="sf-field sf-field--check"${condAttr}>
      <label><input type="checkbox" name="${f.id}" value="yes" ${f.required ? 'required' : ''}> ${f.label}${req}</label></div>`;
  }

  // ── textarea ──
  if (f.type === 'textarea') {
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      <textarea id="sf_${f.id}" name="${f.id}" placeholder="${f.placeholder || ''}" ${f.required ? 'required' : ''} rows="3"></textarea></div>`;
  }

  // ── age ──
  if (f.type === 'age') {
    const curYear = new Date().getFullYear();
    const minAge = f.minAge || 0;
    const maxAge = f.maxAge || 120;
    const minYear = curYear - maxAge;
    const maxYear = curYear - minAge;
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      <input type="number" id="sf_${f.id}" name="${f.id}" placeholder="Your age"
        min="${minAge}" max="${maxAge}" ${f.required ? 'required' : ''}
        data-sf-age-min="${minAge}" data-sf-age-max="${maxAge}"></div>`;
  }

  // ── date ──
  if (f.type === 'date') {
    const minAttr = f.minDate ? `min="${f.minDate}"` : '';
    const maxAttr = f.maxDate ? `max="${f.maxDate}"` : '';
    const listId = f.dateMode === 'specific' && f.allowedDates && f.allowedDates.length
      ? `sf_datalist_${f.id}` : '';
    const datalist = listId
      ? `<datalist id="${listId}">${f.allowedDates.map(d => `<option value="${d}">`).join('')}</datalist>` : '';
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${f.label}${req}</label>
      ${datalist}
      <input type="date" id="sf_${f.id}" name="${f.id}"
        ${minAttr} ${maxAttr} ${listId ? `list="${listId}"` : ''} ${f.required ? 'required' : ''}></div>`;
  }

  // ── year ──
  if (f.type === 'year') {
    const minY = f.minYear || 1920;
    const maxY = f.maxYear || new Date().getFullYear();
    const mid = Math.round((minY + maxY) / 2);
    const years = [];
    for (let y = maxY; y >= minY; y--) years.push(y);
    return `<div class="sf-field sf-field--picker"${condAttr}>
      <label>${f.label}${req}</label>
      <div class="sf-picker-wrap">
        <div class="sf-picker-drum" id="sf_drum_${f.id}">
          ${years.map(y => `<div class="sf-pick-item" data-val="${y}">${y}</div>`).join('')}
        </div>
        <div class="sf-picker-overlay"></div>
      </div>
      <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${mid}"></div>`;
  }

  // ── yearmonth ──
  if (f.type === 'yearmonth') {
    const minY = f.minYear || 1920;
    const maxY = f.maxYear || new Date().getFullYear();
    const midY = Math.round((minY + maxY) / 2);
    const years = [];
    for (let y = maxY; y >= minY; y--) years.push(y);
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return `<div class="sf-field sf-field--picker"${condAttr}>
      <label>${f.label}${req}</label>
      <div class="sf-picker-wrap sf-picker-dual">
        <div class="sf-picker-drum" id="sf_drum_m_${f.id}">
          ${months.map((m, i) => `<div class="sf-pick-item" data-val="${String(i+1).padStart(2,'0')}">${m}</div>`).join('')}
        </div>
        <div class="sf-picker-drum" id="sf_drum_y_${f.id}">
          ${years.map(y => `<div class="sf-pick-item" data-val="${y}">${y}</div>`).join('')}
        </div>
        <div class="sf-picker-overlay"></div>
      </div>
      <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${midY}-01"></div>`;
  }

  // ── slider ──
  if (f.type === 'slider') {
    const track   = f.trackStyle  || 'linear';
    const mode    = f.slideMode   || 'smooth';
    const icon    = f.knobIcon    || '●';
    const showVal = f.showValue   !== false;
    const min     = f.min         ?? 0;
    const max     = f.max         ?? 100;
    const step    = f.step        ?? 1;
    const def     = f.defaultValue ?? Math.round((min + max) / 2);
    const knobPx  = f.knobSize    || 32;
    const trackPx = f.trackSize   || 6;
    const minLbl  = f.minLabel    || '';
    const maxLbl  = f.maxLabel    || '';
    const valSize = f.valueSize   || 14;
    const pct     = ((def - min) / (max - min)) * 100;

    const dataAttrs = `data-min="${min}" data-max="${max}" data-step="${step}" data-mode="${mode}" data-track="${track}"`;

    if (track === 'arc') {
      // Upper semicircle: center (110,110), R=90. Left=(20,110) pct=0, Right=(200,110) pct=1.
      // Clockwise rotation from left: 0° = min, 180° = max.
      const R = 90, CX = 110, CY = 110;
      const arcLen = Math.PI * R; // ≈ 283
      const fillLen = (pct / 100) * arcLen;
      const initRot = pct * 1.8; // deg = pct(0-100) * 1.8  →  0°…180°
      return `<div class="sf-field sf-field--slider"${condAttr}>
        <label>${f.label}${req}</label>
        <div class="sf-slider-wrap sf-slider-arc" style="--sf-accent:${accent};--sf-knob:${knobPx}px;--sf-val-size:${valSize}px">
          <svg class="sf-arc-svg" viewBox="0 0 220 125" xmlns="http://www.w3.org/2000/svg" style="touch-action:none;overflow:visible">
            <path class="sf-arc-bg" d="M 20 110 A 90 90 0 0 1 200 110" fill="none" stroke="#e0e0e0" stroke-width="${trackPx}" stroke-linecap="round"/>
            <path class="sf-arc-fill" d="M 20 110 A 90 90 0 0 1 200 110" fill="none" stroke="${accent}" stroke-width="${trackPx}" stroke-linecap="round"
              stroke-dasharray="${fillLen} ${arcLen}" stroke-dashoffset="0"/>
            <g class="sf-arc-handle" transform="rotate(${initRot} ${CX} ${CY})" style="cursor:grab;touch-action:none">
              <circle cx="${CX - R}" cy="${CY}" r="${knobPx / 2}" fill="${accent}"/>
              <text x="${CX - R}" y="${CY + 1}" text-anchor="middle" dominant-baseline="middle"
                font-size="${knobPx * 0.48}" fill="#fff" style="pointer-events:none;user-select:none">${icon}</text>
            </g>
            ${(minLbl || maxLbl) ? `
            <text x="20" y="122" text-anchor="middle" font-size="10" fill="#aaa">${minLbl}</text>
            <text x="200" y="122" text-anchor="middle" font-size="10" fill="#aaa">${maxLbl}</text>` : ''}
          </svg>
          ${showVal ? `<div class="sf-slider-val" style="font-size:var(--sf-val-size)">${def}</div>` : ''}
          <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${def}" ${dataAttrs} ${f.required ? 'required' : ''}>
        </div></div>`;
    }

    // linear or angled — labels go BELOW the track to avoid overlap
    const angledClass = track === 'angled' ? ' sf-slider-angled' : '';
    return `<div class="sf-field sf-field--slider"${condAttr}>
      <label>${f.label}${req}</label>
      <div class="sf-slider-wrap${angledClass}" style="--sf-accent:${accent};--sf-knob:${knobPx}px;--sf-track:${trackPx}px;--sf-val-size:${valSize}px">
        <div class="sf-slider-track" style="touch-action:none">
          <div class="sf-slider-fill" style="width:${pct}%"></div>
          <div class="sf-slider-handle" tabindex="0" role="slider"
            aria-valuemin="${min}" aria-valuemax="${max}" aria-valuenow="${def}"
            style="left:${pct}%">
            <span class="sf-slider-icon">${icon}</span>
          </div>
        </div>
        ${(minLbl || maxLbl) ? `<div class="sf-slider-lbls"><span>${minLbl}</span><span>${maxLbl}</span></div>` : ''}
        ${showVal ? `<div class="sf-slider-val" style="font-size:var(--sf-val-size)">${def}</div>` : ''}
        <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${def}" ${dataAttrs} ${f.required ? 'required' : ''}>
      </div></div>`;
  }

  // ── default (text, email, number, tel, etc.) ──
  return `<div class="sf-field"${condAttr}>
    <label for="sf_${f.id}">${f.label}${req}</label>
    <input type="${f.type || 'text'}" id="sf_${f.id}" name="${f.id}"
      placeholder="${f.placeholder || ''}" ${f.required ? 'required' : ''}></div>`;
}

// ── Slider + picker CSS (injected into page <style>) ─────────────────────────
function sliderPickerCSS(accent) {
  return `
  /* Picker (year / yearmonth) */
  .sf-field--picker .sf-picker-wrap{position:relative;height:120px;overflow:hidden;border:2px solid #e0e0e0;border-radius:8px;background:#fafafa;user-select:none;}
  .sf-picker-dual{display:flex;}
  .sf-picker-dual .sf-picker-drum{flex:1;border-right:1px solid #e0e0e0;}
  .sf-picker-dual .sf-picker-drum:last-child{border-right:none;}
  .sf-picker-drum{overflow-y:scroll;height:100%;scrollbar-width:none;scroll-snap-type:y mandatory;-webkit-overflow-scrolling:touch;}
  .sf-picker-drum::-webkit-scrollbar{display:none;}
  .sf-pick-item{height:40px;display:flex;align-items:center;justify-content:center;font-size:1rem;color:#555;scroll-snap-align:center;cursor:pointer;}
  .sf-pick-item.active{color:${accent};font-weight:700;font-size:1.1rem;}
  .sf-picker-overlay{position:absolute;inset:0;pointer-events:none;background:linear-gradient(to bottom,rgba(250,250,250,.85) 0%,transparent 35%,transparent 65%,rgba(250,250,250,.85) 100%);}
  .sf-picker-overlay::after{content:'';position:absolute;top:50%;left:4px;right:4px;height:40px;transform:translateY(-50%);border-top:2px solid ${accent};border-bottom:2px solid ${accent};border-radius:4px;}

  /* Slider shared */
  .sf-field--slider .sf-slider-wrap{padding:4px 0 8px;position:relative;}
  .sf-slider-lbls{display:flex;justify-content:space-between;font-size:0.75rem;color:#aaa;margin-bottom:6px;}
  .sf-slider-lbls--arc{margin-bottom:0;margin-top:4px;padding:0 8px;}
  .sf-slider-val{text-align:center;font-weight:700;color:${accent};margin-top:8px;line-height:1;}

  /* Linear/Angled slider */
  .sf-slider-track{position:relative;height:var(--sf-track,6px);background:#e0e0e0;border-radius:99px;cursor:pointer;margin:calc(var(--sf-knob,32px)/2) 0;}
  .sf-slider-fill{position:absolute;left:0;top:0;height:100%;background:var(--sf-accent,#e94560);border-radius:99px;pointer-events:none;transition:width .05s linear;}
  .sf-slider-handle{position:absolute;top:50%;transform:translate(-50%,-50%);width:var(--sf-knob,32px);height:var(--sf-knob,32px);background:var(--sf-accent,#e94560);border-radius:50%;cursor:grab;display:flex;align-items:center;justify-content:center;touch-action:none;user-select:none;pointer-events:none;box-shadow:0 2px 8px rgba(0,0,0,.25);z-index:2;}
  .sf-slider-handle:active{cursor:grabbing;}
  .sf-slider-icon{font-size:calc(var(--sf-knob,32px) * 0.48);line-height:1;pointer-events:none;user-select:none;}

  /* Angled */
  .sf-field--slider{overflow:visible;}
  .sf-slider-angled{padding:20px 0 28px;overflow:visible;}
  .sf-slider-angled .sf-slider-track{transform:rotate(-8deg);transform-origin:center;overflow:visible;}
  .sf-slider-angled .sf-slider-handle{transition:none;}

  /* Arc slider */
  .sf-slider-arc .sf-arc-svg{width:100%;max-width:220px;display:block;margin:0 auto;overflow:visible;}
  .sf-arc-handle{transition:transform .05s linear;}`;
}

// ── Slider + picker JS (injected at end of page <script>) ────────────────────
function sliderPickerJS() {
  return `
(function(){
  /* ── Picker drums (year / yearmonth) ── */
  document.querySelectorAll('.sf-picker-drum').forEach(function(drum){
    var inp=drum.closest('.sf-field--picker').querySelector('input[type=hidden]');
    var isMonth=drum.id&&drum.id.includes('_m_');
    var items=drum.querySelectorAll('.sf-pick-item');
    var itemH=40;
    // scroll to middle item initially
    var mid=Math.floor(items.length/2);
    drum.scrollTop=mid*itemH;
    function update(){
      var idx=Math.round(drum.scrollTop/itemH);
      idx=Math.max(0,Math.min(items.length-1,idx));
      items.forEach(function(el,i){el.classList.toggle('active',i===idx);});
      var val=items[idx]?items[idx].dataset.val:'';
      if(isMonth){
        var cur=inp.value||'';var parts=cur.split('-');
        inp.value=(parts[0]||new Date().getFullYear())+'-'+val;
      } else {
        var cur2=inp.value||'';
        if(cur2.includes('-')){var p2=cur2.split('-');inp.value=val+'-'+(p2[1]||'01');}
        else inp.value=val;
      }
    }
    drum.addEventListener('scroll',function(){clearTimeout(drum._st);drum._st=setTimeout(update,80);},{passive:true});
    update();
  });

  /* ── Linear / Angled slider ── */
  document.querySelectorAll('.sf-slider-track').forEach(function(track){
    var wrap=track.closest('.sf-slider-wrap');
    var handle=track.querySelector('.sf-slider-handle');
    var fill=track.querySelector('.sf-slider-fill');
    var inp=wrap.querySelector('input[type=hidden]');
    var valEl=wrap.querySelector('.sf-slider-val');
    var min=parseFloat(inp.dataset.min||0);
    var max=parseFloat(inp.dataset.max||100);
    var step=parseFloat(inp.dataset.step||1);
    var isStep=inp.dataset.mode==='step';
    var dragging=false;
    var rect=null;

    function snap(v){
      if(isStep) v=Math.round((v-min)/step)*step+min;
      return Math.max(min,Math.min(max,v));
    }
    function pctFromVal(v){return((v-min)/(max-min))*100;}
    function setVal(v){
      v=snap(v);
      var p=pctFromVal(v);
      fill.style.width=p+'%';
      handle.style.left=p+'%';
      handle.setAttribute('aria-valuenow',v);
      inp.value=v;
      if(valEl) valEl.textContent=v;
    }
    function pctFromClient(clientX){
      // rect is always in screen-space; works for both flat and rotated track
      return Math.max(0,Math.min(100,(clientX-rect.left)/rect.width*100));
    }

    // Capture to TRACK so pointermove always fires on track during drag
    track.addEventListener('pointerdown',function(e){
      dragging=true;
      rect=track.getBoundingClientRect();
      track.setPointerCapture(e.pointerId);
      setVal(snap(min+(max-min)*(pctFromClient(e.clientX)/100)));
      e.preventDefault();
    });
    track.addEventListener('pointermove',function(e){
      if(!dragging)return;
      setVal(snap(min+(max-min)*(pctFromClient(e.clientX)/100)));
    });
    track.addEventListener('pointerup',function(){dragging=false;rect=null;});
    track.addEventListener('pointercancel',function(){dragging=false;rect=null;});
    // keyboard on handle
    handle.addEventListener('keydown',function(e){
      var v=parseFloat(inp.value);
      if(e.key==='ArrowRight'||e.key==='ArrowUp'){setVal(v+step);e.preventDefault();}
      else if(e.key==='ArrowLeft'||e.key==='ArrowDown'){setVal(v-step);e.preventDefault();}
    });
  });

  /* ── Arc slider ── */
  // Upper semicircle: handle at left (CX-R, CY) = pct 0 (0° rotation).
  // Dragging clockwise to right = pct 1 (180° rotation).
  document.querySelectorAll('.sf-slider-arc').forEach(function(wrap){
    var svg=wrap.querySelector('.sf-arc-svg');
    var fillPath=wrap.querySelector('.sf-arc-fill');
    var handleG=wrap.querySelector('.sf-arc-handle');
    var inp=wrap.querySelector('input[type=hidden]');
    var valEl=wrap.querySelector('.sf-slider-val');
    var min=parseFloat(inp.dataset.min||0);
    var max=parseFloat(inp.dataset.max||100);
    var step=parseFloat(inp.dataset.step||1);
    var isStep=inp.dataset.mode==='step';
    var R=90,CX=110,CY=110;
    var arcLen=Math.PI*R;
    var svgRect=null;
    var dragging=false;

    function snap(v){
      if(isStep) v=Math.round((v-min)/step)*step+min;
      return Math.max(min,Math.min(max,v));
    }
    function setArc(v){
      v=snap(v);
      var pct=(v-min)/(max-min);
      fillPath.setAttribute('stroke-dasharray',(pct*arcLen)+' '+arcLen);
      // pct=0 → 0° (handle at left), pct=1 → 180° (handle at right)
      handleG.setAttribute('transform','rotate('+(pct*180)+' '+CX+' '+CY+')');
      inp.value=v;
      if(valEl) valEl.textContent=v;
    }
    function valFromPointer(e){
      // Convert screen coords → SVG viewBox (0 0 220 125)
      var scaleX=220/svgRect.width, scaleY=125/svgRect.height;
      var svgX=(e.clientX-svgRect.left)*scaleX;
      var svgY=(e.clientY-svgRect.top)*scaleY;
      var dx=svgX-CX, dy=svgY-CY;
      // atan2 gives angle from positive-x axis: left=-180°/180°, right=0°, top=-90°
      var angle=Math.atan2(dy,dx)*180/Math.PI;
      // Clamp to upper semicircle [-180, 0]: if below center, snap to nearest end
      if(angle>0) angle=(dx<0)?-180:0;
      // Map [-180, 0] → [0, 1]
      var pct=(angle+180)/180;
      return snap(min+(max-min)*pct);
    }
    svg.addEventListener('pointerdown',function(e){
      svgRect=svg.getBoundingClientRect();
      dragging=true;svg.setPointerCapture(e.pointerId);
      setArc(valFromPointer(e));e.preventDefault();
    });
    svg.addEventListener('pointermove',function(e){
      if(!dragging)return;
      setArc(valFromPointer(e));
    });
    svg.addEventListener('pointerup',function(){dragging=false;svgRect=null;});
    svg.addEventListener('pointercancel',function(){dragging=false;svgRect=null;});
  });

  /* ── Conditional field visibility ── */
  function evalConditions(){
    document.querySelectorAll('[data-sf-cond]').forEach(function(el){
      var conds=JSON.parse(el.dataset.sfCond||'[]');
      var visible=true;
      conds.forEach(function(c){
        var ctrl=document.querySelector('[name="'+c.fieldId+'"]');
        if(!ctrl)return;
        var val=ctrl.value||'';
        var match=false;
        if(c.operator==='eq')match=val===c.value;
        else if(c.operator==='neq')match=val!==c.value;
        else if(c.operator==='contains')match=val.toLowerCase().includes((c.value||'').toLowerCase());
        else if(c.operator==='gt')match=parseFloat(val)>parseFloat(c.value);
        else if(c.operator==='lt')match=parseFloat(val)<parseFloat(c.value);
        else if(c.operator==='empty')match=val.trim()==='';
        else if(c.operator==='notempty')match=val.trim()!=='';
        if(c.action==='show'&&!match)visible=false;
        if(c.action==='hide'&&match)visible=false;
      });
      el.style.display=visible?'':'none';
    });
  }
  document.querySelectorAll('input,select,textarea').forEach(function(el){
    el.addEventListener('input',evalConditions);el.addEventListener('change',evalConditions);
  });
  evalConditions();
})();`;
}

// ── Block element renderer (for content blocks) ─────────────────────────────
function renderBlockElement(el) {
  if (!el) return '';
  switch (el.type) {
    case 'heading': {
      const tag = ['h1','h2','h3','h4'][Math.min((el.level || 2) - 1, 3)];
      return `<${tag} class="sf-el-heading" style="margin:12px 0 6px;line-height:1.3">${el.text || ''}</${tag}>`;
    }
    case 'paragraph':
      return `<p class="sf-el-para" style="margin:8px 0;line-height:1.7">${el.text || ''}</p>`;
    case 'image':
      return el.url ? `<img src="${el.url}" alt="${el.alt || ''}" style="max-width:100%;border-radius:6px;margin:8px 0;display:block">` : '';
    case 'spacer':
      return `<div style="height:${el.height || 40}px"></div>`;
    case 'divider': {
      const color = el.color || '#e0e0e0';
      const thick = el.thickness || 1;
      if (el.style === 'space') return `<div style="height:16px"></div>`;
      if (el.style === 'dots') return `<div style="text-align:center;color:${color};letter-spacing:8px;padding:8px 0">···</div>`;
      if (el.style === 'wave') return `<div style="overflow:hidden;margin:8px 0"><svg viewBox="0 0 200 12" style="width:100%;height:12px" preserveAspectRatio="none"><path d="M0 6 Q 25 0 50 6 Q 75 12 100 6 Q 125 0 150 6 Q 175 12 200 6" stroke="${color}" stroke-width="${thick}" fill="none"/></svg></div>`;
      return `<hr style="border:none;border-top:${thick}px solid ${color};margin:8px 0">`;
    }
    case 'wysiwyg':
      return `<div style="margin:8px 0;line-height:1.7">${el.html || ''}</div>`;
    default:
      return '';
  }
}

// ── Section block renderer (renders any section type) ────────────────────────
function renderSectionBlock(section, cfg, formSection, formFields) {
  if (section.visible === false) return '';
  const d = cfg.design;
  const s = cfg.site;

  // Hero
  if (section.id === 'hero' || section.type === 'hero') {
    const h = section;
    return `
    ${h.imageUrl && h.imagePosition === 'above' ? `<img src="${h.imageUrl}" class="sf-hero-img" alt="">` : ''}
    <h1>${h.heading || ''}</h1>
    ${h.subheading ? `<p class="sf-sub">${h.subheading}</p>` : ''}
    ${h.imageUrl && h.imagePosition === 'below' ? `<img src="${h.imageUrl}" class="sf-hero-img below" alt="">` : ''}`;
  }

  // Form
  if (section.id === 'form' || section.type === 'form') {
    return `
  <form id="sf-form" novalidate>
    ${formFields}
    <div class="sf-gdpr">By subscribing you agree to our <a href="${s.privacyPolicyUrl}" target="_blank">Privacy Policy</a>. We store your data securely and you can unsubscribe or request deletion at any time.</div>
    ${s.captchaEnabled && s.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${s.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
    <button type="submit" class="sf-btn">${d.buttonText}</button>
    <div id="sf-msg" class="sf-msg"></div>
  </form>`;
  }

  // Footer
  if (section.id === 'footer' || section.type === 'footer') {
    return `<p class="sf-footer">${section.text || ''}</p>`;
  }

  // Divider
  if (section.type === 'divider') {
    const color = section.color || '#e0e0e0';
    const thick = section.thickness || 1;
    const sp = section.spacing || 20;
    if (section.style === 'space') return `<div style="height:${sp}px"></div>`;
    if (section.style === 'dots') return `<div style="text-align:center;color:${color};letter-spacing:8px;padding:${sp}px 0;font-size:1.2rem">···</div>`;
    if (section.style === 'wave') return `<div style="margin:${sp}px 0;overflow:hidden"><svg viewBox="0 0 200 12" style="width:100%;height:12px" preserveAspectRatio="none"><path d="M0 6 Q 25 0 50 6 Q 75 12 100 6 Q 125 0 150 6 Q 175 12 200 6" stroke="${color}" stroke-width="${thick}" fill="none"/></svg></div>`;
    return `<hr style="border:none;border-top:${thick}px solid ${color};margin:${sp}px 0">`;
  }

  // Video
  if (section.type === 'video') {
    const url = section.url || '';
    if (!url) return '';
    const [rw, rh] = (section.aspectRatio || '16:9').split(':').map(Number);
    const pb = ((rh / rw) * 100).toFixed(2) + '%';
    let embedUrl = '';
    const ytMatch = url.match(/(?:v=|youtu\.be\/|embed\/)([^&?#]+)/);
    const viMatch = url.match(/vimeo\.com\/(\d+)/);
    if (ytMatch) embedUrl = `https://www.youtube.com/embed/${ytMatch[1]}`;
    else if (viMatch) embedUrl = `https://player.vimeo.com/video/${viMatch[1]}`;
    const inner = embedUrl
      ? `<iframe src="${embedUrl}" style="position:absolute;top:0;left:0;width:100%;height:100%;border:0" allowfullscreen></iframe>`
      : `<video src="${url}" controls style="position:absolute;top:0;left:0;width:100%;height:100%"></video>`;
    return `<div style="margin:20px 0">
    <div style="position:relative;padding-bottom:${pb};height:0;overflow:hidden;border-radius:8px">${inner}</div>
    ${section.caption ? `<p style="text-align:center;font-size:0.82rem;color:#999;margin-top:8px">${section.caption}</p>` : ''}
  </div>`;
  }

  // Spin Wheel
  if (section.type === 'spinwheel') {
    const rewards = section.rewards || [];
    if (!rewards.length) return '';
    const swId = `sf_sw_${section.id.replace(/[^a-z0-9]/gi,'_')}`;
    const colors = JSON.stringify(rewards.map(r => r.color || '#e94560'));
    const labels = JSON.stringify(rewards.map(r => r.label || ''));
    const probs  = JSON.stringify(rewards.map(r => +(r.probability || 1)));
    return `<div style="text-align:center;margin:20px 0">
    <canvas id="${swId}" width="280" height="280" style="max-width:100%;display:block;margin:0 auto;border-radius:50%;cursor:pointer"></canvas>
    <button class="sf-btn" style="margin-top:16px;max-width:280px" id="${swId}_btn">${section.spinButtonText || 'Spin!'}</button>
    <p id="${swId}_res" style="margin-top:12px;font-weight:700;font-size:1.1rem;min-height:1.6em"></p>
  </div>
  <script>(function(){
    var C=document.getElementById('${swId}'),ctx=C.getContext('2d');
    var colors=${colors},labels=${labels},probs=${probs},n=colors.length,TAU=Math.PI*2,arc=TAU/n,rot=0,spinning=false;
    function draw(r){ctx.clearRect(0,0,280,280);for(var i=0;i<n;i++){ctx.beginPath();ctx.moveTo(140,140);ctx.arc(140,140,130,r+arc*i,r+arc*(i+1));ctx.fillStyle=colors[i];ctx.fill();ctx.strokeStyle='#fff';ctx.lineWidth=2;ctx.stroke();ctx.save();ctx.translate(140,140);ctx.rotate(r+arc*i+arc/2);ctx.textAlign='right';ctx.fillStyle='#fff';ctx.font='bold 12px sans-serif';ctx.shadowColor='rgba(0,0,0,.4)';ctx.shadowBlur=3;ctx.fillText(labels[i],118,5);ctx.restore();}ctx.beginPath();ctx.arc(140,140,14,0,TAU);ctx.fillStyle='#fff';ctx.fill();ctx.strokeStyle='#ddd';ctx.lineWidth=2;ctx.stroke();}
    draw(rot);
    document.getElementById('${swId}_btn').addEventListener('click',function(){
      if(spinning)return;spinning=true;
      var total=probs.reduce(function(a,b){return a+b;},0),r=Math.random()*total,sum=0,pick=0;
      for(var i=0;i<n;i++){sum+=probs[i];if(r<=sum){pick=i;break;}}
      var extra=TAU*5+(TAU/n)*(n-pick-0.5),start=null,dur=3500,from=rot;
      document.getElementById('${swId}_res').textContent='';
      function anim(ts){if(!start)start=ts;var p=Math.min((ts-start)/dur,1),e=1-Math.pow(1-p,4),cur=from+extra*e;draw(cur);if(p<1){requestAnimationFrame(anim);}else{rot=cur%(TAU);spinning=false;document.getElementById('${swId}_res').textContent='\uD83C\uDF89 '+labels[pick];}}
      requestAnimationFrame(anim);
    });
  })();<\/script>`;
  }

  // Content block (heading/paragraph/image/spacer/divider/wysiwyg elements)
  if (section.type === 'content') {
    const elements = section.elements || [];
    if (!elements.length) return '';
    const c = section.colors || {};
    const cols = section.columns || 1;
    const blockStyle = [
      c.bg ? `background:${c.bg}` : '',
      c.text ? `color:${c.text}` : '',
      c.bg ? `padding:16px` : '',
      c.bg ? `border-radius:8px` : '',
    ].filter(Boolean).join(';');
    const wAttr = blockStyle ? ` style="${blockStyle}"` : '';
    const elHtml = elements.map(el => renderBlockElement(el)).join('');
    if (cols === 2) {
      // Split elements roughly in half for 2-col layout
      const half = Math.ceil(elements.length / 2);
      const col1 = elements.slice(0, half).map(el => renderBlockElement(el)).join('');
      const col2 = elements.slice(half).map(el => renderBlockElement(el)).join('');
      return `<div class="sf-content-block"${wAttr} style="${blockStyle};display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start;margin:16px 0"><div>${col1}</div><div>${col2}</div></div>`;
    }
    return `<div class="sf-content-block"${wAttr} style="${blockStyle};margin:16px 0">${elHtml}</div>`;
  }

  return '';
}

function renderPublicPage(cfg) {
  const d = cfg.design;
  const s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');

  const formFields = cfg.fields.map(f => renderFormField(f, cfg)).join('');

  const bgStyle = d.backgroundImage
    ? `background: linear-gradient(rgba(0,0,0,${d.backgroundOverlay}),rgba(0,0,0,${d.backgroundOverlay})), url('${d.backgroundImage}') center/cover no-repeat fixed; color: #fff;`
    : `background: ${d.backgroundColor};`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${s.title}</title>
${googleFontTag(cfg)}
${s.favicon ? `<link rel="icon" href="${s.favicon}">` : ''}
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --primary: ${d.primaryColor};
    --accent: ${d.accentColor};
    --bg: ${d.backgroundColor};
    --text: ${d.textColor};
    --radius: ${d.buttonRadius};
    --container: ${d.containerWidth};
    --font-heading: '${d.googleFont}', serif;
    --font-body: '${d.bodyFont}', sans-serif;
  }
  body { font-family: var(--font-body); ${bgStyle} min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 20px; }
  .sf-card { background: #fff; border-radius: ${d.cardRadius || '12px'}; padding: ${d.cardPadding || '48px 40px'}; max-width: var(--container); width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
  .sf-logo { text-align: center; margin-bottom: 24px; }
  .sf-logo img { width: ${d.logoWidth}; max-width: 100%; }
  .sf-hero-img { width: 100%; border-radius: 8px; margin-bottom: 28px; object-fit: cover; max-height: 280px; }
  .sf-hero-img.below { margin-top: 28px; margin-bottom: 0; }
  h1 { font-family: var(--font-heading); color: var(--primary); font-size: clamp(1.6rem, 4vw, 2.4rem); line-height: 1.2; margin-bottom: 12px; text-align: center; }
  .sf-sub { color: #666; font-size: 1.05rem; text-align: center; margin-bottom: 32px; line-height: 1.6; }
  .sf-field { margin-bottom: 16px; }
  .sf-field label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--primary); margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
  .req { color: var(--accent); }
  .sf-field input, .sf-field select, .sf-field textarea { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: ${d.fieldRadius || '6px'}; font-family: var(--font-body); font-size: 1rem; color: var(--text); transition: border-color 0.2s; background: #fafafa; }
  .sf-field input:focus, .sf-field select:focus, .sf-field textarea:focus { outline: none; border-color: var(--accent); background: #fff; }
  .sf-field--check label { display: flex; align-items: flex-start; gap: 10px; font-size: 0.9rem; text-transform: none; letter-spacing: 0; }
  .sf-field--check input[type=checkbox] { width: auto; margin-top: 2px; accent-color: var(--accent); }
  .sf-btn { width: 100%; padding: 14px; background: var(--accent); color: #fff; border: none; border-radius: var(--radius); font-family: var(--font-heading); font-size: 1.1rem; font-weight: 700; cursor: pointer; margin-top: 8px; letter-spacing: 0.03em; transition: opacity 0.2s, transform 0.1s; }
  .sf-btn:hover { opacity: 0.9; transform: translateY(-1px); }
  .sf-btn:active { transform: translateY(0); }
  .sf-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
  .sf-msg { display: none; margin-top: 20px; padding: 14px 18px; border-radius: 6px; font-size: 0.95rem; text-align: center; }
  .sf-msg.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
  .sf-msg.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
  .sf-gdpr { font-size: 0.78rem; color: #999; text-align: center; margin-top: 16px; line-height: 1.5; }
  .sf-gdpr a { color: var(--accent); }
  .sf-footer { text-align: center; margin-top: 28px; font-size: 0.82rem; color: #aaa; }
  /* Cookie banner */
  #sf-cookie { position: fixed; bottom: 0; left: 0; right: 0; background: #1a1a1a; color: #eee; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; z-index: 9999; flex-wrap: wrap; font-size: 0.88rem; }
  #sf-cookie a { color: var(--accent); }
  #sf-cookie-accept { background: var(--accent); color: #fff; border: none; padding: 8px 20px; border-radius: 4px; cursor: pointer; font-size: 0.88rem; white-space: nowrap; }
  .sf-captcha { margin: 16px 0 4px; display: flex; justify-content: center; }
  @media(max-width:500px){ .sf-card { padding: 32px 20px; } }
  ${sliderPickerCSS(d.accentColor)}
</style>
${s.captchaEnabled && s.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
</head>
<body>
<div class="sf-card">
  ${d.logoUrl ? `<div class="sf-logo"><img src="${d.logoUrl}" alt="Logo"></div>` : ''}
  ${cfg.sections.map(sec => renderSectionBlock(sec, cfg, formSection, formFields)).join('\n  ')}
</div>

<!-- Cookie Banner -->
<div id="sf-cookie" style="display:none">
  <span>${s.cookieBannerText} <a href="${s.privacyPolicyUrl}">Learn more</a></span>
  <button id="sf-cookie-accept">Accept</button>
</div>

<script>
(function(){
  // Cookie banner
  if(!localStorage.getItem('sf_cookie_ok')){
    document.getElementById('sf-cookie').style.display='flex';
  }
  document.getElementById('sf-cookie-accept').addEventListener('click',function(){
    localStorage.setItem('sf_cookie_ok','1');
    document.getElementById('sf-cookie').style.display='none';
  });

  // Form submission
  const form = document.getElementById('sf-form');
  if(!form) return;
  form.addEventListener('submit', async function(e){
    e.preventDefault();
    const btn = form.querySelector('.sf-btn');
    const msg = document.getElementById('sf-msg');
    btn.disabled = true;
    btn.textContent = 'Submitting…';
    msg.style.display = 'none';

    const data = new URLSearchParams(new FormData(form));
    try {
      const r = await fetch('/subscribe', { method:'POST', body: data });
      const j = await r.json();
      if(j.success){
        msg.className='sf-msg success'; msg.textContent='${(formSection && formSection.submitSuccessMessage) || 'Thank you!'}';
        form.reset();
      } else {
        msg.className='sf-msg error'; msg.textContent=j.error||'${(formSection && formSection.submitErrorMessage) || 'Error. Try again.'}';
        btn.disabled=false; btn.textContent='${d.buttonText}';
      }
    } catch(err){
      msg.className='sf-msg error'; msg.textContent='Network error. Please try again.';
      btn.disabled=false; btn.textContent='${d.buttonText}';
    }
    msg.style.display='block';
  });
})();
${sliderPickerJS()}
</script>
</body>
</html>`;
}

function renderUnsubscribePage(cfg, message, success, isDelete = false) {
  const d = cfg.design;
  const title = isDelete ? 'Delete My Data' : 'Unsubscribe';
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · ${cfg.site.title}</title>
${googleFontTag(cfg)}
<style>
  body { font-family: '${d.bodyFont}',sans-serif; background:${d.backgroundColor}; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:40px 20px; }
  .card { background:#fff; border-radius:12px; padding:40px; max-width:440px; width:100%; box-shadow:0 10px 40px rgba(0,0,0,.1); text-align:center; }
  h1 { font-family:'${d.googleFont}',serif; color:${d.primaryColor}; margin-bottom:16px; }
  p { color:#555; line-height:1.6; margin-bottom:20px; }
  .success { color:#155724; background:#d4edda; padding:14px; border-radius:6px; }
  .error { color:#721c24; background:#f8d7da; padding:14px; border-radius:6px; }
  a { color:${d.accentColor}; }
</style></head><body>
<div class="card">
  <h1>${title}</h1>
  ${message ? `<p class="${success ? 'success' : 'error'}">${message}</p>` : '<p>Processing your request…</p>'}
  <p><a href="/">← Back to home</a></p>
</div></body></html>`;
}

function renderPrivacyPage(cfg) {
  const d = cfg.design;
  const s = cfg.site;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy · ${s.title}</title>
${googleFontTag(cfg)}
<style>
  body { font-family:'${d.bodyFont}',sans-serif; background:${d.backgroundColor}; color:${d.textColor}; padding:60px 20px; }
  .wrap { max-width:720px; margin:0 auto; background:#fff; padding:48px; border-radius:12px; box-shadow:0 4px 30px rgba(0,0,0,.08); }
  h1 { font-family:'${d.googleFont}',serif; color:${d.primaryColor}; margin-bottom:24px; }
  h2 { font-family:'${d.googleFont}',serif; color:${d.primaryColor}; margin:32px 0 12px; font-size:1.2rem; }
  p,li { line-height:1.7; margin-bottom:12px; }
  a { color:${d.accentColor}; }
  ul { padding-left:20px; }
</style></head><body>
<div class="wrap">
  <h1>Privacy Policy</h1>
  <p><strong>Last updated:</strong> ${new Date().toLocaleDateString('en-GB', {year:'numeric',month:'long',day:'numeric'})}</p>
  <h2>1. Who we are</h2>
  <p>This website operates the newsletter signup service "${s.title}". By subscribing, you are providing your personal data to us.</p>
  <h2>2. What data we collect</h2>
  <ul>
    <li>Your email address (required)</li>
    <li>Name and any other fields displayed on the signup form</li>
    <li>Your IP address and timestamp at time of subscription (for consent records)</li>
  </ul>
  <h2>3. How we use your data</h2>
  <p>We use your data solely to send you newsletters and updates you signed up for. We do not sell or share your data with third parties for marketing purposes.</p>
  <h2>4. Legal basis (GDPR)</h2>
  <p>We process your data on the basis of your explicit consent, given at the time of subscription.</p>
  <h2>5. Your rights</h2>
  <ul>
    <li><strong>Unsubscribe:</strong> Use the link in any newsletter email, or visit <a href="/unsubscribe">/unsubscribe</a></li>
    <li><strong>Right to erasure:</strong> You can request complete deletion of your data via the link in your confirmation email or by contacting us</li>
    <li><strong>Right to access:</strong> Contact us to receive a copy of your stored data</li>
  </ul>
  <h2>6. Data retention</h2>
  <p>We retain your data for as long as you are subscribed. If you unsubscribe, we retain a minimal record for our legal consent logs. If you request deletion, all data is permanently removed.</p>
  <h2>7. Cookies</h2>
  <p>We use a single cookie/localStorage item to remember that you have accepted this cookie notice. No tracking or advertising cookies are used.</p>
  <h2>8. Contact</h2>
  <p>For any data-related requests, please contact the site administrator.</p>
  <p style="margin-top:32px"><a href="/">← Back</a></p>
</div></body></html>`;
}

function renderEmbedPage(cfg) {
  const d = cfg.design;
  const s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');

  const formFields = cfg.fields.map(f => renderFormField(f, cfg)).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${s.title}</title>
${googleFontTag(cfg)}
${s.captchaEnabled && s.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --primary: ${d.primaryColor};
    --accent: ${d.accentColor};
    --text: ${d.textColor};
    --radius: ${d.buttonRadius};
    --font-heading: '${d.googleFont}', serif;
    --font-body: '${d.bodyFont}', sans-serif;
  }
  html, body { background: transparent; }
  body { font-family: var(--font-body); color: var(--text); padding: 4px 2px 16px; }
  .sf-logo { text-align: center; margin-bottom: 20px; }
  .sf-logo img { width: ${d.logoWidth}; max-width: 100%; }
  .sf-hero-img { width: 100%; border-radius: 8px; margin-bottom: 20px; object-fit: cover; max-height: 200px; }
  .sf-hero-img.below { margin-top: 20px; margin-bottom: 0; }
  h1 { font-family: var(--font-heading); color: var(--primary); font-size: clamp(1.3rem, 4vw, 1.9rem); line-height: 1.2; margin-bottom: 10px; text-align: center; }
  .sf-sub { color: #666; font-size: 0.97rem; text-align: center; margin-bottom: 22px; line-height: 1.6; }
  .sf-field { margin-bottom: 14px; }
  .sf-field label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--primary); margin-bottom: 5px; letter-spacing: 0.04em; text-transform: uppercase; }
  .req { color: var(--accent); }
  .sf-field input, .sf-field select, .sf-field textarea { width: 100%; padding: 10px 14px; border: 2px solid #e0e0e0; border-radius: ${d.fieldRadius || '6px'}; font-family: var(--font-body); font-size: 0.97rem; color: var(--text); transition: border-color 0.2s; background: #fafafa; }
  .sf-field input:focus, .sf-field select:focus, .sf-field textarea:focus { outline: none; border-color: var(--accent); background: #fff; }
  .sf-field--check label { display: flex; align-items: flex-start; gap: 10px; font-size: 0.88rem; text-transform: none; letter-spacing: 0; }
  .sf-field--check input[type=checkbox] { width: auto; margin-top: 2px; accent-color: var(--accent); }
  .sf-btn { width: 100%; padding: 12px; background: var(--accent); color: #fff; border: none; border-radius: var(--radius); font-family: var(--font-heading); font-size: 1rem; font-weight: 700; cursor: pointer; margin-top: 6px; letter-spacing: 0.03em; transition: opacity 0.2s, transform 0.1s; }
  .sf-btn:hover { opacity: 0.9; transform: translateY(-1px); }
  .sf-btn:active { transform: translateY(0); }
  .sf-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
  .sf-msg { display: none; margin-top: 14px; padding: 12px 16px; border-radius: 6px; font-size: 0.9rem; text-align: center; }
  .sf-msg.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
  .sf-msg.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
  .sf-gdpr { font-size: 0.74rem; color: #aaa; text-align: center; margin-top: 12px; line-height: 1.5; }
  .sf-gdpr a { color: var(--accent); }
  .sf-footer { text-align: center; margin-top: 20px; font-size: 0.78rem; color: #bbb; }
  .sf-captcha { margin: 12px 0 4px; display: flex; justify-content: center; }
  ${sliderPickerCSS(d.accentColor)}
</style>
</head>
<body>
  ${d.logoUrl ? `<div class="sf-logo"><img src="${d.logoUrl}" alt="Logo"></div>` : ''}
  ${cfg.sections.map(sec => renderSectionBlock(sec, cfg, formSection, formFields)).join('\n  ')}

<script>
(function(){
  const form = document.getElementById('sf-form');
  if(!form) return;

  // Post height to parent for auto-resize
  function reportHeight() {
    const h = document.body.scrollHeight;
    window.parent.postMessage({ type: 'sf-resize', height: h }, '*');
  }
  reportHeight();
  new ResizeObserver(reportHeight).observe(document.body);

  form.addEventListener('submit', async function(e){
    e.preventDefault();
    const btn = form.querySelector('.sf-btn');
    const msg = document.getElementById('sf-msg');
    btn.disabled = true;
    btn.textContent = 'Submitting\u2026';
    msg.style.display = 'none';
    const data = new URLSearchParams(new FormData(form));
    try {
      const r = await fetch('/subscribe', { method:'POST', body: data });
      const j = await r.json();
      if(j.success){
        msg.className='sf-msg success'; msg.textContent='${(formSection && formSection.submitSuccessMessage) || 'Thank you!'}';
        form.reset();
        // notify parent of success (optional hook)
        window.parent.postMessage({ type: 'sf-success' }, '*');
      } else {
        msg.className='sf-msg error'; msg.textContent=j.error||'${(formSection && formSection.submitErrorMessage) || 'Error. Try again.'}';
        btn.disabled=false; btn.textContent='${d.buttonText}';
      }
    } catch(err){
      msg.className='sf-msg error'; msg.textContent='Network error. Please try again.';
      btn.disabled=false; btn.textContent='${d.buttonText}';
    }
    msg.style.display='block';
    reportHeight();
  });
})();
${sliderPickerJS()}
</script>
</body>
</html>`;
}

function renderEmbedScript(origin, cfg) {
  return `/* SignFlow Embed — ${origin} */
(function(w, d) {
  'use strict';
  var ORIGIN = '${origin}';

  // Find all placeholder divs
  var containers = d.querySelectorAll('[data-signflow]');
  if (!containers.length) {
    // Fallback: use the script tag's parent if no explicit container
    var scripts = d.querySelectorAll('script[src*="embed.js"]');
    if (scripts.length) containers = [scripts[scripts.length - 1].parentNode];
  }

  containers.forEach(function(container) {
    var width  = container.getAttribute('data-width')  || '100%';
    var radius = container.getAttribute('data-radius') || '12px';
    var shadow = container.getAttribute('data-shadow') !== 'false';
    var minH   = parseInt(container.getAttribute('data-min-height') || '400', 10);

    var iframe = d.createElement('iframe');
    iframe.src = ORIGIN + '/embed';
    iframe.title = 'Newsletter Signup';
    iframe.setAttribute('frameborder', '0');
    iframe.setAttribute('scrolling', 'no');
    iframe.setAttribute('allowtransparency', 'true');
    iframe.style.cssText = [
      'display:block',
      'width:' + width,
      'min-height:' + minH + 'px',
      'height:' + minH + 'px',
      'border:none',
      'border-radius:' + radius,
      'box-shadow:' + (shadow ? '0 4px 30px rgba(0,0,0,0.12)' : 'none'),
      'background:transparent',
      'overflow:hidden',
      'transition:height 0.3s ease'
    ].join(';');

    // Clear container and insert iframe
    container.innerHTML = '';
    container.appendChild(iframe);
  });

  // Listen for height updates and success events from the iframe
  w.addEventListener('message', function(e) {
    if (!e.data || e.origin !== ORIGIN) return;
    if (e.data.type === 'sf-resize') {
      d.querySelectorAll('iframe[src*="' + ORIGIN + '/embed"]').forEach(function(fr) {
        fr.style.height = (e.data.height + 20) + 'px';
      });
    }
    if (e.data.type === 'sf-success') {
      // Developers can listen for this on the parent page:
      // window.addEventListener('message', e => { if(e.data.type==='sf-success') ... })
      w.dispatchEvent(new CustomEvent('signflow:success'));
    }
  });
})(window, document);
`;
}

function renderAccessDeniedPage(email) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Access Denied</title>
<style>
  body { font-family: system-ui,sans-serif; background:#f5f5f7; min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .box { background:#fff; border-radius:12px; padding:48px 40px; max-width:420px; text-align:center; box-shadow:0 10px 40px rgba(0,0,0,.1); }
  h1 { font-size:1.4rem; color:#1a1a2e; margin-bottom:12px; }
  p  { color:#666; line-height:1.6; margin-bottom:20px; font-size:0.95rem; }
  a  { display:inline-block; padding:10px 24px; background:#e94560; color:#fff; border-radius:6px; text-decoration:none; font-weight:600; }
</style></head><body>
<div class="box">
  <h1>⛔ Access Denied</h1>
  <p>The account <strong>${email}</strong> is not authorised to access the SignFlow admin panel.</p>
  <p>You need the <code>${AUTH0_ADMIN_ROLE}</code> role assigned in Auth0.</p>
  <a href="/auth/logout">Sign out</a>
</div></body></html>`;
}

// ── Start ──
(async () => {
  await initAuth0();
  app.listen(PORT, () => {
    console.log(`\n✅ SignFlow running at http://localhost:${PORT}`);
    console.log(`   Admin panel : http://localhost:${PORT}/admin`);
    console.log(`   Auth login  : http://localhost:${PORT}/auth/login`);
    console.log(`   Auth0 domain: ${AUTH0_DOMAIN || '(not configured)'}\n`);
  });
})();
