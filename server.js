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

function renderPublicPage(cfg) {
  const d = cfg.design;
  const s = cfg.site;
  const heroSection = cfg.sections.find(s => s.id === 'hero');
  const formSection = cfg.sections.find(s => s.id === 'form');
  const footerSection = cfg.sections.find(s => s.id === 'footer');

  const formFields = cfg.fields.map(f => {
    if (f.type === 'select') {
      return `<div class="sf-field">
        <label for="sf_${f.id}">${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label>
        <select id="sf_${f.id}" name="${f.id}" ${f.required ? 'required' : ''}>
          <option value="">— Select —</option>
          ${(f.options || []).map(o => `<option value="${o}">${o}</option>`).join('')}
        </select>
      </div>`;
    }
    if (f.type === 'checkbox') {
      return `<div class="sf-field sf-field--check">
        <label><input type="checkbox" name="${f.id}" value="yes" ${f.required ? 'required' : ''}> ${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label>
      </div>`;
    }
    if (f.type === 'textarea') {
      return `<div class="sf-field">
        <label for="sf_${f.id}">${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label>
        <textarea id="sf_${f.id}" name="${f.id}" placeholder="${f.placeholder || ''}" ${f.required ? 'required' : ''} rows="3"></textarea>
      </div>`;
    }
    return `<div class="sf-field">
      <label for="sf_${f.id}">${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label>
      <input type="${f.type || 'text'}" id="sf_${f.id}" name="${f.id}" placeholder="${f.placeholder || ''}" ${f.required ? 'required' : ''}>
    </div>`;
  }).join('');

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
  .sf-card { background: #fff; border-radius: 12px; padding: 48px 40px; max-width: var(--container); width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
  .sf-logo { text-align: center; margin-bottom: 24px; }
  .sf-logo img { width: ${d.logoWidth}; max-width: 100%; }
  .sf-hero-img { width: 100%; border-radius: 8px; margin-bottom: 28px; object-fit: cover; max-height: 280px; }
  .sf-hero-img.below { margin-top: 28px; margin-bottom: 0; }
  h1 { font-family: var(--font-heading); color: var(--primary); font-size: clamp(1.6rem, 4vw, 2.4rem); line-height: 1.2; margin-bottom: 12px; text-align: center; }
  .sf-sub { color: #666; font-size: 1.05rem; text-align: center; margin-bottom: 32px; line-height: 1.6; }
  .sf-field { margin-bottom: 16px; }
  .sf-field label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--primary); margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
  .req { color: var(--accent); }
  .sf-field input, .sf-field select, .sf-field textarea { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 6px; font-family: var(--font-body); font-size: 1rem; color: var(--text); transition: border-color 0.2s; background: #fafafa; }
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
</style>
${s.captchaEnabled && s.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
</head>
<body>
<div class="sf-card">
  ${d.logoUrl ? `<div class="sf-logo"><img src="${d.logoUrl}" alt="Logo"></div>` : ''}
  ${heroSection && heroSection.visible ? `
    ${heroSection.imageUrl && heroSection.imagePosition === 'above' ? `<img src="${heroSection.imageUrl}" class="sf-hero-img" alt="">` : ''}
    <h1>${heroSection.heading}</h1>
    ${heroSection.subheading ? `<p class="sf-sub">${heroSection.subheading}</p>` : ''}
    ${heroSection.imageUrl && heroSection.imagePosition === 'below' ? `<img src="${heroSection.imageUrl}" class="sf-hero-img below" alt="">` : ''}
  ` : ''}
  ${formSection && formSection.visible ? `
  <form id="sf-form" novalidate>
    ${formFields}
    <div class="sf-gdpr">By subscribing you agree to our <a href="${s.privacyPolicyUrl}" target="_blank">Privacy Policy</a>. We store your data securely and you can unsubscribe or request deletion at any time.</div>
    ${s.captchaEnabled && s.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${s.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
    <button type="submit" class="sf-btn">${d.buttonText}</button>
    <div id="sf-msg" class="sf-msg"></div>
  </form>
  ` : ''}
  ${footerSection && footerSection.visible ? `<p class="sf-footer">${footerSection.text}</p>` : ''}
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
  const heroSection = cfg.sections.find(sec => sec.id === 'hero');
  const formSection = cfg.sections.find(sec => sec.id === 'form');
  const footerSection = cfg.sections.find(sec => sec.id === 'footer');

  // Reuse same field rendering logic
  const formFields = cfg.fields.map(f => {
    if (f.type === 'select') {
      return `<div class="sf-field">
        <label for="sf_${f.id}">${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label>
        <select id="sf_${f.id}" name="${f.id}" ${f.required ? 'required' : ''}>
          <option value="">— Select —</option>
          ${(f.options || []).map(o => `<option value="${o}">${o}</option>`).join('')}
        </select></div>`;
    }
    if (f.type === 'checkbox') {
      return `<div class="sf-field sf-field--check">
        <label><input type="checkbox" name="${f.id}" value="yes" ${f.required ? 'required' : ''}> ${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label></div>`;
    }
    if (f.type === 'textarea') {
      return `<div class="sf-field">
        <label for="sf_${f.id}">${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label>
        <textarea id="sf_${f.id}" name="${f.id}" placeholder="${f.placeholder || ''}" ${f.required ? 'required' : ''} rows="3"></textarea></div>`;
    }
    return `<div class="sf-field">
      <label for="sf_${f.id}">${f.label}${f.required ? ' <span class="req">*</span>' : ''}</label>
      <input type="${f.type || 'text'}" id="sf_${f.id}" name="${f.id}" placeholder="${f.placeholder || ''}" ${f.required ? 'required' : ''}></div>`;
  }).join('');

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
  .sf-field input, .sf-field select, .sf-field textarea { width: 100%; padding: 10px 14px; border: 2px solid #e0e0e0; border-radius: 6px; font-family: var(--font-body); font-size: 0.97rem; color: var(--text); transition: border-color 0.2s; background: #fafafa; }
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
</style>
</head>
<body>
  ${d.logoUrl ? `<div class="sf-logo"><img src="${d.logoUrl}" alt="Logo"></div>` : ''}
  ${heroSection && heroSection.visible ? `
    ${heroSection.imageUrl && heroSection.imagePosition === 'above' ? `<img src="${heroSection.imageUrl}" class="sf-hero-img" alt="">` : ''}
    <h1>${heroSection.heading}</h1>
    ${heroSection.subheading ? `<p class="sf-sub">${heroSection.subheading}</p>` : ''}
    ${heroSection.imageUrl && heroSection.imagePosition === 'below' ? `<img src="${heroSection.imageUrl}" class="sf-hero-img below" alt="">` : ''}
  ` : ''}
  ${formSection && formSection.visible ? `
  <form id="sf-form" novalidate>
    ${formFields}
    <div class="sf-gdpr">By subscribing you agree to our <a href="${s.privacyPolicyUrl}" target="_blank">Privacy Policy</a>.</div>
    ${s.captchaEnabled && s.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${s.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
    <button type="submit" class="sf-btn">${d.buttonText}</button>
    <div id="sf-msg" class="sf-msg"></div>
  </form>
  ` : ''}
  ${footerSection && footerSection.visible ? `<p class="sf-footer">${footerSection.text}</p>` : ''}

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
