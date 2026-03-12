// Load .env file if present (production secrets — never commit this file)
require('dotenv').config();

const express    = require('express');
const fs         = require('fs');
const path       = require('path');
const { v4: uuidv4 } = require('uuid');
const rateLimit  = require('express-rate-limit');
const Joi        = require('joi');
const helmet     = require('helmet');
const multer     = require('multer');
const session    = require('express-session');
const { Issuer, generators } = require('openid-client');
const nodemailer = require('nodemailer');
const { Pool }   = require('pg');
const { S3Client, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const multerS3   = require('multer-s3');

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

// ── SMTP (from .env) — optional; email only sent when all three are set ────────
const SMTP_HOST   = process.env.SMTP_HOST   || '';
const SMTP_PORT   = parseInt(process.env.SMTP_PORT) || 587;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_USER   = process.env.SMTP_USER   || '';
const SMTP_PASS   = process.env.SMTP_PASS   || '';
const SMTP_FROM   = process.env.SMTP_FROM   || SMTP_USER; // e.g. "noreply@yourdomain.com"
const ORIGIN      = process.env.ORIGIN      || `http://localhost:${process.env.PORT || 3000}`;

// ── PostgreSQL pool ────────────────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ── AWS S3 ─────────────────────────────────────────────────────────────────────
const s3        = new S3Client({ region: process.env.AWS_REGION || 'us-east-1' });
const S3_BUCKET = process.env.S3_BUCKET || '';
function s3PublicUrl(key) {
  return `https://${S3_BUCKET}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com/${key}`;
}

// Create nodemailer transporter (lazy — only used when SMTP is configured)
let _mailer = null;
function getMailer() {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  if (!_mailer) {
    _mailer = nodemailer.createTransport({
      host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
  }
  return _mailer;
}

// ── HTML escaping ─────────────────────────────────────────────────────────────
// Used in every page renderer to prevent XSS from admin-entered text fields.
function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── WYSIWYG sanitisation ───────────────────────────────────────────────────────
// Strips disallowed tags/attributes from admin-authored rich HTML before rendering.
// Prevents XSS if admin account is compromised or config is tampered with.
const sanitizeHtml = require('sanitize-html');
const SANITIZE_OPTS = {
  allowedTags: ['h1','h2','h3','h4','h5','h6','p','strong','em','b','i','u','s',
                'br','ul','ol','li','a','img','blockquote','code','pre',
                'table','thead','tbody','tr','td','th','span','div','hr'],
  allowedAttributes: {
    'a':   ['href','target','rel'],
    'img': ['src','alt','width','height','style'],
    '*':   ['style','class']
  },
  allowedSchemes: ['http','https','mailto'],
};
function sanitizeWysiwyg(html) {
  return sanitizeHtml(html || '', SANITIZE_OPTS);
}

// Replace {{merge tags}} in email subject/body before sending
function replaceMergeTags(text, cfg, subscriber, unsubUrl) {
  const firstName = (subscriber.customFields && (subscriber.customFields.firstName || subscriber.customFields.first_name)) ||
    subscriber.email.split('@')[0];
  const map = {
    '{{email}}':          subscriber.email,
    '{{firstName}}':      firstName,
    '{{formName}}':       (cfg.site && cfg.site.title) || 'SignFlow',
    '{{unsubscribeUrl}}': unsubUrl,
  };
  // Strip editor merge-tag spans (keep inner text which is the {{tag}}) then replace
  let out = text.replace(/<span[^>]*class="etpl-merge"[^>]*>([\s\S]*?)<\/span>/g, '$1');
  return out.replace(/\{\{[a-zA-Z]+\}\}/g, t => (map[t] !== undefined ? map[t] : t));
}

async function sendWelcomeEmail(cfg, subscriber) {
  const mailer = getMailer();
  if (!mailer) return; // SMTP not configured — skip silently
  const s = cfg.site;
  if (!s.emailEnabled) return;
  const prefUrl = `${ORIGIN}/preferences?token=${subscriber.unsubscribeToken}&email=${encodeURIComponent(subscriber.email)}`;
  const fromName  = s.emailFromName  || s.title || 'SignFlow';
  const ed = s.emailDesign || {};
  const bgColor    = ed.bgColor    || '#f4f4f4';
  const cardBg     = ed.cardBg     || '#ffffff';
  const textColor  = ed.textColor  || '#333333';
  const bodyFont   = ed.bodyFont   || s.bodyFont || 'Lato';
  const bodyFontSize = ed.bodyFontSize || '16px';
  const maxWidth   = ed.maxWidth   || '600px';
  const padding    = ed.padding    || '40px';
  const radius     = ed.borderRadius || '8px';
  const rawSubject = s.emailSubject || `Thanks for subscribing to ${s.title}`;
  const rawBody    = sanitizeWysiwyg(s.emailBodyHtml) || `<p>Hi!</p><p>Thanks for subscribing to <strong>${s.title}</strong>. We're excited to have you!</p>`;
  const subject    = replaceMergeTags(rawSubject, cfg, subscriber, prefUrl);
  const bodyHtml   = replaceMergeTags(rawBody,    cfg, subscriber, prefUrl);
  // Auto-append unsubscribe footer only if {{unsubscribeUrl}} not already used in body
  const footer = rawBody.includes('{{unsubscribeUrl}}') ? '' :
    `<p style="margin-top:32px;font-size:0.8rem;color:#aaa;border-top:1px solid #eee;padding-top:16px">Don't want these emails? <a href="${prefUrl}" style="color:#aaa">Manage preferences</a></p>`;
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=${encodeURIComponent(bodyFont)}:wght@400;600&display=swap" rel="stylesheet">
</head><body style="margin:0;padding:0;background:${bgColor}">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 16px">
<table width="${maxWidth}" cellpadding="0" cellspacing="0" style="max-width:${maxWidth}">
<tr><td style="background:${cardBg};border-radius:${radius};padding:${padding};color:${textColor};font-family:'${bodyFont}',Helvetica,Arial,sans-serif;font-size:${bodyFontSize};line-height:1.6">
${bodyHtml}
${footer}
</td></tr></table></td></tr></table>
</body></html>`;
  await mailer.sendMail({
    from: `"${fromName}" <${SMTP_FROM}>`,
    to: subscriber.email,
    ...(s.emailReplyTo ? { replyTo: s.emailReplyTo } : {}),
    subject,
    html
  });
}

// ── Paths (data/ kept for import script; uploads now in S3) ───────────────────
const DATA_DIR         = path.join(__dirname, 'data');
const CONFIG_FILE      = path.join(DATA_DIR, 'config.json');       // legacy — used only by import script
const SUBSCRIBERS_FILE = path.join(DATA_DIR, 'subscribers.json'); // legacy — used only by import script
const FORMS_DIR        = path.join(DATA_DIR, 'forms');             // legacy — used only by import script
const UPLOADS_DIR      = path.join(__dirname, 'public', 'uploads'); // legacy — used only by import script
const FONTS_DIR        = path.join(UPLOADS_DIR, 'fonts');           // legacy — used only by import script

// Slugs that cannot be used as form slugs (they're real routes)
const RESERVED_SLUGS = new Set(['admin','auth','api','privacy','unsubscribe','delete-data','preferences','embed','public','uploads','assets','branding-preview']);

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
// Helmet security headers — CSP configured per environment.
// The admin SPA uses inline scripts (single-file HTML), so script-src needs
// 'unsafe-inline'. A future refactor moving admin JS to a separate file would
// allow removing 'unsafe-inline' and using a nonce/hash instead.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'", 'https://js.hcaptcha.com'],
      scriptSrcAttr:  ["'unsafe-inline'"],  // allow onclick/onchange handlers in admin SPA & public pages
      styleSrc:       ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:        ["'self'", 'https://fonts.gstatic.com', 'https://*.amazonaws.com'],
      imgSrc:         ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc:     ["'self'", 'https://api.hcaptcha.com'],
      frameSrc:       ["'self'", 'https://www.youtube.com', 'https://player.vimeo.com'],  // 'self' needed for admin live preview iframe
      frameAncestors: ["'self'"],   // overridden to * on /:slug/embed routes
      objectSrc:      ["'none'"],
      baseUri:        ["'self'"],
    },
  },
  // X-Frame-Options: SAMEORIGIN is the helmet default.
  // The embed routes override this header individually.
  frameguard: { action: 'sameorigin' },
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.set('trust proxy', 1);
const PgStore = require('connect-pg-simple')(session);
app.use(session({
  store: new PgStore({ pool, createTableIfMissing: true }),
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
// Note: /uploads is no longer served statically — files are stored in S3 and URLs are direct S3 links.
app.use('/admin',   express.static(path.join(__dirname, 'admin')));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'favicon.ico')));

// ── Multer → S3 ───────────────────────────────────────────────────────────────
const FONT_EXTS = new Set(['.woff','.woff2','.ttf','.otf']);
const upload = multer({
  storage: multerS3({
    s3, bucket: S3_BUCKET,
    contentType: multerS3.AUTO_CONTENT_TYPE,
    key: (req, file, cb) => cb(null, `uploads/${uuidv4()}${path.extname(file.originalname)}`)
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Images only'));
  }
});
const uploadFont = multer({
  storage: multerS3({
    s3, bucket: S3_BUCKET,
    contentType: multerS3.AUTO_CONTENT_TYPE,
    key: (req, file, cb) => cb(null, `fonts/${uuidv4()}${path.extname(file.originalname)}`)
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    FONT_EXTS.has(path.extname(file.originalname).toLowerCase()) ? cb(null, true) : cb(new Error('Font files only'));
  }
});

// ── Rate limiting ─────────────────────────────────────────────────────────────
const submitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  keyGenerator: (req) => `${req.ip}-${req.params.slug || ''}`,  // per-IP per-form slug
  message: { error: 'Too many requests' }
});
const adminLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
const authLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: 'Too many login attempts' });

// ── Data helpers (PostgreSQL) ─────────────────────────────────────────────────

// Map a subscribers DB row to the camelCase object shape used throughout the app
function rowToSubscriber(r) {
  return {
    id: r.id, email: r.email, status: r.status,
    subscribedAt: r.subscribed_at ? r.subscribed_at.toISOString() : null,
    unsubscribedAt: r.unsubscribed_at ? r.unsubscribed_at.toISOString() : null,
    unsubscribeToken: r.unsubscribe_token,
    consentGiven: r.consent_given, consentTimestamp: r.consent_timestamp,
    ipAddress: r.ip_address, customFields: r.custom_fields || {},
    exported: r.exported || false,
    exportedAt: r.exported_at ? r.exported_at.toISOString() : null
  };
}

// Map a media DB row to the shape used by the admin API
function rowToMedia(r) {
  return {
    id: r.id, url: r.url, s3Key: r.s3_key,
    name: r.original_name, size: r.size, mimeType: r.mime_type,
    uploadedAt: r.uploaded_at ? r.uploaded_at.toISOString() : null,
    folder: r.folder || ''
  };
}

async function readFormsIndex() {
  const { rows } = await pool.query('SELECT slug, name, created_at FROM forms ORDER BY created_at ASC');
  return rows.map(r => ({ slug: r.slug, name: r.name, createdAt: r.created_at ? r.created_at.toISOString() : null }));
}

async function readFormConfig(slug) {
  const { rows } = await pool.query('SELECT config FROM forms WHERE slug=$1', [slug]);
  if (!rows.length) throw new Error(`Form not found: ${slug}`);
  const cfg = rows[0].config;
  if (ENV_HCAPTCHA_SECRET) cfg.site.hcaptchaSecretKey = ENV_HCAPTCHA_SECRET;
  return cfg;
}

async function writeFormConfig(slug, cfg) {
  await pool.query('UPDATE forms SET config=$1 WHERE slug=$2', [cfg, slug]);
}

async function readFormSubscribers(slug) {
  const { rows } = await pool.query(
    'SELECT * FROM subscribers WHERE form_slug=$1 ORDER BY subscribed_at DESC', [slug]);
  return rows.map(rowToSubscriber);
}

async function readFormMedia(slug) {
  const { rows } = await pool.query(
    'SELECT * FROM media WHERE form_slug=$1 ORDER BY uploaded_at DESC', [slug]);
  return rows.map(rowToMedia);
}

async function readSharedMedia() {
  const { rows } = await pool.query(
    'SELECT * FROM media WHERE form_slug IS NULL ORDER BY uploaded_at DESC');
  return rows.map(rowToMedia);
}

async function readSharedFonts() {
  const { rows } = await pool.query('SELECT * FROM fonts ORDER BY uploaded_at DESC');
  return rows.map(r => ({
    id: r.id, name: r.name, url: r.url, s3Key: r.s3_key,
    uploadedAt: r.uploaded_at ? r.uploaded_at.toISOString() : null
  }));
}

async function readDesignTemplates() {
  const { rows } = await pool.query('SELECT * FROM design_templates ORDER BY created_at DESC');
  return rows.map(r => ({
    id: r.id, name: r.name, design: r.design,
    createdAt: r.created_at ? r.created_at.toISOString() : null
  }));
}

// Generic sections used when ?_generic=1 is requested (design tab preview)
// Real form content is replaced with placeholder demo content so the preview
// always looks clean regardless of what the user has built.
const GENERIC_PREVIEW_SECTIONS = [
  { id:'hero', type:'hero', visible:true,
    heading:'Stay in the loop', subheading:'Join our community and get the latest news, tips, and updates delivered straight to your inbox.', colors:{} },
  { id:'form', type:'form', visible:true },
  { id:'footer', type:'footer', visible:true, text:'© 2026 · Unsubscribe any time' }
];
const GENERIC_PREVIEW_FIELDS = [
  { id:'gf_name',  type:'text',  label:'Your name',      placeholder:'Jane Smith',          required:false, system:false },
  { id:'gf_email', type:'email', label:'Email address',  placeholder:'jane@example.com',    required:true,  system:true  }
];

function defaultFormConfig(slug, name) {
  return {
    slug, name,
    site: { title: name, description: '', favicon: '', adminPassword: '', cookieBannerText: '', privacyPolicyUrl: '/privacy',
            gdprText: 'By subscribing you agree to our <a href="{privacyUrl}" target="_blank">Privacy Policy</a>. We store your data securely and you can unsubscribe or request deletion at any time.',
            unsubscribeEnabled: true, captchaEnabled: false, hcaptchaSiteKey: '', hcaptchaSecretKey: '',
            emailEnabled: false, emailFromName: '', emailReplyTo: '', emailSubject: '', emailBodyHtml: '',
            emailDesign: { bgColor: '#f4f4f4', cardBg: '#ffffff', textColor: '#333333', headingColor: '#1a1a2e',
              bodyFont: 'Lato', headingFont: 'Playfair Display', maxWidth: '600px', padding: '40px', borderRadius: '8px' },
            unsubscribePageText: 'Manage your subscription preferences below.',
            embedAllowedDomains: [] },
    design: { googleFont: 'Playfair Display', bodyFont: 'Lato', primaryColor: '#1a1a2e',
              accentColor: '#e94560', backgroundColor: '#f8f5f0', textColor: '#1a1a2e',
              buttonText: 'Subscribe Now', buttonRadius: '4px', containerWidth: '560px',
              backgroundImage: '', backgroundOverlay: 0.4, backgroundOverlayColor: '#000000', logoUrl: '', logoWidth: '180px',
              cardPadding: '48px 40px', cardRadius: '12px', fieldRadius: '6px',
              fieldBg: '#fafafa', fieldBorderColor: '#e0e0e0', fieldBorderStyle: 'solid',
              fieldBorderWidth: 2, fieldFont: '',
              btnBg: '', btnTextColor: '#ffffff', btnBorderColor: 'transparent', btnBorderStyle: 'solid', btnBorderWidth: 0,
              customFonts: [] },
    sections: [
      { id: 'hero',   type: 'hero',   visible: true, heading: 'Sign Up', subheading: '', imageUrl: '', imagePosition: 'above', colors: {} },
      { id: 'form',   type: 'form',   visible: true, submitSuccessMessage: "Thanks! You're on the list.", submitErrorMessage: 'Something went wrong.', colors: {} },
      { id: 'footer', type: 'footer', visible: true, text: '', colors: {} }
    ],
    fields: [{ id: 'email', label: 'Email Address', type: 'email', required: true, placeholder: 'your@email.com', system: true, conditions: [] }],
    confirmation: [],
    designTemplateId: null,
    preferenceCenter: {
      bgColor: '', bgImage: '', bgOverlay: 0.4, bgOverlayColor: '#000000',
      cardBg: '#ffffff', cardRadius: '12px', cardMaxWidth: '480px', cardPadding: '40px',
      logoUrl: '', logoWidth: '160px',
      accentColor: '', primaryColor: '', textColor: '',
      headingFont: '', bodyFont: '',
      pageHeading: 'Email Preferences',
      subText: 'Manage your subscription preferences below.',
      sections: []
    }
  };
}

// ── One-time migration from single-form to multi-form layout ──────────────────
function migrateIfNeeded() {
  if (fs.existsSync(FORMS_DIR)) return; // already migrated
  fs.mkdirSync(FORMS_DIR, { recursive: true });
  let name = 'My Form';
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      cfg.slug = 'default';
      cfg.name = (cfg.site && cfg.site.title) || name;
      name = cfg.name;
      writeFormConfig('default', cfg);
      console.log('✔ Migrated config.json → data/forms/default.json');
    } catch (e) { console.error('Migration error (config):', e.message); }
  } else {
    writeFormConfig('default', defaultFormConfig('default', name));
  }
  if (fs.existsSync(SUBSCRIBERS_FILE)) {
    try {
      fs.copyFileSync(SUBSCRIBERS_FILE, path.join(DATA_DIR, 'subscribers-default.json'));
      console.log('✔ Migrated subscribers.json → data/subscribers-default.json');
    } catch (e) { console.error('Migration error (subscribers):', e.message); }
  }
  writeFormsIndex([{ slug: 'default', name, createdAt: new Date().toISOString() }]);
  console.log('✔ Multi-form migration complete.');
}

// ── Database initialisation ───────────────────────────────────────────────────
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS forms (
      slug       VARCHAR(100) PRIMARY KEY,
      name       VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      config     JSONB        NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS subscribers (
      id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      form_slug         VARCHAR(100) NOT NULL REFERENCES forms(slug) ON DELETE CASCADE,
      email             VARCHAR(320) NOT NULL,
      status            VARCHAR(20)  NOT NULL DEFAULT 'active',
      subscribed_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      unsubscribed_at   TIMESTAMPTZ,
      unsubscribe_token VARCHAR(255),
      consent_given     BOOLEAN      NOT NULL DEFAULT FALSE,
      consent_timestamp VARCHAR(50),
      ip_address        VARCHAR(45),
      custom_fields     JSONB        NOT NULL DEFAULT '{}',
      exported          BOOLEAN      NOT NULL DEFAULT FALSE,
      exported_at       TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_form_email ON subscribers(form_slug, email);
    CREATE        INDEX IF NOT EXISTS idx_sub_token      ON subscribers(unsubscribe_token);
    CREATE        INDEX IF NOT EXISTS idx_sub_form_slug  ON subscribers(form_slug);

    CREATE TABLE IF NOT EXISTS media (
      id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      form_slug     VARCHAR(100),
      s3_key        VARCHAR(500) NOT NULL,
      url           VARCHAR(500) NOT NULL,
      original_name VARCHAR(255),
      mime_type     VARCHAR(100),
      size          INTEGER,
      folder        VARCHAR(100) NOT NULL DEFAULT '',
      uploaded_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_media_form_slug ON media(form_slug);

    CREATE TABLE IF NOT EXISTS fonts (
      id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      name        VARCHAR(100) NOT NULL UNIQUE,
      s3_key      VARCHAR(500) NOT NULL,
      url         VARCHAR(500) NOT NULL,
      uploaded_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS design_templates (
      id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      name       VARCHAR(255) NOT NULL,
      design     JSONB        NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics (
      form_slug    VARCHAR(100) NOT NULL REFERENCES forms(slug) ON DELETE CASCADE,
      key          VARCHAR(50)  NOT NULL,
      count        BIGINT       NOT NULL DEFAULT 0,
      last_updated TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      PRIMARY KEY (form_slug, key)
    );
  `);
  console.log('✔ Database tables ready');
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

// ── CSRF protection ───────────────────────────────────────────────────────────
// Double-submit pattern: token stored in session, sent as X-CSRF-Token header.
// GET /api/admin/csrf-token exposes the token to the admin SPA on load.
function csrfCheck(req, res, next) {
  const token = req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrf) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
}

// Single middleware covers all state-changing admin API calls — no per-route changes needed.
// GET / HEAD / OPTIONS are safe methods and pass through without a token check.
app.use('/api/admin', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!isAdminUser(req.session)) return next(); // let adminAuth handle 401
  return csrfCheck(req, res, next);
});

// ════════════════════════════════════════
// PUBLIC ROUTES  (named routes BEFORE /:slug wildcard)
// ════════════════════════════════════════

// Root → redirect to first form
app.get('/', async (req, res) => {
  try {
    const idx = await readFormsIndex();
    if (idx.length) return res.redirect(`/${idx[0].slug}`);
  } catch (e) {}
  res.status(404).send('<p>No forms found. <a href="/admin">Go to admin</a></p>');
});

// Privacy policy — uses first form for branding
app.get('/privacy', async (req, res) => {
  try {
    const idx = await readFormsIndex();
    const cfg = idx.length ? await readFormConfig(idx[0].slug) : defaultFormConfig('_', 'SignFlow');
    const sharedFonts = await readSharedFonts();
    res.send(renderPrivacyPage(cfg, sharedFonts));
  } catch (e) { res.status(500).send('Error'); }
});

// Helper: find which form a subscriber token belongs to (returns { slug, subscriber })
async function findSubscriberByToken(email, token) {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM subscribers
       WHERE email=$1 AND unsubscribe_token=$2
       LIMIT 1`,
      [decodeURIComponent(email), token]
    );
    if (!rows.length) return null;
    return { slug: rows[0].form_slug, subscriber: rowToSubscriber(rows[0]) };
  } catch(e) { return null; }
}

// Helper: get all subscriptions for an email across all forms
async function findAllSubscriptions(email) {
  try {
    const { rows } = await pool.query(
      `SELECT s.*, f.slug AS form_slug, f.config->'site'->>'title' AS form_title
       FROM subscribers s JOIN forms f ON f.slug = s.form_slug
       WHERE s.email = $1`,
      [decodeURIComponent(email)]
    );
    return rows.map(r => ({
      slug: r.form_slug, sub: rowToSubscriber(r),
      formName: r.form_title || r.form_slug
    }));
  } catch(e) { return []; }
}

// Preference centre — GET: show page
app.get('/preferences', async (req, res) => {
  const { token, email } = req.query;
  let cfg;
  const found = (token && email) ? await findSubscriberByToken(email, token) : null;
  try {
    if (found) cfg = await readFormConfig(found.slug);
    else { const idx = await readFormsIndex(); cfg = idx.length ? await readFormConfig(idx[0].slug) : defaultFormConfig('_','SignFlow'); }
  } catch(e) { cfg = defaultFormConfig('_','SignFlow'); }
  const [sharedFonts, allSubs] = await Promise.all([readSharedFonts(), email ? findAllSubscriptions(email) : Promise.resolve([])]);
  res.send(renderPreferencePage(cfg, { token, email, found, allSubs }, sharedFonts));
});

// Preference centre — POST: perform action
app.post('/preferences', async (req, res) => {
  const { token, email, action } = req.body;
  let cfg;
  const found = (token && email) ? await findSubscriberByToken(email, token) : null;
  try {
    if (found) cfg = await readFormConfig(found.slug);
    else { const idx = await readFormsIndex(); cfg = idx.length ? await readFormConfig(idx[0].slug) : defaultFormConfig('_','SignFlow'); }
  } catch(e) { cfg = defaultFormConfig('_','SignFlow'); }

  let message = '', success = false;
  if (!found) {
    message = 'Invalid or expired link. Please use the link from your email.';
  } else if (action === 'unsub-one') {
    await pool.query(
      `UPDATE subscribers SET status='unsubscribed', unsubscribed_at=NOW()
       WHERE id=$1`, [found.subscriber.id]);
    message = 'You have been unsubscribed from this mailing.';
    success = true;
  } else if (action === 'unsub-all') {
    await pool.query(
      `UPDATE subscribers SET status='unsubscribed', unsubscribed_at=NOW()
       WHERE email=$1`, [decodeURIComponent(email)]);
    message = 'You have been unsubscribed from all mailings.';
    success = true;
  } else if (action === 'delete-all') {
    await pool.query('DELETE FROM subscribers WHERE email=$1', [decodeURIComponent(email)]);
    message = 'Your data has been permanently deleted from all our records.';
    success = true;
  } else {
    message = 'Unknown action.';
  }
  const [sharedFonts, allSubs] = await Promise.all([readSharedFonts(), email ? findAllSubscriptions(email) : Promise.resolve([])]);
  res.send(renderPreferencePage(cfg, { token, email, found: success ? null : found, message, success, allSubs }, sharedFonts));
});

// Backward compat: /unsubscribe redirects to /preferences
app.get('/unsubscribe', async (req, res) => {
  const { token, email } = req.query;
  if (token && email) return res.redirect(302, `/preferences?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`);
  let cfg;
  try { const idx = await readFormsIndex(); cfg = idx.length ? await readFormConfig(idx[0].slug) : defaultFormConfig('_','SignFlow'); }
  catch(e) { cfg = defaultFormConfig('_','SignFlow'); }
  const sharedFonts = await readSharedFonts();
  res.send(renderPreferencePage(cfg, {}, sharedFonts));
});

// Backward compat: /delete-data redirects to /preferences
app.get('/delete-data', async (req, res) => {
  const { token, email } = req.query;
  if (token && email) return res.redirect(302, `/preferences?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`);
  let cfg;
  try { const idx = await readFormsIndex(); cfg = idx.length ? await readFormConfig(idx[0].slug) : defaultFormConfig('_','SignFlow'); }
  catch(e) { cfg = defaultFormConfig('_','SignFlow'); }
  const sharedFonts = await readSharedFonts();
  res.send(renderPreferencePage(cfg, {}, sharedFonts));
});

// ════════════════════════════════════════
// AUTH0 ROUTES
// ════════════════════════════════════════

// Kick off Auth0 login
app.get('/auth/login', authLimiter, (req, res) => {
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
app.get('/auth/callback', authLimiter, async (req, res) => {
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

    // Store user in session and generate a per-session CSRF token
    req.session.user = claims;
    req.session.accessToken = tokenSet.access_token;
    req.session.csrf = require('crypto').randomBytes(32).toString('hex');
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

// ════════════════════════════════════════
// ADMIN ROUTES
// ════════════════════════════════════════

// Admin panel SPA
app.get('/admin', adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

// Return total file size of all media items for a form (from DB)
async function getFormMediaSize(slug) {
  try {
    const { rows } = await pool.query(
      'SELECT COALESCE(SUM(size), 0) AS total FROM media WHERE form_slug=$1', [slug]);
    return parseInt(rows[0].total, 10);
  } catch(_) { return 0; }
}

// ── Analytics helpers ─────────────────────────────────────────────────────────
async function readAnalytics(slug) {
  const { rows } = await pool.query(
    'SELECT key, count, last_updated FROM analytics WHERE form_slug=$1', [slug]);
  const result = { visits: 0, submits: 0, errors: 0 };
  rows.forEach(r => { result[r.key] = parseInt(r.count, 10); });
  if (rows.length) result.lastUpdated = rows[0].last_updated ? rows[0].last_updated.toISOString() : null;
  return result;
}

// Fire-and-forget analytics increment — never blocks a request
function bumpAnalytic(slug, key) {
  pool.query(
    `INSERT INTO analytics(form_slug, key, count, last_updated)
     VALUES($1, $2, 1, NOW())
     ON CONFLICT(form_slug, key)
     DO UPDATE SET count = analytics.count + 1, last_updated = NOW()`,
    [slug, key]
  ).catch(e => console.error('[analytics]', e.message));
}

// CSRF token endpoint — called once on admin panel load
app.get('/api/admin/csrf-token', adminAuth, (req, res) => {
  // Lazily create token if not yet present (e.g. dev mode without Auth0)
  if (!req.session.csrf) req.session.csrf = require('crypto').randomBytes(32).toString('hex');
  res.json({ token: req.session.csrf });
});

// List all forms (with subscriber counts)
app.get('/api/admin/forms', adminAuth, async (req, res) => {
  try {
    const origin = `${req.protocol}://${req.get('host')}`;
    const idx = await readFormsIndex();
    const [sharedFonts, templates] = await Promise.all([readSharedFonts(), readDesignTemplates()]);
    const result = await Promise.all(idx.map(async f => {
      const entry = { ...f, subscriberCount: 0, embedPageSize: null, embedJsSize: null, mediaSize: null };
      try {
        const cfg = await readFormConfig(f.slug);
        const { rows: countRows } = await pool.query(
          `SELECT COUNT(*) AS c FROM subscribers WHERE form_slug=$1 AND status='active'`, [f.slug]);
        entry.subscriberCount = parseInt(countRows[0].c, 10);
        entry.description   = cfg.site.description || '';
        entry.embedPageSize = Buffer.byteLength(renderEmbedPage(cfg, sharedFonts, templates), 'utf8');
        entry.embedJsSize   = Buffer.byteLength(renderEmbedScript(origin, cfg), 'utf8');
        entry.mediaSize     = await getFormMediaSize(f.slug);
      } catch(_) { /* skip if config unreadable */ }
      entry.analytics = await readAnalytics(f.slug);
      return entry;
    }));
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Create new form
app.post('/api/admin/forms', adminAuth, async (req, res) => {
  try {
    const { error: valErr, value: body } = Joi.object({
      name: Joi.string().min(1).max(100).required(),
      slug: Joi.string().min(1).max(60).pattern(/^[a-z0-9-]+$/).required()
    }).validate(req.body);
    if (valErr) return res.status(400).json({ error: valErr.details[0].message });
    const { slug, name } = body;
    if (RESERVED_SLUGS.has(slug)) return res.status(400).json({ error: 'Slug is reserved' });
    await pool.query(
      'INSERT INTO forms(slug, name, created_at, config) VALUES($1, $2, NOW(), $3)',
      [slug, name, defaultFormConfig(slug, name)]
    );
    res.json({ success: true, slug });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Slug already in use' });
    res.status(500).json({ error: e.message });
  }
});

// Delete a form
app.delete('/api/admin/forms/:slug', adminAuth, async (req, res) => {
  try {
    const { slug } = req.params;
    const idx = await readFormsIndex();
    if (idx.length <= 1) return res.status(400).json({ error: 'Cannot delete the last form' });
    // Delete associated S3 media files before removing the DB record (cascade doesn't cover S3)
    const { rows: mediaRows } = await pool.query('SELECT s3_key FROM media WHERE form_slug=$1', [slug]);
    await Promise.all(mediaRows.map(r =>
      s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: r.s3_key })).catch(() => {})
    ));
    // Delete form — cascades to subscribers, analytics, media (DB rows)
    await pool.query('DELETE FROM forms WHERE slug=$1', [slug]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Rename a form
app.patch('/api/admin/forms/:slug/meta', adminAuth, async (req, res) => {
  try {
    const { slug } = req.params;
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    // Update name column and sync title inside config JSONB (nested jsonb_set)
    const { rowCount } = await pool.query(
      `UPDATE forms
       SET name=$1,
           config = jsonb_set(jsonb_set(config, '{name}', $2::jsonb), '{site,title}', $2::jsonb)
       WHERE slug=$3`,
      [name, JSON.stringify(name), slug]
    );
    if (!rowCount) return res.status(404).json({ error: 'Form not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get a form's config
app.get('/api/admin/forms/:slug', adminAuth, async (req, res) => {
  try { res.json(await readFormConfig(req.params.slug)); }
  catch(e) { res.status(404).json({ error: 'Form not found' }); }
});

// Save a form's config
app.post('/api/admin/forms/:slug', adminAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    // If name changed, also update the name column
    const updates = req.body.name
      ? await pool.query('UPDATE forms SET config=$1, name=$2 WHERE slug=$3', [req.body, req.body.name, slug])
      : await pool.query('UPDATE forms SET config=$1 WHERE slug=$2', [req.body, slug]);
    if (!updates.rowCount) return res.status(404).json({ error: 'Form not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Upload image for a form (or to shared library when shared=1 in body)
app.post('/api/admin/forms/:slug/upload', adminAuth, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const s3Key  = req.file.key;
  const url    = req.file.location;
  const folder = req.body.folder || '';
  const shared = req.body.shared === '1' || req.body.shared === 'true';
  try {
    await pool.query(
      `INSERT INTO media(id, form_slug, s3_key, url, original_name, mime_type, size, folder, uploaded_at)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
      [uuidv4(), shared ? null : req.params.slug, s3Key, url,
       req.file.originalname, req.file.mimetype, req.file.size, folder]
    );
  } catch(_) {}
  res.json({ url });
});

// Upload image directly to shared library
app.post('/api/admin/media/upload', adminAuth, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const s3Key  = req.file.key;
  const url    = req.file.location;
  const folder = req.body.folder || '';
  try {
    await pool.query(
      `INSERT INTO media(id, form_slug, s3_key, url, original_name, mime_type, size, folder, uploaded_at)
       VALUES($1, NULL, $2, $3, $4, $5, $6, $7, NOW())`,
      [uuidv4(), s3Key, url, req.file.originalname, req.file.mimetype, req.file.size, folder]
    );
  } catch(_) {}
  res.json({ url });
});

// Upload font — defaults to shared library; pass shared=0 for form-only
app.post('/api/admin/forms/:slug/upload-font', adminAuth, uploadFont.single('font'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const s3Key   = req.file.key;
  const url     = req.file.location;
  const name    = (req.body.name || '').trim();
  const toShared = req.body.shared !== '0';   // default: save to shared library
  if (toShared && name) {
    try {
      await pool.query(
        `INSERT INTO fonts(id, name, s3_key, url, uploaded_at)
         VALUES($1, $2, $3, $4, NOW())
         ON CONFLICT(name) DO NOTHING`,
        [uuidv4(), name, s3Key, url]
      );
    } catch(_) {}
    return res.json({ url, shared: true });
  }
  res.json({ url, shared: false });
});

// List shared fonts
app.get('/api/admin/fonts', adminAuth, async (req, res) => {
  try { res.json(await readSharedFonts()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// Delete a shared font
app.delete('/api/admin/fonts/:id', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT s3_key FROM fonts WHERE id=$1', [req.params.id]);
    if (rows.length) {
      await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: rows[0].s3_key })).catch(() => {});
      await pool.query('DELETE FROM fonts WHERE id=$1', [req.params.id]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// List media library for a form (shared items first, then form-specific)
app.get('/api/admin/forms/:slug/media', adminAuth, async (req, res) => {
  try {
    const shared = (await readSharedMedia()).map(i => ({ ...i, _shared: true }));
    const form   = (await readFormMedia(req.params.slug)).map(i => ({ ...i, _shared: false }));
    res.json([...shared, ...form]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Delete a media item (removes from S3 + DB)
app.delete('/api/admin/forms/:slug/media', adminAuth, async (req, res) => {
  try {
    const { id } = req.body;
    const { rows } = await pool.query('SELECT s3_key FROM media WHERE id=$1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: rows[0].s3_key })).catch(() => {});
    await pool.query('DELETE FROM media WHERE id=$1', [id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Update media item metadata (folder, name)
app.patch('/api/admin/forms/:slug/media/:id', adminAuth, async (req, res) => {
  try {
    const { folder, name } = req.body;
    const sets = [];
    const vals = [];
    if (folder !== undefined) { sets.push(`folder=$${vals.length+1}`); vals.push(folder); }
    if (name   !== undefined) { sets.push(`original_name=$${vals.length+1}`); vals.push(name); }
    if (!sets.length) return res.json({ success: true });
    vals.push(req.params.id);
    await pool.query(`UPDATE media SET ${sets.join(',')} WHERE id=$${vals.length}`, vals);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Move a media item between form and shared library
app.post('/api/admin/forms/:slug/media/:id/move', adminAuth, async (req, res) => {
  try {
    const { toShared } = req.body;
    const newSlug = toShared ? null : req.params.slug;
    const { rowCount } = await pool.query(
      'UPDATE media SET form_slug=$1 WHERE id=$2', [newSlug, req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get subscribers for a form (paginated)
app.get('/api/admin/forms/:slug/subscribers', adminAuth, async (req, res) => {
  try {
    const slug   = req.params.slug;
    const page   = Math.max(1, parseInt(req.query.page)  || 1);
    const limit  = Math.min(200, parseInt(req.query.limit) || 50);
    const search = (req.query.search || '').trim();
    const status = req.query.status || 'all';
    const offset = (page - 1) * limit;

    const conditions = ['form_slug=$1'];
    const vals = [slug];
    if (status !== 'all') { conditions.push(`status=$${vals.length+1}`); vals.push(status); }
    if (search) {
      conditions.push(`(email ILIKE $${vals.length+1} OR custom_fields::text ILIKE $${vals.length+1})`);
      vals.push(`%${search}%`);
    }
    const where = conditions.join(' AND ');

    const countRes = await pool.query(`SELECT COUNT(*) AS c FROM subscribers WHERE ${where}`, vals);
    const total = parseInt(countRes.rows[0].c, 10);
    const dataRes = await pool.query(
      `SELECT * FROM subscribers WHERE ${where} ORDER BY subscribed_at DESC LIMIT $${vals.length+1} OFFSET $${vals.length+2}`,
      [...vals, limit, offset]
    );
    res.json({ subscribers: dataRes.rows.map(rowToSubscriber), total, page, pages: Math.ceil(total/limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Delete subscriber (GDPR)
app.delete('/api/admin/forms/:slug/subscribers/:id', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM subscribers WHERE id=$1 AND form_slug=$2', [req.params.id, req.params.slug]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Export subscribers as CSV/JSON — marks each exported record
app.get('/api/admin/forms/:slug/export', adminAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const cfg  = await readFormConfig(slug);
    const fmt  = req.query.format || 'csv';
    // Mark every record as exported and fetch updated rows in one query
    await pool.query(
      `UPDATE subscribers SET exported=TRUE, exported_at=NOW() WHERE form_slug=$1`, [slug]);
    const subs = await readFormSubscribers(slug);
    if (fmt === 'json') {
      res.setHeader('Content-Disposition', `attachment; filename="subscribers-${slug}.json"`);
      res.setHeader('Content-Type', 'application/json');
      return res.send(JSON.stringify(subs, null, 2));
    }
    const customFieldIds = cfg.fields.filter(f => !f.system).map(f => f.id);
    const headers = ['id','email','status','subscribedAt','unsubscribedAt','exported','exportedAt','consentGiven','consentTimestamp','ipAddress',...customFieldIds];
    const rows = subs.map(s => headers.map(h => {
      if (customFieldIds.includes(h)) return `"${(s.customFields[h]||'').replace(/"/g,'""')}"`;
      return `"${(s[h]||'').toString().replace(/"/g,'""')}"`;
    }).join(','));
    res.setHeader('Content-Disposition', `attachment; filename="subscribers-${slug}.csv"`);
    res.setHeader('Content-Type', 'text/csv');
    res.send([headers.join(','), ...rows].join('\n'));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Clear export flag for one subscriber
app.post('/api/admin/forms/:slug/subscribers/:id/clear-export', adminAuth, async (req, res) => {
  try {
    await pool.query(
      'UPDATE subscribers SET exported=FALSE, exported_at=NULL WHERE id=$1 AND form_slug=$2',
      [req.params.id, req.params.slug]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Clear export flag for all subscribers
app.post('/api/admin/forms/:slug/subscribers/clear-all-exports', adminAuth, async (req, res) => {
  try {
    await pool.query(
      'UPDATE subscribers SET exported=FALSE, exported_at=NULL WHERE form_slug=$1', [req.params.slug]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: manually unsubscribe a subscriber (keeps record, sets status=unsubscribed)
app.post('/api/admin/forms/:slug/subscribers/:id/unsubscribe', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `UPDATE subscribers SET status='unsubscribed', unsubscribed_at=NOW()
       WHERE id=$1 AND form_slug=$2`, [req.params.id, req.params.slug]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: reactivate a previously unsubscribed subscriber
app.post('/api/admin/forms/:slug/subscribers/:id/reactivate', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `UPDATE subscribers SET status='active', unsubscribed_at=NULL
       WHERE id=$1 AND form_slug=$2`, [req.params.id, req.params.slug]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Analytics: get per-form analytics
app.get('/api/admin/forms/:slug/analytics', adminAuth, async (req, res) => {
  try { res.json(await readAnalytics(req.params.slug)); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// Analytics: reset counters for a form
app.post('/api/admin/forms/:slug/analytics/reset', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM analytics WHERE form_slug=$1', [req.params.slug]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════
// PER-FORM PUBLIC ROUTES  (wildcard — must come LAST)
// ════════════════════════════════════════

// ── Design templates ──────────────────────────────────────────────────────────
app.get('/api/admin/design-templates', adminAuth, async (req, res) => {
  try { res.json(await readDesignTemplates()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/design-templates', adminAuth, async (req, res) => {
  try {
    const { name, design } = req.body;
    if (!name || !design) return res.status(400).json({ error: 'name and design required' });
    const id = uuidv4();
    await pool.query(
      'INSERT INTO design_templates(id, name, design, created_at) VALUES($1, $2, $3, NOW())',
      [id, name, design]
    );
    res.json({ id, name, design, createdAt: new Date().toISOString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/design-templates/:id', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM design_templates WHERE id=$1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/design-templates/:id', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'UPDATE design_templates SET design=$1 WHERE id=$2', [req.body.design, req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    const templates = await readDesignTemplates();
    const tmpl = templates.find(t => t.id === req.params.id);
    res.json(tmpl || { id: req.params.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Branding tab preview — standalone dummy form, no form slug required
// Uses GENERIC_PREVIEW_SECTIONS/FIELDS with selected form's design (or defaults).
app.get('/branding-preview', adminAuth, async (req, res) => {
  try {
    const [sharedFonts, templates] = await Promise.all([readSharedFonts(), readDesignTemplates()]);
    let formCfg = defaultFormConfig('_preview', 'Preview');
    // If a real form slug is provided, inherit its design (fonts, colours, etc.)
    if (req.query.slug) {
      try {
        const realCfg = await readFormConfig(req.query.slug);
        if (realCfg && realCfg.design) formCfg = { ...formCfg, design: { ...realCfg.design } };
      } catch (_) { /* slug not found — fall back to defaults */ }
    }
    formCfg = { ...formCfg, sections: GENERIC_PREVIEW_SECTIONS, fields: GENERIC_PREVIEW_FIELDS };
    // Apply template design if requested (preserve per-form custom fonts)
    if (req.query._tplPreview) {
      const tpl = templates.find(t => t.id === req.query._tplPreview);
      if (tpl && tpl.design) {
        formCfg = { ...formCfg, design: { ...formCfg.design, ...tpl.design, customFonts: (formCfg.design || {}).customFonts || [] } };
      }
    }
    res.send(renderPublicPage(formCfg, sharedFonts, templates));
  } catch (e) {
    res.status(500).send('Preview error: ' + e.message);
  }
});

// Public form page
app.get('/:slug', async (req, res) => {
  const { slug } = req.params;
  if (RESERVED_SLUGS.has(slug)) return res.status(404).send('Not found');
  try {
    let formCfg = await readFormConfig(slug);
    if (!req.query._preview && !req.query._tplPreview) bumpAnalytic(slug, 'visits');
    const [sharedFonts, templates] = await Promise.all([readSharedFonts(), readDesignTemplates()]);
    const tplPreviewId = req.query._tplPreview;
    if (tplPreviewId) {
      const tpl = templates.find(t => t.id === tplPreviewId);
      if (tpl && tpl.design) formCfg = { ...formCfg, design: { ...tpl.design, customFonts: (formCfg.design || {}).customFonts } };
    }
    // ?_generic=1 — replace sections/fields with neutral demo content (used by design-tab preview)
    if (req.query._generic) {
      formCfg = { ...formCfg, sections: GENERIC_PREVIEW_SECTIONS, fields: GENERIC_PREVIEW_FIELDS };
    }
    res.send(renderPublicPage(formCfg, sharedFonts, templates));
  }
  catch(e) { res.status(404).send('<p>Form not found. <a href="/">Home</a></p>'); }
});

// Confirmation/response state preview (admin only)
app.get('/:slug/confirmation-preview', adminAuth, async (req, res) => {
  try {
    const [cfg, sharedFonts, templates] = await Promise.all([
      readFormConfig(req.params.slug), readSharedFonts(), readDesignTemplates()]);
    let html = renderPublicPage(cfg, sharedFonts, templates);
    // Inject script to immediately show the confirmation state and hide the form
    html = html.replace('</body>',
      '<script>document.addEventListener("DOMContentLoaded",function(){' +
      'var f=document.getElementById("sf-form");' +
      'var c=document.getElementById("sf-confirmation");' +
      'if(f)f.style.display="none";' +
      'if(c){c.style.display="block";}' +
      '});<\/script></body>');
    res.send(html);
  } catch(e) { res.status(404).send('Form not found'); }
});

// Embed iframe page — allows framing; respects per-form domain allowlist
app.get('/:slug/embed', async (req, res) => {
  try {
    const [cfg, sharedFonts, templates] = await Promise.all([
      readFormConfig(req.params.slug), readSharedFonts(), readDesignTemplates()]);

    // ── Domain allowlist check ───────────────────────────────────────────────
    const allowedDomains = (cfg.site.embedAllowedDomains || []).filter(Boolean);
    if (allowedDomains.length > 0) {
      const origin = req.get('Origin') || req.get('Referer') || '';
      const matched = allowedDomains.some(d => origin.includes(d.trim()));
      if (!matched) return res.status(403).send('Embedding not allowed from this origin.');
    }

    // ── Dynamic frame-ancestors ──────────────────────────────────────────────
    const faVal = allowedDomains.length > 0
      ? allowedDomains.map(d => `https://${d.trim()}`).join(' ')
      : '*';

    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://js.hcaptcha.com; " +
      "script-src-attr 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com https://*.amazonaws.com; img-src 'self' data: blob: https:; " +
      "connect-src 'self' https://api.hcaptcha.com; " +
      "frame-src https://www.youtube.com https://player.vimeo.com; " +
      `frame-ancestors ${faVal}; object-src 'none'; base-uri 'self'`);
    res.send(renderEmbedPage(cfg, sharedFonts, templates));
  } catch(e) { res.status(404).send('Form not found'); }
});

// Embed JS snippet
app.get('/:slug/embed.js', async (req, res) => {
  try {
    const cfg = await readFormConfig(req.params.slug);
    const origin = `${req.protocol}://${req.get('host')}`;
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=60');
    res.send(renderEmbedScript(origin, cfg));
  } catch(e) { res.status(404).send('// Form not found'); }
});

// Form submission
app.post('/:slug/subscribe', submitLimiter, async (req, res) => {
  const { slug } = req.params;
  let cfg;
  try { cfg = await readFormConfig(slug); }
  catch(e) { return res.status(404).json({ error: 'Form not found' }); }
  const body = req.body;

  if (cfg.site.captchaEnabled && cfg.site.hcaptchaSecretKey) {
    const captchaToken = body['h-captcha-response'] || '';
    if (!captchaToken) { bumpAnalytic(slug, 'errors'); return res.status(400).json({ error: 'Please complete the CAPTCHA.' }); }
    try {
      const vp = new URLSearchParams({ secret: cfg.site.hcaptchaSecretKey, response: captchaToken, remoteip: req.ip });
      const vr = await fetch('https://api.hcaptcha.com/siteverify', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: vp.toString() });
      const vj = await vr.json();
      if (!vj.success) { bumpAnalytic(slug, 'errors'); return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' }); }
    } catch(e) { return res.status(500).json({ error: 'CAPTCHA service error. Please try again.' }); }
  }

  // ── Joi input validation ──────────────────────────────────────────────────
  const schemaShape = { email: Joi.string().email({ tlds: { allow: false } }).max(254).required() };
  cfg.fields.filter(f => !f.system).forEach(f => {
    schemaShape[f.id] = Joi.string().max(1000).allow('').optional();
  });
  const { error: valErr, value: validated } = Joi.object(schemaShape).unknown(true).validate(body);
  if (valErr) {
    bumpAnalytic(slug, 'errors');
    return res.status(400).json({ error: valErr.details[0].message });
  }
  const email = validated.email.trim().toLowerCase();

  // Check for existing active subscription
  const { rows: existingRows } = await pool.query(
    `SELECT id, status FROM subscribers WHERE form_slug=$1 AND email=$2 LIMIT 1`, [slug, email]);
  const existing = existingRows[0] || null;
  if (existing && existing.status === 'active') {
    bumpAnalytic(slug, 'errors');
    return res.status(409).json({ error: 'This email is already subscribed.' });
  }

  const customFields = {};
  cfg.fields.filter(f => !f.system).forEach(f => { customFields[f.id] = (body[f.id] || '').trim(); });

  const id             = uuidv4();
  const token          = uuidv4();
  const now            = new Date().toISOString();
  const record         = { id, email, status: 'active', subscribedAt: now, unsubscribedAt: null,
                           unsubscribeToken: token, consentGiven: true, consentTimestamp: now,
                           ipAddress: req.ip, customFields };

  if (existing) {
    // Re-activate a previously unsubscribed record
    await pool.query(
      `UPDATE subscribers SET status='active', subscribed_at=NOW(), unsubscribed_at=NULL,
       unsubscribe_token=$1, consent_given=TRUE, consent_timestamp=$2,
       ip_address=$3, custom_fields=$4 WHERE id=$5`,
      [token, now, req.ip, customFields, existing.id]
    );
    record.id = existing.id;
  } else {
    await pool.query(
      `INSERT INTO subscribers
       (id, form_slug, email, status, subscribed_at, unsubscribed_at,
        unsubscribe_token, consent_given, consent_timestamp, ip_address, custom_fields)
       VALUES($1,$2,$3,'active',NOW(),NULL,$4,TRUE,$5,$6,$7)`,
      [id, slug, email, token, now, req.ip, customFields]
    );
  }

  bumpAnalytic(slug, 'submits');
  // Fire-and-forget welcome email (never blocks the response)
  sendWelcomeEmail(cfg, record).catch(e => console.error('[email]', e.message));
  res.json({ success: true });
});

// ════════════════════════════════════════
// PAGE RENDERERS
// ════════════════════════════════════════

// Fonts that are NOT on Google Fonts (premium/custom — require .woff2 upload)
const NON_GF_FONTS = new Set(['Roc Grotesk']);

function googleFontTag(cfg, effectiveDesign, sharedFonts = []) {
  // Merge shared + per-form custom fonts; both bypass Google Fonts loading
  const allCustomNames = new Set([
    ...sharedFonts.map(f => f.name),
    ...(cfg.design.customFonts || []).map(f => f.name)
  ]);
  // Use effective design (may be template-overridden) for font selection
  const d = effectiveDesign || cfg.design;
  const seen = new Set();
  const fonts = [d.h1Font||d.googleFont, d.h2Font||d.googleFont, d.h3Font||d.googleFont, d.h4Font||d.googleFont, d.bodyFont, d.btnFont]
    .filter(Boolean)
    .filter(f => !NON_GF_FONTS.has(f) && !allCustomNames.has(f))
    .filter(f => { if(seen.has(f)) return false; seen.add(f); return true; });
  if (!fonts.length) return '';
  const query = fonts.map(f => f.replace(/ /g, '+')).join('&family=');
  return `<link href="https://fonts.googleapis.com/css2?family=${query}:wght@300;400;600;700&display=swap" rel="stylesheet">`;
}

function gdprHtml(siteCfg) {
  const text = siteCfg.gdprText ||
    'By subscribing you agree to our <a href="{privacyUrl}" target="_blank">Privacy Policy</a>. We store your data securely and you can unsubscribe or request deletion at any time.';
  return text.replace(/\{privacyUrl\}/g, siteCfg.privacyPolicyUrl || '#');
}

function customFontFaceCSS(cfg, sharedFonts = []) {
  // Merge shared fonts (loaded for every form) + per-form fonts, deduplicated by name
  const shared = sharedFonts;
  const formFonts = cfg.design.customFonts || [];
  const seen = new Set();
  const fonts = [...shared, ...formFonts].filter(f => {
    if (seen.has(f.name)) return false;
    seen.add(f.name);
    return true;
  });
  if (!fonts.length) return '';
  const faces = fonts.map(f => {
    const ext = f.url.split('.').pop().toLowerCase();
    const fmt = ext === 'woff2' ? 'woff2' : ext === 'woff' ? 'woff' : ext === 'otf' ? 'opentype' : 'truetype';
    return `@font-face { font-family: '${f.name}'; src: url('${f.url}') format('${fmt}'); font-weight: 100 900; font-display: swap; }`;
  }).join('\n  ');
  return `<style>\n  ${faces}\n</style>`;
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
      <label for="sf_${f.id}">${escapeHtml(f.label)}${req}</label>
      <select id="sf_${f.id}" name="${f.id}" ${f.required ? 'required' : ''}>
        <option value="">— Select —</option>
        ${(f.options || []).map(o => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('')}
      </select></div>`;
  }

  // ── checkbox ──
  if (f.type === 'checkbox') {
    return `<div class="sf-field sf-field--check"${condAttr}>
      <label><input type="checkbox" name="${f.id}" value="yes" ${f.required ? 'required' : ''}> ${escapeHtml(f.label)}${req}</label></div>`;
  }

  // ── textarea ──
  if (f.type === 'textarea') {
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${escapeHtml(f.label)}${req}</label>
      <textarea id="sf_${f.id}" name="${f.id}" placeholder="${escapeHtml(f.placeholder || '')}" ${f.required ? 'required' : ''} rows="3"></textarea></div>`;
  }

  // ── age ──
  if (f.type === 'age') {
    const curYear = new Date().getFullYear();
    const minAge = f.minAge || 0;
    const maxAge = f.maxAge || 120;
    const minYear = curYear - maxAge;
    const maxYear = curYear - minAge;
    return `<div class="sf-field"${condAttr}>
      <label for="sf_${f.id}">${escapeHtml(f.label)}${req}</label>
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
      <label>${escapeHtml(f.label)}${req}</label>
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
      <label>${escapeHtml(f.label)}${req}</label>
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
        <label>${escapeHtml(f.label)}${req}</label>
        <div class="sf-slider-wrap sf-slider-arc" style="--sf-accent:${accent};--sf-knob:${knobPx}px;--sf-val-size:${valSize}px">
          <svg class="sf-arc-svg" viewBox="0 0 220 125" xmlns="http://www.w3.org/2000/svg" style="touch-action:none;overflow:visible">
            <path class="sf-arc-bg" d="M 20 110 A 90 90 0 0 1 200 110" fill="none" stroke="#e0e0e0" stroke-width="${trackPx}" stroke-linecap="round"/>
            <path class="sf-arc-fill" d="M 20 110 A 90 90 0 0 1 200 110" fill="none" stroke="${accent}" stroke-width="${trackPx}" stroke-linecap="round"
              stroke-dasharray="${fillLen} ${arcLen}" stroke-dashoffset="0"/>
            <g class="sf-arc-handle" transform="rotate(${initRot} ${CX} ${CY})" style="cursor:grab;touch-action:none">
              <circle cx="${CX - R}" cy="${CY}" r="${knobPx / 2}" fill="${accent}"/>
              <text x="${CX - R}" y="${CY + 1}" text-anchor="middle" dominant-baseline="middle"
                font-size="${knobPx * 0.48}" fill="#fff" style="pointer-events:none;user-select:none">${escapeHtml(icon)}</text>
            </g>
            ${(minLbl || maxLbl) ? `
            <text x="20" y="122" text-anchor="middle" font-size="10" fill="#aaa">${escapeHtml(minLbl)}</text>
            <text x="200" y="122" text-anchor="middle" font-size="10" fill="#aaa">${escapeHtml(maxLbl)}</text>` : ''}
          </svg>
          ${showVal ? `<div class="sf-slider-val" style="font-size:var(--sf-val-size)">${def}</div>` : ''}
          <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${def}" ${dataAttrs} ${f.required ? 'required' : ''}>
        </div></div>`;
    }

    // linear or angled — labels go BELOW the track to avoid overlap
    const angledClass = track === 'angled' ? ' sf-slider-angled' : '';
    return `<div class="sf-field sf-field--slider"${condAttr}>
      <label>${escapeHtml(f.label)}${req}</label>
      <div class="sf-slider-wrap${angledClass}" style="--sf-accent:${accent};--sf-knob:${knobPx}px;--sf-track:${trackPx}px;--sf-val-size:${valSize}px">
        <div class="sf-slider-track" style="touch-action:none">
          <div class="sf-slider-fill" style="width:${pct}%"></div>
          <div class="sf-slider-handle" tabindex="0" role="slider"
            aria-valuemin="${min}" aria-valuemax="${max}" aria-valuenow="${def}"
            style="left:${pct}%">
            <span class="sf-slider-icon">${escapeHtml(icon)}</span>
          </div>
        </div>
        ${(minLbl || maxLbl) ? `<div class="sf-slider-lbls"><span>${escapeHtml(minLbl)}</span><span>${escapeHtml(maxLbl)}</span></div>` : ''}
        ${showVal ? `<div class="sf-slider-val" style="font-size:var(--sf-val-size)">${def}</div>` : ''}
        <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${def}" ${dataAttrs} ${f.required ? 'required' : ''}>
      </div></div>`;
  }

  // ── default (text, email, number, tel, etc.) ──
  return `<div class="sf-field"${condAttr}>
    <label for="sf_${f.id}">${escapeHtml(f.label)}${req}</label>
    <input type="${f.type || 'text'}" id="sf_${f.id}" name="${f.id}"
      placeholder="${escapeHtml(f.placeholder || '')}" ${f.required ? 'required' : ''}></div>`;
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
  .sf-slider-track{position:relative;height:var(--sf-knob,32px);background:transparent;cursor:pointer;margin:2px 0;-webkit-tap-highlight-color:transparent;}
  .sf-slider-track::before{content:'';position:absolute;left:0;right:0;top:50%;transform:translateY(-50%);height:var(--sf-track,6px);background:#e0e0e0;border-radius:99px;pointer-events:none;}
  .sf-slider-fill{position:absolute;left:0;top:50%;transform:translateY(-50%);height:var(--sf-track,6px);background:var(--sf-accent,#e94560);border-radius:99px;pointer-events:none;}
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
function renderBlockElement(el, cfg) {
  if (!el) return '';
  if (el.type === 'field') {
    const f = cfg && (cfg.fields||[]).find(fd => fd.id === el.fieldId);
    if (!f) return '';
    const st = el.style || {};
    const vars = [
      st.labelColor ? `--sf-lbl:${st.labelColor}` : '',
      st.textColor  ? `--sf-txt:${st.textColor}`  : '',
      st.bg         ? `--sf-fbg:${st.bg}`          : '',
      st.fontFamily ? `--sf-ff:'${st.fontFamily}',sans-serif` : '',
      st.fontSize   ? `--sf-fsz:${st.fontSize}px`  : ''
    ].filter(Boolean).join(';');
    const html = renderFormField(f, cfg);
    return vars ? `<div style="${vars}">${html}</div>` : html;
  }
  if (el.type === 'submit') {
    const d2 = (cfg&&cfg.design)||{};
    const s2 = (cfg&&cfg.site)||{};
    const btnBg = el.btnBg || d2.btnBg || d2.accentColor || '';
    const btnTc = el.btnTextColor || d2.btnTextColor || '#fff';
    const btnStyle = (btnBg||btnTc!=='#fff') ? ` style="background:${btnBg||'var(--btn-bg)'};color:${btnTc}"` : '';
    const btnLabel = el.buttonText || d2.buttonText || 'Subscribe';
    return `<div class="sf-gdpr">${gdprHtml(s2)}</div>
    ${s2.captchaEnabled && s2.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${s2.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
    <button type="submit" class="sf-btn"${btnStyle}>${escapeHtml(btnLabel)}</button>
    <div id="sf-msg" class="sf-msg"></div>`;
  }
  switch (el.type) {
    case 'heading': {
      const tag = ['h1','h2','h3','h4'][Math.min((el.level || 2) - 1, 3)];
      const align = el.align ? `text-align:${el.align};` : '';
      return `<${tag} class="sf-el-heading" style="${align}margin:12px 0 6px;line-height:1.3">${escapeHtml(el.text || '')}</${tag}>`;
    }
    case 'paragraph': {
      const align = el.align ? `text-align:${el.align};` : '';
      return `<p class="sf-el-para" style="${align}margin:8px 0;line-height:1.7">${escapeHtml(el.text || '')}</p>`;
    }
    case 'image': {
      if (!el.url) return '';
      const w = el.width || '100%';
      const a = el.align || 'center';
      const m = a === 'right' ? '8px 0 8px auto' : a === 'left' ? '8px auto 8px 0' : '8px auto';
      return `<img src="${el.url}" alt="${escapeHtml(el.alt || '')}" style="max-width:100%;width:${w};border-radius:6px;margin:${m};display:block">`;
    }
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
      return `<div style="margin:8px 0;line-height:1.7">${sanitizeWysiwyg(el.html)}</div>`;
    case 'video': {
      if (!el.url) return '';
      const [rw, rh] = (el.aspectRatio || '16:9').split(':').map(Number);
      const pb = ((rh / rw) * 100).toFixed(2) + '%';
      const ap = el.autoplay;
      let emb = '';
      const yt = el.url.match(/(?:v=|youtu\.be\/|embed\/)([^&?#]+)/);
      const vi = el.url.match(/vimeo\.com\/(\d+)/);
      if (yt) emb = `https://www.youtube.com/embed/${yt[1]}${ap ? '?autoplay=1&mute=1&playsinline=1' : ''}`;
      else if (vi) emb = `https://player.vimeo.com/video/${vi[1]}${ap ? '?autoplay=1&muted=1' : ''}`;
      const inner = emb
        ? `<iframe src="${emb}" style="position:absolute;inset:0;width:100%;height:100%;border:0" allowfullscreen allow="autoplay; encrypted-media"></iframe>`
        : `<video src="${el.url}" ${ap ? 'autoplay muted playsinline loop ' : ''}controls style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover"></video>`;
      return `<div style="margin:8px 0"><div style="position:relative;padding-bottom:${pb};height:0;overflow:hidden;border-radius:8px">${inner}</div>${el.caption ? `<p style="text-align:center;font-size:0.82rem;color:#999;margin-top:6px">${escapeHtml(el.caption)}</p>` : ''}</div>`;
    }
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
    const hc = h.colors || {};
    // Apply per-section color overrides as inline styles (override CSS vars)
    const h1Sty = hc.text ? ` style="color:${hc.text}"` : '';
    const subSty = hc.text ? ` style="color:${hc.text}"` : '';
    const bgSty = hc.bg ? ` style="background:${hc.bg};padding:20px;border-radius:8px;margin-bottom:4px"` : '';
    return `<div${bgSty}>
    ${h.imageUrl && h.imagePosition === 'above' ? `<img src="${h.imageUrl}" class="sf-hero-img" alt="">` : ''}
    <h1${h1Sty}>${escapeHtml(h.heading || '')}</h1>
    ${h.subheading ? `<p class="sf-sub"${subSty}>${escapeHtml(h.subheading)}</p>` : ''}
    ${h.imageUrl && h.imagePosition === 'below' ? `<img src="${h.imageUrl}" class="sf-hero-img below" alt="">` : ''}
    </div>`;
  }

  // Form (inner content only — <form> wrapper is at the card level)
  if (section.id === 'form' || section.type === 'form') {
    return `
    ${formFields}
    <div class="sf-gdpr">${gdprHtml(s)}</div>
    ${s.captchaEnabled && s.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${s.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
    <button type="submit" class="sf-btn">${escapeHtml(d.buttonText)}</button>
    <div id="sf-msg" class="sf-msg"></div>`;
  }

  // Footer
  if (section.id === 'footer' || section.type === 'footer') {
    if (section.items && section.items.length > 0) {
      return `<div class="sf-footer">${section.items.map(item => renderBlockElement(item, cfg)).join('')}</div>`;
    }
    return `<p class="sf-footer">${escapeHtml(section.text || '')}</p>`;
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
    const ap = section.autoplay;
    let embedUrl = '';
    const ytMatch = url.match(/(?:v=|youtu\.be\/|embed\/)([^&?#]+)/);
    const viMatch = url.match(/vimeo\.com\/(\d+)/);
    if (ytMatch) embedUrl = `https://www.youtube.com/embed/${ytMatch[1]}${ap ? '?autoplay=1&mute=1&playsinline=1' : ''}`;
    else if (viMatch) embedUrl = `https://player.vimeo.com/video/${viMatch[1]}${ap ? '?autoplay=1&muted=1' : ''}`;
    const inner = embedUrl
      ? `<iframe src="${embedUrl}" style="position:absolute;top:0;left:0;width:100%;height:100%;border:0" allowfullscreen allow="autoplay; encrypted-media"></iframe>`
      : `<video src="${url}" ${ap ? 'autoplay muted playsinline loop ' : ''}controls style="position:absolute;top:0;left:0;width:100%;height:100%;object-fit:cover"></video>`;
    return `<div style="margin:20px 0">
    <div style="position:relative;padding-bottom:${pb};height:0;overflow:hidden;border-radius:8px">${inner}</div>
    ${section.caption ? `<p style="text-align:center;font-size:0.82rem;color:#999;margin-top:8px">${escapeHtml(section.caption)}</p>` : ''}
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
    <button class="sf-btn" style="margin-top:16px;max-width:280px" id="${swId}_btn">${escapeHtml(section.spinButtonText || 'Spin!')}</button>
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

  // Container block — flexible mix of fields, submit button, and content blocks
  if (section.type === 'container') {
    const items = section.items || [];
    const style = section.style || {};
    const cols = section.columns || 1;
    // Support both new (borderColor/borderWidth) and old (border string) formats
    const borderStr = style.borderColor
      ? `border:${style.borderWidth || 1}px solid ${style.borderColor}`
      : style.border ? `border:${style.border}` : '';
    const radiusStr = style.radius || (d.cardRadius || '8px');
    const hasStyle = !!(style.bg || borderStr || style.shadow);
    const baseProps = [
      style.bg ? `background:${style.bg}` : '',
      borderStr,
      style.shadow ? 'box-shadow:0 4px 20px rgba(0,0,0,.1)' : '',
      hasStyle ? `border-radius:${radiusStr};padding:16px 20px` : '',
      'margin:12px 0',
      cols === 2 ? 'display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start' : '',
    ].filter(Boolean).join(';');
    const renderCntItem = (item) => {
      if (!item) return '';
      if (item.type === 'field') {
        const f = (cfg.fields||[]).find(fd => fd.id === item.fieldId);
        if (!f) return '';
        const st = item.style || {};
        const vars = [
          st.labelColor ? `--sf-lbl:${st.labelColor}` : '',
          st.textColor  ? `--sf-txt:${st.textColor}`  : '',
          st.bg         ? `--sf-fbg:${st.bg}`          : '',
          st.fontFamily ? `--sf-ff:'${st.fontFamily}',sans-serif` : '',
          st.fontSize   ? `--sf-fsz:${st.fontSize}px`  : ''
        ].filter(Boolean).join(';');
        const html = renderFormField(f, cfg);
        return vars ? `<div style="${vars}">${html}</div>` : html;
      }
      if (item.type === 'submit') {
        const btnLabel = item.buttonText || d.buttonText || 'Subscribe';
        const btnBg = item.btnBg || d.btnBg || d.accentColor || '';
        const btnTc = item.btnTextColor || d.btnTextColor || '#fff';
        const btnSty = (item.btnBg || item.btnTextColor) ? ` style="background:${btnBg||'var(--btn-bg)'};color:${btnTc}"` : '';
        return `<div class="sf-gdpr">${gdprHtml(s)}</div>
        ${s.captchaEnabled && s.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${s.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
        <button type="submit" class="sf-btn"${btnSty}>${escapeHtml(btnLabel)}</button>
        <div id="sf-msg" class="sf-msg"></div>`;
      }
      return renderBlockElement(item, cfg);
    };
    if (cols === 2) {
      const mid = Math.ceil(items.length / 2);
      const c1 = (section.col1||items.slice(0,mid)).map(renderCntItem).join('');
      const c2 = (section.col2||items.slice(mid)).map(renderCntItem).join('');
      return `<div style="${baseProps}"><div>${c1}</div><div>${c2}</div></div>`;
    }
    return `<div style="${baseProps}">${items.map(renderCntItem).join('')}</div>`;
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
    const elHtml = elements.map(el => renderBlockElement(el, cfg)).join('');
    if (cols === 2) {
      // Split elements roughly in half for 2-col layout
      const half = Math.ceil(elements.length / 2);
      const col1 = elements.slice(0, half).map(el => renderBlockElement(el, cfg)).join('');
      const col2 = elements.slice(half).map(el => renderBlockElement(el, cfg)).join('');
      return `<div class="sf-content-block"${wAttr} style="${blockStyle};display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start;margin:16px 0"><div>${col1}</div><div>${col2}</div></div>`;
    }
    return `<div class="sf-content-block"${wAttr} style="${blockStyle};margin:16px 0">${elHtml}</div>`;
  }

  return '';
}

function hexToRgb(hex) {
  const h = (hex||'#000000').replace('#','');
  const r = parseInt(h.slice(0,2),16)||0, g = parseInt(h.slice(2,4),16)||0, b = parseInt(h.slice(4,6),16)||0;
  return `${r},${g},${b}`;
}

function renderPublicPage(cfg, sharedFonts = [], templates = []) {
  let d = cfg.design || {};
  if (cfg.designTemplateId) {
    const tpl = templates.find(t => t.id === cfg.designTemplateId);
    if (tpl && tpl.design) d = { ...tpl.design, customFonts: (cfg.design || {}).customFonts };
  }
  const s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');

  const formFields = cfg.fields.map(f => renderFormField(f, cfg)).join('');

  const overlayRgb = hexToRgb(d.backgroundOverlayColor||'#000000');
  const bgStyle = d.backgroundImage
    ? `background: linear-gradient(rgba(${overlayRgb},${d.backgroundOverlay}),rgba(${overlayRgb},${d.backgroundOverlay})), url('${d.backgroundImage}') center/cover no-repeat fixed; color: #fff;`
    : `background: ${d.backgroundColor};`;

  const confirmationBlocks = (cfg.confirmation || []).map(sec => renderSectionBlock(sec, cfg, null, '')).join('\n  ');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(s.title)}</title>
${googleFontTag(cfg, d, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
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
    --font-h1: '${d.h1Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-h2: '${d.h2Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-h3: '${d.h3Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-h4: '${d.h4Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-heading: var(--font-h1);
    --font-body: '${d.bodyFont||'sans-serif'}', sans-serif;
    --font-btn: '${d.btnFont||d.bodyFont||'sans-serif'}', sans-serif;
    --font-field: '${d.fieldFont||d.bodyFont||'sans-serif'}', sans-serif;
    --btn-bg: ${d.btnBg || d.accentColor};
    --btn-color: ${d.btnTextColor || '#fff'};
    --btn-border-color: ${d.btnBorderColor || 'transparent'};
    --btn-border-style: ${d.btnBorderStyle || 'solid'};
    --btn-border-width: ${d.btnBorderWidth ?? 0}px;
  }
  body { font-family: var(--font-body); ${bgStyle} min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 20px; }
  .sf-card { background: #fff; border-radius: ${d.cardRadius || '12px'}; padding: ${d.cardPadding || '48px 40px'}; max-width: var(--container); width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.15); color: var(--text); }
  .sf-logo { text-align: center; margin-bottom: 24px; }
  .sf-logo img { width: ${d.logoWidth}; max-width: 100%; }
  .sf-hero-img { width: 100%; border-radius: 8px; margin-bottom: 28px; object-fit: cover; max-height: 280px; }
  .sf-hero-img.below { margin-top: 28px; margin-bottom: 0; }
  h1 { font-family: var(--font-h1); color: var(--primary); font-size: clamp(1.6rem, 4vw, 2.4rem); line-height: 1.2; margin-bottom: 12px; text-align: center; }
  h2 { font-family: var(--font-h2); color: var(--primary); font-size: clamp(1.2rem, 3vw, 1.7rem); line-height: 1.3; margin-bottom: 10px; }
  h3 { font-family: var(--font-h3); color: var(--primary); font-size: clamp(1rem, 2.5vw, 1.3rem); line-height: 1.35; margin-bottom: 8px; }
  h4 { font-family: var(--font-h4); color: var(--primary); font-size: 1.05rem; line-height: 1.4; margin-bottom: 6px; }
  .sf-sub { color: #666; font-size: 1.05rem; text-align: center; margin-bottom: 32px; line-height: 1.6; }
  .sf-field { margin-bottom: 16px; }
  .sf-field label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--sf-lbl, var(--primary)); margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
  .req { color: var(--accent); }
  .sf-field input, .sf-field select, .sf-field textarea { width: 100%; padding: 12px 16px; border: ${d.fieldBorderWidth||2}px ${d.fieldBorderStyle||'solid'} ${d.fieldBorderColor||'#e0e0e0'}; border-radius: ${d.fieldRadius || '6px'}; font-family: var(--sf-ff, var(--font-field)); font-size: var(--sf-fsz, 1rem); color: var(--sf-txt, var(--text)); transition: border-color 0.2s; background: var(--sf-fbg, ${d.fieldBg||'#fafafa'}); }
  .sf-field input:focus, .sf-field select:focus, .sf-field textarea:focus { outline: none; border-color: var(--accent); background: #fff; }
  .sf-field--check label { display: flex; align-items: flex-start; gap: 10px; font-size: 0.9rem; text-transform: none; letter-spacing: 0; }
  .sf-field--check input[type=checkbox] { width: auto; margin-top: 2px; accent-color: var(--accent); }
  .sf-btn { width: 100%; padding: 14px; background: var(--btn-bg); color: var(--btn-color); border: var(--btn-border-width) var(--btn-border-style) var(--btn-border-color); border-radius: var(--radius); font-family: var(--font-btn); font-size: 1.1rem; font-weight: 700; cursor: pointer; margin-top: 8px; letter-spacing: 0.03em; transition: opacity 0.2s, transform 0.1s; }
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
  <form id="sf-form" novalidate>
    <div id="sf-form-content">
      ${d.logoUrl ? `<div class="sf-logo"><img src="${d.logoUrl}" alt="Logo"></div>` : ''}
      ${cfg.sections.map(sec => renderSectionBlock(sec, cfg, formSection, formFields)).join('\n  ')}
    </div>
  </form>
  ${confirmationBlocks ? `<div id="sf-confirmation" style="display:none">${confirmationBlocks}</div>` : ''}
</div>

<!-- Cookie Banner -->
<div id="sf-cookie" style="display:none">
  <span>${escapeHtml(s.cookieBannerText)} <a href="${s.privacyPolicyUrl}">Learn more</a></span>
  <button id="sf-cookie-accept">Accept</button>
</div>

<script>
(function(){
  // Cookie banner — only on direct page loads (not in iframes/embeds)
  if(window.self === window.top && !localStorage.getItem('sf_cookie_ok')){
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
    const btn = form.querySelector('button[type=submit]');
    const msg = document.getElementById('sf-msg');
    if(btn){btn.disabled = true;btn.textContent = 'Submitting\u2026';}
    if(msg)msg.style.display = 'none';

    const data = new URLSearchParams(new FormData(form));
    try {
      const r = await fetch('/${cfg.slug}/subscribe', { method:'POST', body: data });
      const j = await r.json();
      if(j.success){
        const conf = document.getElementById('sf-confirmation');
        const fc = document.getElementById('sf-form-content');
        if(conf && conf.children.length > 0){
          if(fc) fc.style.display = 'none';
          conf.style.display = 'block';
        } else {
          if(msg){msg.className='sf-msg success'; msg.textContent=${JSON.stringify((formSection && formSection.submitSuccessMessage) || "Thank you! You're subscribed.")};msg.style.display='block';}
          if(btn){btn.textContent='\u2713 Subscribed';btn.style.opacity='0.7';}
          form.reset();
        }
      } else {
        if(msg){msg.className='sf-msg error'; msg.textContent=j.error||${JSON.stringify((formSection && formSection.submitErrorMessage) || 'Something went wrong. Please try again.')};msg.style.display='block';}
        if(btn){btn.disabled=false; btn.textContent=${JSON.stringify(d.buttonText||'Subscribe')};}
      }
    } catch(err){
      if(msg){msg.className='sf-msg error'; msg.textContent='Network error. Please try again.';msg.style.display='block';}
      if(btn){btn.disabled=false; btn.textContent=${JSON.stringify(d.buttonText||'Subscribe')};}
    }
  });
})();
${sliderPickerJS()}
</script>
</body>
</html>`;
}

function renderUnsubscribePage(cfg, message, success, isDelete = false, sharedFonts = []) {
  const d = cfg.design;
  const title = isDelete ? 'Delete My Data' : 'Unsubscribe';
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} · ${escapeHtml(cfg.site.title)}</title>
${googleFontTag(cfg, null, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
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

function renderPrefCenterBlock(block) {
  if (!block || !block.type) return '';
  switch (block.type) {
    case 'heading': {
      const tag = block.level || 'h2';
      const st = [
        block.color    ? `color:${block.color}` : '',
        block.align    ? `text-align:${block.align}` : '',
        block.fontSize ? `font-size:${block.fontSize}px` : '',
        block.fontFamily ? `font-family:'${block.fontFamily}',sans-serif` : ''
      ].filter(Boolean).join(';');
      return `<${tag} class="pc-heading" style="${st}">${escapeHtml(block.text||'')}</${tag}>`;
    }
    case 'paragraph': {
      const st = [
        block.color    ? `color:${block.color}` : '',
        block.align    ? `text-align:${block.align}` : '',
        block.fontSize ? `font-size:${block.fontSize}px` : ''
      ].filter(Boolean).join(';');
      return `<p class="pc-para" style="${st}">${escapeHtml(block.text||'')}</p>`;
    }
    case 'image': {
      if (!block.url) return '';
      const w = block.width ? `max-width:${block.width}px;` : 'max-width:100%;';
      const align = block.align === 'center' ? 'margin:0 auto;display:block;' : block.align === 'right' ? 'margin-left:auto;display:block;' : '';
      return `<div class="pc-image-wrap" style="margin:12px 0"><img src="${block.url}" alt="${escapeHtml(block.alt||'')}" style="${w}${align}width:100%;border-radius:${block.radius||0}px"></div>`;
    }
    case 'spacer':
      return `<div style="height:${block.height||20}px"></div>`;
    case 'divider': {
      const col = block.color || '#e0e0e0';
      const th = block.thickness || 1;
      return `<hr style="border:none;border-top:${th}px solid ${col};margin:${block.margin||16}px 0">`;
    }
    case 'wysiwyg':
      return `<div class="pc-wysiwyg">${sanitizeWysiwyg(block.html)}</div>`;
    case 'button': {
      const bg  = block.bgColor  || '#333333';
      const tc  = block.textColor|| '#ffffff';
      const r   = block.radius   || 6;
      const url = block.url      || '#';
      return `<div style="text-align:${block.align||'left'};margin:10px 0"><a href="${url}" style="display:inline-block;background:${bg};color:${tc};padding:11px 22px;border-radius:${r}px;text-decoration:none;font-size:0.9rem;font-weight:500">${escapeHtml(block.label||'Click here')}</a></div>`;
    }
    default: return '';
  }
}

function renderPreferencePage(cfg, { token, email, found, message, success, allSubs } = {}, sharedFonts = []) {
  const d  = cfg.design || {};
  const s  = cfg.site   || {};
  const pc = cfg.preferenceCenter || {};

  // Design values — pc overrides, then fall back to form design
  const bgColor    = pc.bgColor    || d.backgroundColor || '#f8f5f0';
  const bgImage    = pc.bgImage    || '';
  const bgOverlay  = pc.bgOverlay  != null ? pc.bgOverlay  : 0.4;
  const bgOvCol    = pc.bgOverlayColor || '#000000';
  const cardBg     = pc.cardBg     || '#ffffff';
  const cardRadius = pc.cardRadius || '12px';
  const cardMaxW   = pc.cardMaxWidth || '480px';
  const cardPad    = pc.cardPadding  || '40px';
  const logoUrl    = pc.logoUrl    || d.logoUrl    || '';
  const logoWidth  = pc.logoWidth  || d.logoWidth  || '160px';
  const accent     = pc.accentColor  || d.accentColor  || '#e94560';
  const primary    = pc.primaryColor || d.primaryColor || '#1a1a2e';
  const textCol    = pc.textColor    || d.textColor    || '#333333';
  const hFont      = pc.headingFont  || d.googleFont   || 'serif';
  const bFont      = pc.bodyFont     || d.bodyFont     || 'sans-serif';
  const heading    = pc.pageHeading  || 'Email Preferences';
  const subText    = pc.subText      || s.unsubscribePageText || 'Manage your subscription preferences below.';

  // Background CSS
  let bodyBg = bgColor;
  let bodyBgExtra = '';
  if (bgImage) {
    bodyBgExtra = `background-image:url('${bgImage}');background-size:cover;background-position:center;`;
    if (bgOverlay > 0) {
      bodyBgExtra += `position:relative;`;
    }
  }

  // Subscription list — allSubs must be pre-fetched by the async caller (never call async here)
  const subs = Array.isArray(allSubs) ? allSubs : [];
  const foundFormName = found ? (subs.find(x => x.slug === found.slug) || {}).formName || found.slug : '';
  const subsListHtml = subs.length ? subs.map(({ formName, sub }) => `
    <div class="sub-item">
      <span class="sub-name">${escapeHtml(formName)}</span>
      <span class="badge ${escapeHtml(sub.status)}">${escapeHtml(sub.status)}</span>
    </div>`).join('') : '';

  const formHidden = token && email ? `<input type="hidden" name="token" value="${escapeHtml(token)}"><input type="hidden" name="email" value="${escapeHtml(email)}">` : '';
  const actionsHtml = found && !success ? `
    <form method="POST" action="/preferences" class="pref-actions">
      ${formHidden}
      <button type="submit" name="action" value="unsub-one" class="btn-pref btn-secondary">
        Unsubscribe from <em>${escapeHtml(foundFormName)}</em>
      </button>
      <button type="submit" name="action" value="unsub-all" class="btn-pref btn-secondary">
        Unsubscribe from all mailings
      </button>
      <button type="submit" name="action" value="delete-all" class="btn-pref btn-danger"
        onclick="return confirm('Permanently delete all your data? This cannot be undone.')">
        Delete all my data
      </button>
    </form>` : '';

  // Custom content sections (rendered above actions)
  const sectionsHtml = (pc.sections || []).map(b => renderPrefCenterBlock(b)).join('');
  // Custom content sections (rendered below actions)
  const afterSectionsHtml = (pc.afterSections || []).map(b => renderPrefCenterBlock(b)).join('');

  const overlayDiv = (bgImage && bgOverlay > 0)
    ? `<div style="position:fixed;inset:0;background:${bgOvCol};opacity:${bgOverlay};pointer-events:none;z-index:0"></div>` : '';

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(heading)} · ${escapeHtml(s.title||'SignFlow')}</title>
${googleFontTag(cfg, null, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
<style>
  *,*::before,*::after{box-sizing:border-box}
  body{font-family:'${bFont}',sans-serif;background:${bodyBg};${bodyBgExtra}min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px;color:${textCol}}
  .pc-wrap{position:relative;z-index:1;width:100%;display:flex;align-items:center;justify-content:center}
  .card{background:${cardBg};border-radius:${cardRadius};padding:${cardPad};max-width:${cardMaxW};width:100%;box-shadow:0 10px 40px rgba(0,0,0,.12)}
  .pc-logo{text-align:center;margin-bottom:20px}.pc-logo img{max-height:70px;max-width:${logoWidth};width:auto}
  h1.pc-title{font-family:'${hFont}',serif;color:${primary};margin:0 0 8px;font-size:1.6rem;font-weight:600}
  .pc-subtext{color:${textCol};opacity:.75;line-height:1.6;margin-bottom:20px}
  .pc-heading{font-family:'${hFont}',serif;color:${primary};margin:14px 0 8px}
  .pc-para{line-height:1.65;margin-bottom:12px}
  .pc-wysiwyg{line-height:1.65}
  .sub-list{margin-bottom:24px;border:1px solid #eee;border-radius:8px;overflow:hidden}
  .sub-item{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid #f0f0f0;font-size:0.9rem}
  .sub-item:last-child{border-bottom:none}
  .sub-name{font-weight:500}
  .badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:0.7rem;font-weight:600;letter-spacing:.03em}
  .badge.active{background:#d4edda;color:#155724}
  .badge.unsubscribed{background:#f0f0f0;color:#888}
  .pref-actions{display:flex;flex-direction:column;gap:10px}
  .btn-pref{padding:12px 20px;border-radius:6px;border:none;font-size:0.9rem;cursor:pointer;text-align:left;transition:opacity .2s;font-family:'${bFont}',sans-serif}
  .btn-pref:hover{opacity:.85}
  .btn-secondary{background:#f4f4f4;color:#333}
  .btn-danger{background:#fff0f0;color:#c0392b;border:1px solid #f5c6cb}
  .btn-pref em{font-style:normal;font-weight:600}
  .msg-success{color:#155724;background:#d4edda;padding:14px;border-radius:6px;margin-bottom:20px}
  .msg-error{color:#721c24;background:#f8d7da;padding:14px;border-radius:6px;margin-bottom:20px}
  .back{display:inline-block;margin-top:24px;font-size:0.85rem;color:${accent};text-decoration:none}
</style></head><body>
${overlayDiv}
<div class="pc-wrap"><div class="card">
  ${logoUrl ? `<div class="pc-logo"><img src="${logoUrl}" alt="${s.title||''}"></div>` : ''}
  ${!pc.hideHeading ? `<h1 class="pc-title">${escapeHtml(heading)}</h1><p class="pc-subtext">${escapeHtml(subText)}</p>` : ''}
  ${message ? `<p class="${success ? 'msg-success' : 'msg-error'}">${escapeHtml(message)}</p>` : ''}
  ${email ? `<p style="font-size:0.85rem;opacity:.6;margin-bottom:16px">Managing preferences for: <strong>${escapeHtml(email)}</strong></p>` : ''}
  ${sectionsHtml}
  ${subsListHtml ? `<div class="sub-list">${subsListHtml}</div>` : ''}
  ${actionsHtml}
  ${afterSectionsHtml}
  <a href="/" class="back">← Back to home</a>
</div></div></body></html>`;
}

function renderPrivacyPage(cfg, sharedFonts = []) {
  const d = cfg.design;
  const s = cfg.site;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy · ${escapeHtml(s.title)}</title>
${googleFontTag(cfg, null, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
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
  ${s.privacyContent ? sanitizeWysiwyg(s.privacyContent) : `
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
  <p style="margin-top:32px"><a href="/">← Back</a></p>`}
</div></body></html>`;
}

function renderEmbedPage(cfg, sharedFonts = [], templates = []) {
  let d = cfg.design || {};
  if (cfg.designTemplateId) {
    const tpl = templates.find(t => t.id === cfg.designTemplateId);
    if (tpl && tpl.design) d = { ...tpl.design, customFonts: (cfg.design || {}).customFonts };
  }
  const s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');

  const formFields = cfg.fields.map(f => renderFormField(f, cfg)).join('');
  const confirmationBlocks = (cfg.confirmation || []).map(sec => renderSectionBlock(sec, cfg, null, '')).join('\n  ');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${s.title}</title>
${googleFontTag(cfg, d, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
${s.captchaEnabled && s.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --primary: ${d.primaryColor};
    --accent: ${d.accentColor};
    --text: ${d.textColor};
    --radius: ${d.buttonRadius};
    --font-h1: '${d.h1Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-h2: '${d.h2Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-h3: '${d.h3Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-h4: '${d.h4Font||d.googleFont||d.bodyFont||'serif'}', serif;
    --font-heading: var(--font-h1);
    --font-body: '${d.bodyFont||'sans-serif'}', sans-serif;
    --font-btn: '${d.btnFont||d.bodyFont||'sans-serif'}', sans-serif;
    --font-field: '${d.fieldFont||d.bodyFont||'sans-serif'}', sans-serif;
    --btn-bg: ${d.btnBg || d.accentColor};
    --btn-color: ${d.btnTextColor || '#fff'};
    --btn-border-color: ${d.btnBorderColor || 'transparent'};
    --btn-border-style: ${d.btnBorderStyle || 'solid'};
    --btn-border-width: ${d.btnBorderWidth ?? 0}px;
  }
  html, body { background: transparent; }
  body { font-family: var(--font-body); color: var(--text); padding: 4px 2px 16px; }
  .sf-logo { text-align: center; margin-bottom: 20px; }
  .sf-logo img { width: ${d.logoWidth}; max-width: 100%; }
  .sf-hero-img { width: 100%; border-radius: 8px; margin-bottom: 20px; object-fit: cover; max-height: 200px; }
  .sf-hero-img.below { margin-top: 20px; margin-bottom: 0; }
  h1 { font-family: var(--font-h1); color: var(--primary); font-size: clamp(1.3rem, 4vw, 1.9rem); line-height: 1.2; margin-bottom: 10px; text-align: center; }
  h2 { font-family: var(--font-h2); color: var(--primary); font-size: clamp(1.1rem, 3vw, 1.5rem); line-height: 1.3; margin-bottom: 8px; }
  h3 { font-family: var(--font-h3); color: var(--primary); font-size: clamp(0.95rem, 2.5vw, 1.2rem); line-height: 1.35; margin-bottom: 6px; }
  .sf-sub { color: #666; font-size: 0.97rem; text-align: center; margin-bottom: 22px; line-height: 1.6; }
  .sf-field { margin-bottom: 14px; }
  .sf-field label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--sf-lbl, var(--primary)); margin-bottom: 5px; letter-spacing: 0.04em; text-transform: uppercase; }
  .req { color: var(--accent); }
  .sf-field input, .sf-field select, .sf-field textarea { width: 100%; padding: 10px 14px; border: ${d.fieldBorderWidth||2}px ${d.fieldBorderStyle||'solid'} ${d.fieldBorderColor||'#e0e0e0'}; border-radius: ${d.fieldRadius || '6px'}; font-family: var(--sf-ff, var(--font-field)); font-size: var(--sf-fsz, 0.97rem); color: var(--sf-txt, var(--text)); transition: border-color 0.2s; background: var(--sf-fbg, ${d.fieldBg||'#fafafa'}); }
  .sf-field input:focus, .sf-field select:focus, .sf-field textarea:focus { outline: none; border-color: var(--accent); background: #fff; }
  .sf-field--check label { display: flex; align-items: flex-start; gap: 10px; font-size: 0.88rem; text-transform: none; letter-spacing: 0; }
  .sf-field--check input[type=checkbox] { width: auto; margin-top: 2px; accent-color: var(--accent); }
  .sf-btn { width: 100%; padding: 12px; background: var(--btn-bg); color: var(--btn-color); border: var(--btn-border-width) var(--btn-border-style) var(--btn-border-color); border-radius: var(--radius); font-family: var(--font-btn); font-size: 1rem; font-weight: 700; cursor: pointer; margin-top: 6px; letter-spacing: 0.03em; transition: opacity 0.2s, transform 0.1s; }
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
  <form id="sf-form" novalidate>
    <div id="sf-form-content">
      ${d.logoUrl ? `<div class="sf-logo"><img src="${d.logoUrl}" alt="Logo"></div>` : ''}
      ${cfg.sections.map(sec => renderSectionBlock(sec, cfg, formSection, formFields)).join('\n  ')}
    </div>
  </form>
  ${confirmationBlocks ? `<div id="sf-confirmation" style="display:none">${confirmationBlocks}</div>` : ''}

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
    const btn = form.querySelector('button[type=submit]');
    const msg = document.getElementById('sf-msg');
    if(btn){btn.disabled = true;btn.textContent = 'Submitting\u2026';}
    if(msg)msg.style.display = 'none';
    const data = new URLSearchParams(new FormData(form));
    try {
      const r = await fetch('/${cfg.slug}/subscribe', { method:'POST', body: data });
      const j = await r.json();
      if(j.success){
        const conf = document.getElementById('sf-confirmation');
        const fc = document.getElementById('sf-form-content');
        if(conf && conf.children.length > 0){
          if(fc) fc.style.display = 'none';
          conf.style.display = 'block';
          window.parent.postMessage({ type: 'sf-success' }, '*');
          reportHeight();
        } else {
          if(msg){msg.className='sf-msg success'; msg.textContent=${JSON.stringify((formSection && formSection.submitSuccessMessage) || "Thank you! You're subscribed.")};msg.style.display='block';}
          form.reset();
          window.parent.postMessage({ type: 'sf-success' }, '*');
          reportHeight();
        }
      } else {
        if(msg){msg.className='sf-msg error'; msg.textContent=j.error||${JSON.stringify((formSection && formSection.submitErrorMessage) || 'Something went wrong. Please try again.')};msg.style.display='block';}
        if(btn){btn.disabled=false; btn.textContent=${JSON.stringify(d.buttonText||'Subscribe')};}
        reportHeight();
      }
    } catch(err){
      if(msg){msg.className='sf-msg error'; msg.textContent='Network error. Please try again.';msg.style.display='block';}
      if(btn){btn.disabled=false; btn.textContent=${JSON.stringify(d.buttonText||'Subscribe')};}
      reportHeight();
    }
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
    iframe.src = ORIGIN + '/' + cfg.slug + '/embed';
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

// ── Global error safety (prevent unhandled rejections from crashing the process) ──
process.on('unhandledRejection', (reason) => {
  console.error('⚠ Unhandled promise rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('⚠ Uncaught exception:', err);
});

// ── Start ──
(async () => {
  await initDb();
  await initAuth0();
  app.listen(PORT, () => {
    console.log(`\n✅ SignFlow running at http://localhost:${PORT}`);
    console.log(`   Admin panel : http://localhost:${PORT}/admin`);
    console.log(`   Auth login  : http://localhost:${PORT}/auth/login`);
    console.log(`   Auth0 domain: ${AUTH0_DOMAIN || '(not configured)'}\n`);
  });
})();
