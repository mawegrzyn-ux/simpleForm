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
const { S3Client, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const multerS3   = require('multer-s3');
const Anthropic  = require('@anthropic-ai/sdk');

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

// ── Anthropic AI ───────────────────────────────────────────────────────────────
const _anthropic = process.env.ANTHROPIC_API_KEY
  ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY })
  : null;

// Extract plain-text help content from admin/index.html at startup (cached in memory).
// Phase 2: replace with pgvector semantic search (search_docs tool).
let _helpContext = '';
function _loadHelpContext() {
  try {
    const html = fs.readFileSync(path.join(__dirname, 'admin', 'index.html'), 'utf8');
    const stripTags = s => s
      .replace(/<pre[^>]*>[\s\S]*?<\/pre>/g, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ')
      .replace(/[ \t]{2,}/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
    const chunks = [];
    const re = /data-tags="([^"]+)"[\s\S]*?<div class="help-group-head"[^>]*>([\s\S]*?)<\/div>\s*<div class="help-group-body">([\s\S]*?)<\/div>\s*<\/div>/g;
    let m;
    while ((m = re.exec(html)) !== null) {
      const heading = stripTags(m[2]).replace(/expand_more/g, '').trim();
      const body = stripTags(m[3]);
      if (body.length > 40) chunks.push(`## ${heading}\n${body}`);
    }
    _helpContext = chunks.join('\n\n').substring(0, 80000);
    console.log(`[AI] Help context: ${_helpContext.length} chars, ${chunks.length} sections`);
  } catch(e) {
    console.warn('[AI] Could not load help context:', e.message);
  }
}
_loadHelpContext();

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

// ── Phone number validation ───────────────────────────────────────────────────
// ISO 3166-1 alpha-2 → E.164 calling code (most common countries)
const PHONE_COUNTRY_CODES = {
  AF:'+93',AL:'+355',DZ:'+213',AR:'+54',AM:'+374',AU:'+61',AT:'+43',AZ:'+994',
  BH:'+973',BD:'+880',BE:'+32',BR:'+55',BG:'+359',CA:'+1', CL:'+56',CN:'+86',
  CO:'+57',HR:'+385',CY:'+357',CZ:'+420',DK:'+45',EG:'+20',EE:'+372',FI:'+358',
  FR:'+33',GE:'+995',DE:'+49',GH:'+233',GR:'+30',HK:'+852',HU:'+36',IN:'+91',
  ID:'+62',IE:'+353',IL:'+972',IT:'+39',JP:'+81',JO:'+962',KE:'+254',KW:'+965',
  KZ:'+7', LV:'+371',LT:'+370',LU:'+352',MY:'+60',MX:'+52',MA:'+212',NL:'+31',
  NZ:'+64',NG:'+234',NO:'+47',PK:'+92',PH:'+63',PL:'+48',PT:'+351',QA:'+974',
  RO:'+40',RU:'+7', SA:'+966',SG:'+65',SK:'+421',ZA:'+27',KR:'+82',ES:'+34',
  LK:'+94',SE:'+46',CH:'+41',TW:'+886',TH:'+66',TR:'+90',UA:'+380',AE:'+971',
  GB:'+44',US:'+1', UY:'+598',VN:'+84'
};
/**
 * Validates a phone number string.
 * Strips spaces, dashes, parentheses, dots then checks E.164-ish format (7-15 digits, optional +).
 * If allowedCountries is non-empty, the number must begin with one of those calling codes.
 * Returns { ok: true } or { ok: false, msg: '...' }.
 */
function validatePhoneNumber(raw, allowedCountries) {
  if (!raw || !raw.trim()) return { ok: true }; // empty → handled by Joi required/optional
  const normalized = raw.trim().replace(/[\s\-\(\)\.]/g, '');
  if (!/^\+?\d{7,15}$/.test(normalized)) {
    return { ok: false, msg: 'Please enter a valid phone number (e.g. +44 7700 900000)' };
  }
  if (allowedCountries && allowedCountries.length > 0) {
    // Require the number to start with + and a recognised calling code
    const withPlus = normalized.startsWith('+') ? normalized : null;
    const matched  = withPlus && allowedCountries.some(code => {
      const prefix = PHONE_COUNTRY_CODES[code];
      return prefix && withPlus.startsWith(prefix);
    });
    if (!matched) {
      return { ok: false, msg: `Phone number must include a country dialling code for: ${allowedCountries.join(', ')}` };
    }
  }
  return { ok: true };
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
  // Add all custom field values as {{fieldId}} tags
  if (subscriber.customFields) {
    Object.entries(subscriber.customFields).forEach(([k, v]) => {
      map[`{{${k}}}`] = v != null ? String(v) : '';
    });
  }
  // Strip editor merge-tag spans (keep inner text which is the {{tag}}) then replace
  let out = text.replace(/<span[^>]*class="etpl-merge"[^>]*>([\s\S]*?)<\/span>/g, '$1');
  return out.replace(/\{\{[a-zA-Z0-9_]+\}\}/g, t => (map[t] !== undefined ? map[t] : t));
}

async function sendWelcomeEmail(cfg, subscriber, logId = null) {
  const mailer = getMailer();
  if (!mailer) return; // SMTP not configured — skip silently
  const s = cfg.site;
  if (!s.emailEnabled) return;
  logId = logId || uuidv4(); // pre-generate for tracking
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
  const rawBodyHtml = replaceMergeTags(rawBody,    cfg, subscriber, prefUrl);
  const bodyHtml   = rewriteEmailLinks(rawBodyHtml, cfg.slug, logId);
  // Prize draw — append a prize section if this subscriber won something
  let prizeSection = '';
  const pdField = (cfg.fields || []).find(f => f.type === 'prizedraw');
  if (pdField) {
    const rawPrize = (subscriber.customFields || {})[pdField.id];
    let prize = null;
    try { prize = typeof rawPrize === 'string' ? JSON.parse(rawPrize) : rawPrize; } catch(e) {}
    if (prize && prize.label) {
      const prizeUrl = `${ORIGIN}/${cfg.slug}/prize/${subscriber.unsubscribeToken}`;
      const prizeImg = prize.icon ? `<img src="${escapeHtml(prize.icon)}" width="80" height="80" style="border-radius:50%;object-fit:cover;display:block;margin:0 auto 12px" alt="${escapeHtml(prize.label)}">` : '';
      prizeSection = `
<table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0"><tr><td align="center" style="background:#fffbea;border-radius:8px;padding:24px;border:2px solid #f59e0b">
  <p style="margin:0 0 4px;font-size:1.4rem">🎉</p>
  ${prizeImg}
  <p style="margin:0 0 4px;font-size:0.85rem;color:#92400e;font-weight:600;letter-spacing:0.05em;text-transform:uppercase">You won a prize!</p>
  <p style="margin:0 0 16px;font-size:1.3rem;font-weight:700;color:#78350f">${escapeHtml(prize.label)}</p>
  <a href="${prizeUrl}" style="display:inline-block;background:#f59e0b;color:#fff;text-decoration:none;padding:10px 24px;border-radius:6px;font-weight:600;font-size:0.9rem">View your prize →</a>
</td></tr></table>`;
    }
  }
  // Auto-append unsubscribe footer only if {{unsubscribeUrl}} not already used in body
  const prefLink = s.emailPrefLink || {};
  const prefLinkLabel = prefLink.label || "Don't want these emails?";
  const prefLinkText  = prefLink.linkText || 'Manage preferences';
  const footer = (prefLink.hide || rawBody.includes('{{unsubscribeUrl}}')) ? '' :
    `<p style="margin-top:32px;font-size:0.8rem;color:#aaa;border-top:1px solid #eee;padding-top:16px">${escapeHtml(prefLinkLabel)} <a href="${prefUrl}" style="color:#aaa">${escapeHtml(prefLinkText)}</a></p>`;
  const trackingPixel = `<img src="${ORIGIN}/${cfg.slug}/track/o/${logId}" width="1" height="1" alt="" style="display:none;width:1px;height:1px">`;
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=${encodeURIComponent(bodyFont)}:wght@400;600&display=swap" rel="stylesheet">
</head><body style="margin:0;padding:0;background:${bgColor}">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 16px">
<table width="${maxWidth}" cellpadding="0" cellspacing="0" style="max-width:${maxWidth}">
<tr><td style="background:${cardBg};border-radius:${radius};padding:${padding};color:${textColor};font-family:'${bodyFont}',Helvetica,Arial,sans-serif;font-size:${bodyFontSize};line-height:1.6">
${bodyHtml}
${prizeSection}
${footer}
${trackingPixel}
</td></tr></table></td></tr></table>
</body></html>`;
  let sendError = null;
  try {
    await mailer.sendMail({
      from: `"${fromName}" <${SMTP_FROM}>`,
      to: subscriber.email,
      ...(s.emailReplyTo ? { replyTo: s.emailReplyTo } : {}),
      subject,
      html
    });
  } catch(e) {
    sendError = e.message;
    console.error('[email]', e.message);
  }
  // Log every attempt to email_log (best-effort — never blocks the response)
  try {
    await pool.query(
      `INSERT INTO email_log (id, form_slug, subscriber_id, email, subject, status, error)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (id) DO NOTHING`,
      [logId, cfg.slug, subscriber.id || null, subscriber.email, subject,
       sendError ? 'failed' : 'sent', sendError || null]
    );
  } catch(dbErr) {
    console.error('[email-log]', dbErr.message);
  }
}

// ── Email link rewriter (for click tracking) ──────────────────────────────────
function rewriteEmailLinks(html, slug, logId) {
  return html.replace(/href="(https?:\/\/[^"]+)"/g, (match, url) => {
    if (url.includes('/track/') || url.includes('/unsubscribe') || url.includes('/preferences') || url.includes('/confirm/')) return match;
    return `href="${ORIGIN}/${slug}/track/c/${logId}?u=${encodeURIComponent(url)}"`;
  });
}

// ── Double opt-in confirmation email ─────────────────────────────────────────
async function sendConfirmationEmail(cfg, subscriber) {
  const mailer = getMailer();
  if (!mailer) return;
  const s = cfg.site;
  if (!s.emailEnabled) return;
  const confirmUrl = `${ORIGIN}/${cfg.slug}/confirm/${subscriber.unsubscribeToken}`;
  const fromName = s.emailFromName || s.title || 'SignFlow';
  const ed = s.emailDesign || {};
  const bgColor  = ed.bgColor  || '#f4f4f4';
  const cardBg   = ed.cardBg   || '#ffffff';
  const textColor = ed.textColor || '#333333';
  const bodyFont  = ed.bodyFont  || s.bodyFont || 'Lato';
  const maxWidth  = ed.maxWidth  || '600px';
  const padding   = ed.padding   || '40px';
  const radius    = ed.borderRadius || '8px';
  const accentColor = cfg.design?.accentColor || '#e94560';
  const subject = s.confirmEmailSubject || `Please confirm your subscription to ${s.title || cfg.name}`;
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=${encodeURIComponent(bodyFont)}:wght@400;600&display=swap" rel="stylesheet">
</head><body style="margin:0;padding:0;background:${bgColor}">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 16px">
<table width="${maxWidth}" cellpadding="0" cellspacing="0" style="max-width:${maxWidth}">
<tr><td style="background:${cardBg};border-radius:${radius};padding:${padding};color:${textColor};font-family:'${bodyFont}',Helvetica,Arial,sans-serif;font-size:16px;line-height:1.6;text-align:center">
<p style="margin:0 0 16px;font-size:1.3rem;font-weight:600;color:${textColor}">Confirm your subscription</p>
<p style="margin:0 0 24px">Click the button below to confirm your subscription to <strong>${escapeHtml(s.title || cfg.name)}</strong>.</p>
<a href="${confirmUrl}" style="display:inline-block;background:${accentColor};color:#fff;text-decoration:none;padding:12px 32px;border-radius:6px;font-weight:600;font-size:0.95rem">Confirm subscription</a>
<p style="margin:24px 0 0;font-size:0.8rem;color:#aaa">If you didn't request this, you can safely ignore this email.</p>
</td></tr></table></td></tr></table>
</body></html>`;
  let sendError = null;
  try {
    await mailer.sendMail({
      from: `"${fromName}" <${SMTP_FROM}>`,
      to: subscriber.email,
      ...(s.emailReplyTo ? { replyTo: s.emailReplyTo } : {}),
      subject, html
    });
  } catch(e) {
    sendError = e.message;
    console.error('[email-confirm]', e.message);
  }
  try {
    await pool.query(
      `INSERT INTO email_log (form_slug, subscriber_id, email, subject, status, error)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [cfg.slug, subscriber.id || null, subscriber.email, subject,
       sendError ? 'failed' : 'sent', sendError || null]
    );
  } catch(dbErr) {
    console.error('[email-log]', dbErr.message);
  }
}

// ── Admin audit log ───────────────────────────────────────────────────────────
async function logAudit(req, action, targetType, targetId, detail = {}) {
  try {
    const userEmail = req.session?.user?.email || req.session?.user?.sub || null;
    await pool.query(
      `INSERT INTO audit_log (user_email, action, target_type, target_id, detail)
       VALUES ($1, $2, $3, $4, $5)`,
      [userEmail, action, targetType || null, targetId || null, detail]
    );
  } catch(e) {
    console.error('[audit]', e.message);
  }
}

// ── RBAC helpers ──────────────────────────────────────────────────────────────

function isSuperAdmin(req) {
  return req.session?.user?.systemRole === 'super-admin';
}

function requireSuperAdmin(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Super-admin required' });
  next();
}

// Returns array of market UUIDs the user belongs to, or null (= all) for super-admin
function getUserMarketIds(req) {
  if (isSuperAdmin(req)) return null;
  return (req.session.user?.markets || []).map(m => m.market_id);
}

// Returns highest role across markets shared between user and form.
// Returns 'admin' for super-admin; null if user has no shared market with the form.
function userEffectiveRole(req, formMarketIds) {
  if (isSuperAdmin(req)) return 'admin';
  const RANK = { viewer: 1, editor: 2, admin: 3 };
  let best = null;
  for (const um of (req.session.user?.markets || [])) {
    if (formMarketIds.includes(um.market_id)) {
      if (!best || RANK[um.role] > RANK[best]) best = um.role;
    }
  }
  return best;
}

async function getFormMarketIds(slug) {
  const { rows } = await pool.query(
    'SELECT market_id FROM form_markets WHERE form_slug=$1', [slug]);
  return rows.map(r => r.market_id);
}

// Unassigned forms (no markets) are visible to all authenticated admin users.
async function canUserAccessForm(req, slug) {
  if (isSuperAdmin(req)) return true;
  const fmIds = await getFormMarketIds(slug);
  if (fmIds.length === 0) return true;
  const userMktIds = getUserMarketIds(req);
  return fmIds.some(id => userMktIds.includes(id));
}

// Allows market-level admins read-only access to platform settings
function requireAdminOrSuperAdmin(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: 'Unauthorized' });
  if (isSuperAdmin(req)) return next();
  const hasAdminRole = (req.session.user.markets || []).some(m => m.role === 'admin');
  if (!hasAdminRole) return res.status(403).json({ error: 'Forbidden' });
  next();
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
      scriptSrc:      ["'self'", "'unsafe-inline'", 'https://js.hcaptcha.com', 'https://www.googletagmanager.com', 'https://connect.facebook.net', 'https://cdnjs.cloudflare.com'],
      scriptSrcAttr:  ["'unsafe-inline'"],  // allow onclick/onchange handlers in admin SPA & public pages
      styleSrc:       ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:        ["'self'", 'https://fonts.gstatic.com', 'https://*.amazonaws.com'],
      imgSrc:         ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc:     ["'self'", 'https://api.hcaptcha.com', 'https://www.google-analytics.com', 'https://region1.google-analytics.com', 'https://www.facebook.com'],
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
  limits: { fileSize: 25 * 1024 * 1024 },
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

// ── IP Flagging ───────────────────────────────────────────────────────────────
const crypto = require('crypto');

function hashIp(ip) {
  return crypto.createHmac('sha256', SESSION_SECRET + 'sf-ip-salt')
    .update(ip || 'unknown').digest('hex').slice(0, 40);
}
function _ipFlagLevel(strikes) {
  if (strikes >= 6) return 3;
  if (strikes >= 3) return 2;
  return 1;
}
function _ipFlagExpiry(level) {
  const ms = { 1: 3_600_000, 2: 86_400_000, 3: 604_800_000 }[level] || 3_600_000;
  return new Date(Date.now() + ms);
}
async function getIpFlagLevel(ipHash) {
  try {
    const { rows } = await pool.query(
      'SELECT level FROM ip_flags WHERE ip_hash=$1 AND expires_at > NOW()', [ipHash]);
    return rows[0]?.level || 0;
  } catch(e) { return 0; }
}
async function flagIp(ipHash, reason) {
  try {
    const { rows } = await pool.query(
      'SELECT strike_count FROM ip_flags WHERE ip_hash=$1', [ipHash]);
    const strikes = (rows[0]?.strike_count || 0) + 1;
    const level   = _ipFlagLevel(strikes);
    const expires = _ipFlagExpiry(level);
    await pool.query(`
      INSERT INTO ip_flags (ip_hash, level, strike_count, reason, last_seen, expires_at)
      VALUES ($1,$2,$3,$4,NOW(),$5)
      ON CONFLICT (ip_hash) DO UPDATE SET
        level=EXCLUDED.level, strike_count=EXCLUDED.strike_count,
        reason=EXCLUDED.reason, last_seen=NOW(), expires_at=EXCLUDED.expires_at
    `, [ipHash, level, strikes, reason, expires]);
    return level;
  } catch(e) { return 0; }
}
// Math challenge: server signs (answer + 10-min window) so no state needed
function genChallenge() {
  const a   = Math.floor(Math.random() * 20) + 5;
  const b   = Math.floor(Math.random() * 20) + 5;
  const op  = Math.random() < 0.5 ? '+' : '-';
  const ans = op === '+' ? a + b : a - b;
  const win = Math.floor(Date.now() / 600_000);
  const tok = crypto.createHmac('sha256', SESSION_SECRET + 'sf-chal')
    .update(`${ans}:${win}`).digest('hex').slice(0, 16);
  return { question: `What is ${a} ${op} ${b}?`, token: tok };
}
function verifyChallenge(token, answer) {
  if (!token || answer == null || isNaN(answer)) return false;
  const win = Math.floor(Date.now() / 600_000);
  for (const w of [win, win - 1]) {  // allow up to 20 min (prev window)
    const exp = crypto.createHmac('sha256', SESSION_SECRET + 'sf-chal')
      .update(`${answer}:${w}`).digest('hex').slice(0, 16);
    if (token === exp) return true;
  }
  return false;
}
// Timing token: server signs timestamp; verified on submit
function genTimingToken() {
  const ts  = Date.now().toString();
  const sig = crypto.createHmac('sha256', SESSION_SECRET + 'sf-timing')
    .update(ts).digest('hex').slice(0, 16);
  return `${ts}.${sig}`;
}
function verifyTimingToken(val) {
  if (!val) return { ok: false, reason: 'missing' };
  const [ts, sig] = val.split('.');
  if (!ts || !sig) return { ok: false, reason: 'malformed' };
  const exp = crypto.createHmac('sha256', SESSION_SECRET + 'sf-timing')
    .update(ts).digest('hex').slice(0, 16);
  if (sig !== exp) return { ok: false, reason: 'bad_sig' };
  const age = Date.now() - parseInt(ts);
  if (age < 2500)     return { ok: false, reason: 'too_fast' };
  if (age > 3_600_000) return { ok: false, reason: 'expired' };
  return { ok: true };
}

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
    exportedAt: r.exported_at ? r.exported_at.toISOString() : null,
    emailStatus:  r.email_status  || null,   // 'sent' | 'failed' | null (never attempted)
    emailError:   r.email_error   || null,
    emailLogId:   r.email_log_id  || null,
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
  const { rows } = await pool.query('SELECT slug, name, created_at, status, testing_pin FROM forms ORDER BY created_at ASC');
  return rows.map(r => ({
    slug: r.slug, name: r.name,
    createdAt: r.created_at ? r.created_at.toISOString() : null,
    status: r.status || 'draft',
    testingPin: r.testing_pin || null,
  }));
}

async function readFormConfig(slug) {
  const { rows } = await pool.query('SELECT config FROM forms WHERE slug=$1', [slug]);
  if (!rows.length) throw new Error(`Form not found: ${slug}`);
  return rows[0].config;
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
    site: { title: name, description: '', favicon: '', adminPassword: '',
            cookieBannerText: 'We use <strong>necessary cookies</strong> to keep this site running. With your consent, analytics and marketing cookies help us improve our service.',
            privacyPolicyUrl: '/privacy',
            gdprText: 'By subscribing you agree to our <a href="{privacyUrl}" target="_blank">Privacy Policy</a>. We store your data securely and you can unsubscribe or request deletion at any time.',
            unsubscribeEnabled: true,
            emailEnabled: false, emailFromName: '', emailReplyTo: '', emailSubject: '', emailBodyHtml: '',
            emailDesign: { bgColor: '#f4f4f4', cardBg: '#ffffff', textColor: '#333333', headingColor: '#1a1a2e',
              bodyFont: 'Lato', headingFont: 'Playfair Display', maxWidth: '600px', padding: '40px', borderRadius: '8px' },
            unsubscribePageText: 'Manage your subscription preferences below.',
            embedAllowedDomains: [],
            allowDuplicateEmail: false,
            uniqueKeyFields: ['email'] },
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
    -- One-time migration: downgrade unique index to plain index so allowDup forms
    -- can store multiple rows per email (different key-field combos).
    -- Uniqueness for allowDup=false is enforced at the application layer.
    DO $mig$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_sub_form_email' AND indexdef ILIKE '%unique%'
      ) THEN
        DROP INDEX idx_sub_form_email;
        CREATE INDEX idx_sub_form_email ON subscribers(form_slug, email);
      END IF;
    END $mig$;
    CREATE INDEX IF NOT EXISTS idx_sub_form_email ON subscribers(form_slug, email);
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

    CREATE TABLE IF NOT EXISTS isel_presets (
      id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      name       TEXT         NOT NULL UNIQUE,
      items      JSONB        NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ip_flags (
      ip_hash      TEXT        PRIMARY KEY,
      level        INT         NOT NULL DEFAULT 1,
      strike_count INT         NOT NULL DEFAULT 1,
      reason       TEXT,
      first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at   TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ip_flags_expires ON ip_flags(expires_at);

    CREATE TABLE IF NOT EXISTS email_log (
      id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      form_slug     TEXT        NOT NULL REFERENCES forms(slug) ON DELETE CASCADE,
      subscriber_id UUID,
      email         TEXT        NOT NULL,
      subject       TEXT,
      status        TEXT        NOT NULL CHECK (status IN ('sent','failed')),
      error         TEXT,
      sent_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_email_log_form ON email_log(form_slug, sent_at DESC);
    ALTER TABLE email_log
      ADD COLUMN IF NOT EXISTS open_count      INT         NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS click_count     INT         NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS first_opened_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS last_clicked_at TIMESTAMPTZ;

    CREATE TABLE IF NOT EXISTS audit_log (
      id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      user_email  TEXT,
      action      TEXT        NOT NULL,
      target_type TEXT,
      target_id   TEXT,
      detail      JSONB       NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp DESC);

    CREATE TABLE IF NOT EXISTS markets (
      id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name       TEXT NOT NULL,
      slug       TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_markets_slug ON markets(slug);

    CREATE TABLE IF NOT EXISTS sf_users (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      auth0_sub   TEXT UNIQUE NOT NULL,
      email       TEXT NOT NULL,
      name        TEXT,
      system_role TEXT NOT NULL DEFAULT 'viewer',
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen   TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS user_markets (
      user_id    UUID REFERENCES sf_users(id) ON DELETE CASCADE,
      market_id  UUID REFERENCES markets(id)  ON DELETE CASCADE,
      role       TEXT NOT NULL DEFAULT 'viewer',
      PRIMARY KEY (user_id, market_id)
    );
    CREATE INDEX IF NOT EXISTS idx_user_markets_user ON user_markets(user_id);

    CREATE TABLE IF NOT EXISTS form_markets (
      form_slug  VARCHAR(100) REFERENCES forms(slug) ON DELETE CASCADE,
      market_id  UUID         REFERENCES markets(id) ON DELETE CASCADE,
      PRIMARY KEY (form_slug, market_id)
    );
    CREATE INDEX IF NOT EXISTS idx_form_markets_slug ON form_markets(form_slug);

    CREATE TABLE IF NOT EXISTS global_settings (
      id    INTEGER PRIMARY KEY DEFAULT 1,
      value JSONB   NOT NULL DEFAULT '{}'
    );
    INSERT INTO global_settings (id, value) VALUES (1, '{}') ON CONFLICT DO NOTHING;

    ALTER TABLE forms
      ADD COLUMN IF NOT EXISTS status      TEXT NOT NULL DEFAULT 'draft',
      ADD COLUMN IF NOT EXISTS testing_pin CHAR(4);
    UPDATE forms SET testing_pin = LPAD((FLOOR(RANDOM()*9000)+1000)::TEXT, 4, '0')
      WHERE testing_pin IS NULL;

    CREATE TABLE IF NOT EXISTS bug_reports (
      id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      type         TEXT        NOT NULL DEFAULT 'bug',
      title        TEXT        NOT NULL,
      description  TEXT        NOT NULL,
      steps        TEXT,
      context      JSONB       NOT NULL DEFAULT '{}',
      reported_by  TEXT,
      status       TEXT        NOT NULL DEFAULT 'open',
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE bug_reports ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'bug';
    CREATE INDEX IF NOT EXISTS idx_bug_reports_status ON bug_reports(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_bug_reports_type   ON bug_reports(type, created_at DESC);
  `);
  console.log('✔ Database tables ready');
}

// ── Global settings (platform-wide, not per-form) ─────────────────────────────
let globalSettings = { captchaMode: 'builtin', hcaptchaSiteKey: '', hcaptchaSecretKey: '' };

async function loadGlobalSettings() {
  const { rows } = await pool.query('SELECT value FROM global_settings WHERE id=1');
  const raw = rows[0]?.value || {};
  globalSettings = {
    captchaMode:      raw.captchaMode      || 'builtin',
    hcaptchaSiteKey:  raw.hcaptchaSiteKey  || '',
    // ENV var is a deploy-time fallback; DB value takes precedence when set
    hcaptchaSecretKey: raw.hcaptchaSecretKey || ENV_HCAPTCHA_SECRET || '',
  };
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

    // Upsert sf_users — first ever user becomes super-admin
    let { rows: [dbUser] } = await pool.query(
      'SELECT * FROM sf_users WHERE auth0_sub=$1', [claims.sub]);
    if (!dbUser) {
      const { rows: [{ c }] } = await pool.query('SELECT COUNT(*) AS c FROM sf_users');
      const systemRole = (parseInt(c, 10) === 0) ? 'super-admin' : 'viewer';
      ({ rows: [dbUser] } = await pool.query(
        'INSERT INTO sf_users (auth0_sub,email,name,system_role) VALUES ($1,$2,$3,$4) RETURNING *',
        [claims.sub, claims.email || '', claims.name || '', systemRole]
      ));
    } else {
      await pool.query(
        'UPDATE sf_users SET last_seen=NOW(),email=$1,name=$2 WHERE auth0_sub=$3',
        [claims.email || '', claims.name || '', claims.sub]);
    }
    const { rows: userMarkets } = await pool.query(
      `SELECT um.market_id, um.role, m.name, m.slug
       FROM user_markets um JOIN markets m ON m.id=um.market_id
       WHERE um.user_id=$1`, [dbUser.id]);
    // Augment session — keeps existing Auth0 claims intact for backward compat
    req.session.user = { ...claims, dbId: dbUser.id,
      systemRole: dbUser.system_role, markets: userMarkets };

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
    let idx = await readFormsIndex();
    // Market-based filtering for non-super-admins
    if (!isSuperAdmin(req)) {
      const userMktIds = new Set(getUserMarketIds(req));
      const access = await Promise.all(idx.map(async f => {
        const fmIds = await getFormMarketIds(f.slug);
        return fmIds.length === 0 || fmIds.some(id => userMktIds.has(id));
      }));
      idx = idx.filter((_, i) => access[i]);
    }
    const [sharedFonts, templates] = await Promise.all([readSharedFonts(), readDesignTemplates()]);
    const result = await Promise.all(idx.map(async f => {
      const entry = { ...f, subscriberCount: 0, embedPageSize: null, embedJsSize: null, mediaSize: null,
                      status: f.status || 'draft', testingPin: f.testingPin || null };
      try {
        const cfg = await readFormConfig(f.slug);
        const { rows: countRows } = await pool.query(
          `SELECT COUNT(*) AS c FROM subscribers WHERE form_slug=$1 AND status='active'`, [f.slug]);
        entry.subscriberCount = parseInt(countRows[0].c, 10);
        entry.description        = cfg.site.description || '';
        entry.designTemplateId   = cfg.designTemplateId || null;
        entry.embedPageSize = Buffer.byteLength(renderEmbedPage(cfg, sharedFonts, templates), 'utf8');
        entry.embedJsSize   = Buffer.byteLength(renderEmbedScript(origin, cfg), 'utf8');
        entry.mediaSize     = await getFormMediaSize(f.slug);
      } catch(_) { /* skip if config unreadable */ }
      entry.analytics = await readAnalytics(f.slug);
      // Attach market list to each form entry
      entry.markets = await pool.query(
        `SELECT m.id, m.name, m.slug FROM form_markets fm
         JOIN markets m ON m.id=fm.market_id WHERE fm.form_slug=$1`, [f.slug]
      ).then(r => r.rows);
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
      slug: Joi.string().min(1).max(60).pattern(/^[a-z0-9-]+$/).required(),
      marketIds: Joi.array().items(Joi.string().uuid()).default([])
    }).validate(req.body);
    if (valErr) return res.status(400).json({ error: valErr.details[0].message });
    const { slug, name, marketIds } = body;
    if (RESERVED_SLUGS.has(slug)) return res.status(400).json({ error: 'Slug is reserved' });
    // Non-super-admins must assign to at least one market they administer
    if (!isSuperAdmin(req)) {
      const userAdminMktIds = new Set(
        (req.session.user?.markets || []).filter(m => m.role === 'admin').map(m => m.market_id));
      if (!marketIds.some(id => userAdminMktIds.has(id)))
        return res.status(403).json({ error: 'Assign form to at least one market you administer' });
    }
    const newTestingPin = String(Math.floor(1000 + Math.random() * 9000));
    await pool.query(
      'INSERT INTO forms(slug, name, created_at, status, testing_pin, config) VALUES($1, $2, NOW(), $3, $4, $5)',
      [slug, name, 'draft', newTestingPin, defaultFormConfig(slug, name)]
    );
    // Assign form to selected markets
    for (const mId of marketIds) {
      await pool.query(
        'INSERT INTO form_markets(form_slug,market_id) VALUES($1,$2) ON CONFLICT DO NOTHING',
        [slug, mId]);
    }
    logAudit(req, 'form.create', 'form', slug, { name, marketIds });
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
    // Role check — only admin or super-admin can delete
    const fmIds = await getFormMarketIds(slug);
    if (!isSuperAdmin(req) && userEffectiveRole(req, fmIds) !== 'admin')
      return res.status(403).json({ error: 'Admin role required to delete this form' });
    const idx = await readFormsIndex();
    if (idx.length <= 1) return res.status(400).json({ error: 'Cannot delete the last form' });
    // Delete associated S3 media files before removing the DB record (cascade doesn't cover S3)
    const { rows: mediaRows } = await pool.query('SELECT s3_key FROM media WHERE form_slug=$1', [slug]);
    await Promise.all(mediaRows.map(r =>
      s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: r.s3_key })).catch(() => {})
    ));
    // Delete form — cascades to subscribers, analytics, media, form_markets (DB rows)
    await pool.query('DELETE FROM forms WHERE slug=$1', [slug]);
    logAudit(req, 'form.delete', 'form', slug, {});
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

// Update form status (and optionally PIN)
app.patch('/api/admin/forms/:slug/status', adminAuth, async (req, res) => {
  try {
    const { slug } = req.params;
    const { status, testingPin } = req.body;
    const VALID_STATUSES = ['draft', 'testing', 'live', 'archived'];
    if (!VALID_STATUSES.includes(status))
      return res.status(400).json({ error: 'Invalid status. Must be draft, testing, live, or archived.' });
    // 'live' requires admin or super-admin role — editors can toggle between draft/testing/archived
    if (status === 'live') {
      const fmIds = await getFormMarketIds(slug);
      const role = userEffectiveRole(req, fmIds);
      if (!isSuperAdmin(req) && role !== 'admin')
        return res.status(403).json({ error: 'Admin role required to publish a form' });
    }
    if (testingPin !== undefined) {
      if (!/^\d{4}$/.test(testingPin))
        return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
      await pool.query('UPDATE forms SET status=$1, testing_pin=$2 WHERE slug=$3', [status, testingPin, slug]);
    } else {
      await pool.query('UPDATE forms SET status=$1 WHERE slug=$2', [status, slug]);
    }
    logAudit(req, 'form.status_change', 'form', slug,
      { status, testingPin: testingPin ? '****' : undefined });
    res.json({ ok: true });
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
    // Role check — editor or above required
    const fmIds = await getFormMarketIds(slug);
    const role = userEffectiveRole(req, fmIds);
    if (!isSuperAdmin(req) && !['admin', 'editor'].includes(role))
      return res.status(403).json({ error: 'Editor role or above required to save config' });
    // If name changed, also update the name column
    const updates = req.body.name
      ? await pool.query('UPDATE forms SET config=$1, name=$2 WHERE slug=$3', [req.body, req.body.name, slug])
      : await pool.query('UPDATE forms SET config=$1 WHERE slug=$2', [req.body, slug]);
    if (!updates.rowCount) return res.status(404).json({ error: 'Form not found' });
    logAudit(req, 'form.config_save', 'form', slug, {});
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

// Duplicate-check before upload: GET /api/admin/media/check-dup?name=foo.jpg&scope=form&slug=myslug
app.get('/api/admin/media/check-dup', adminAuth, async (req, res) => {
  try {
    const name  = (req.query.name  || '').trim();
    const scope = req.query.scope === 'shared' ? 'shared' : 'form';
    const slug  = req.query.slug || '';
    if (!name) return res.json({ exists: false });
    let rows;
    if (scope === 'shared') {
      ({ rows } = await pool.query(
        `SELECT id, url, original_name FROM media WHERE form_slug IS NULL AND original_name=$1 LIMIT 1`, [name]
      ));
    } else {
      ({ rows } = await pool.query(
        `SELECT id, url, original_name FROM media WHERE form_slug=$1 AND original_name=$2 LIMIT 1`, [slug, name]
      ));
    }
    if (rows.length) {
      res.json({ exists: true, id: rows[0].id, url: rows[0].url });
    } else {
      res.json({ exists: false });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Image proxy for canvas editor — fetches S3 object server-side and returns with CORS headers
// Avoids the browser CORS restriction that taints canvas when drawing cross-origin images
app.get('/api/admin/media/img-proxy', adminAuth, async (req, res) => {
  const key = (req.query.key || '').replace(/^\/+/, '');
  if (!key || !key.startsWith('uploads/')) return res.status(400).send('Invalid key');
  try {
    const cmd = new GetObjectCommand({ Bucket: S3_BUCKET, Key: key });
    const s3Res = await s3.send(cmd);
    const mimeType = s3Res.ContentType || 'image/jpeg';
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    s3Res.Body.pipe(res);
  } catch(e) {
    res.status(404).send('Not found');
  }
});

// Multi-upload: POST /api/admin/forms/:slug/upload-multi (up to 20 files)
app.post('/api/admin/forms/:slug/upload-multi', adminAuth, (req, res, next) => {
  upload.array('images', 20)(req, res, err => {
    if (err) return res.status(400).json({ error: err.message || 'Upload error' });
    next();
  });
}, async (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files' });
  const folder = req.body.folder || '';
  const shared = req.body.shared === '1' || req.body.shared === 'true';
  const results = [];
  for (const file of req.files) {
    try {
      await pool.query(
        `INSERT INTO media(id, form_slug, s3_key, url, original_name, mime_type, size, folder, uploaded_at)
         VALUES($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
        [uuidv4(), shared ? null : req.params.slug, file.key, file.location,
         file.originalname, file.mimetype, file.size, folder]
      );
      results.push({ ok: true, name: file.originalname, url: file.location });
    } catch(e) {
      results.push({ ok: false, name: file.originalname, error: e.message });
    }
  }
  res.json({ results });
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

// All media (no form scope) — used by media library when no form is active
app.get('/api/admin/media', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, form_slug, s3_key, url, original_name, mime_type, size, folder, uploaded_at
       FROM media ORDER BY uploaded_at DESC`
    );
    res.json(rows.map(r => ({ ...rowToMedia(r), _shared: r.form_slug === null, formSlug: r.form_slug })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Bulk delete media items (S3 + DB)
app.post('/api/admin/media/bulk-delete', adminAuth, async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No IDs' });
  try {
    const { rows } = await pool.query('SELECT s3_key FROM media WHERE id = ANY($1::uuid[])', [ids]);
    for (const r of rows) {
      try { await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: r.s3_key })); } catch(_) {}
    }
    await pool.query('DELETE FROM media WHERE id = ANY($1::uuid[])', [ids]);
    res.json({ deleted: ids.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Bulk move media items to a category (folder field)
app.patch('/api/admin/media/bulk-move-category', adminAuth, async (req, res) => {
  const { ids, category } = req.body;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No IDs' });
  try {
    await pool.query('UPDATE media SET folder=$1 WHERE id = ANY($2::uuid[])', [category || null, ids]);
    res.json({ updated: ids.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get subscribers for a form (paginated)
app.get('/api/admin/forms/:slug/subscribers', adminAuth, async (req, res) => {
  try {
    const slug        = req.params.slug;
    const page        = Math.max(1, parseInt(req.query.page)   || 1);
    const limit       = Math.min(200, parseInt(req.query.limit) || 50);
    const search      = (req.query.search || '').trim();
    const status      = req.query.status      || 'all';
    const emailStatus = req.query.emailStatus || 'all';
    const offset      = (page - 1) * limit;

    // Allowlisted sort columns — s.* columns and el.status from the LATERAL join
    const SORT_ALLOW = {
      email:'s.email', status:'s.status', subscribed_at:'s.subscribed_at',
      exported:'s.exported', email_status:'el.status'
    };
    const sort = SORT_ALLOW[req.query.sort] || 's.subscribed_at';
    const dir  = req.query.dir === 'asc' ? 'ASC' : 'DESC';

    // Always include the email_log LATERAL join so we can filter/sort by email status
    const lateral = `LEFT JOIN LATERAL (
      SELECT status, error, id FROM email_log
      WHERE subscriber_id = s.id ORDER BY sent_at DESC LIMIT 1
    ) el ON true`;

    const conditions = ['s.form_slug=$1'];
    const vals = [slug];
    if (status !== 'all') { conditions.push(`s.status=$${vals.length+1}`); vals.push(status); }
    if (search) {
      conditions.push(`(s.email ILIKE $${vals.length+1} OR s.status ILIKE $${vals.length+1} OR s.ip_address ILIKE $${vals.length+1} OR s.custom_fields::text ILIKE $${vals.length+1})`);
      vals.push(`%${search}%`);
    }
    if      (emailStatus === 'sent')   conditions.push(`el.status = 'sent'`);
    else if (emailStatus === 'failed') conditions.push(`el.status = 'failed'`);
    else if (emailStatus === 'none')   conditions.push(`el.status IS NULL`);
    const where = conditions.join(' AND ');

    const countRes = await pool.query(
      `SELECT COUNT(*) AS c FROM subscribers s ${lateral} WHERE ${where}`, vals);
    const total = parseInt(countRes.rows[0].c, 10);
    const dataRes = await pool.query(
      `SELECT s.*, el.status AS email_status, el.error AS email_error, el.id AS email_log_id
         FROM subscribers s ${lateral}
         WHERE ${where}
         ORDER BY ${sort} ${dir} NULLS LAST LIMIT $${vals.length+1} OFFSET $${vals.length+2}`,
      [...vals, limit, offset]
    );
    res.json({ subscribers: dataRes.rows.map(rowToSubscriber), total, page, pages: Math.ceil(total/limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Delete subscriber (GDPR)
app.delete('/api/admin/forms/:slug/subscribers/:id', adminAuth, async (req, res) => {
  try {
    // Role check — only admin can delete subscribers
    const fmIds = await getFormMarketIds(req.params.slug);
    if (!isSuperAdmin(req) && userEffectiveRole(req, fmIds) !== 'admin')
      return res.status(403).json({ error: 'Admin role required to delete subscribers' });
    const { rowCount } = await pool.query(
      'DELETE FROM subscribers WHERE id=$1 AND form_slug=$2', [req.params.id, req.params.slug]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    logAudit(req, 'subscriber.delete', 'subscriber', req.params.id, { form_slug: req.params.slug });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Export subscribers as CSV/JSON — marks each exported record
app.get('/api/admin/forms/:slug/export', adminAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    // Role check — viewer cannot export
    const fmIds = await getFormMarketIds(slug);
    if (!isSuperAdmin(req) && userEffectiveRole(req, fmIds) === 'viewer')
      return res.status(403).json({ error: 'Viewer role cannot export subscribers' });
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

// Admin: resend confirmation email to a pending subscriber
app.post('/api/admin/forms/:slug/subscribers/:id/resend-confirm', adminAuth, async (req, res) => {
  try {
    const { slug, id } = req.params;
    const { rows } = await pool.query(
      `SELECT id, email, unsubscribe_token FROM subscribers WHERE id=$1 AND form_slug=$2 AND status='pending' LIMIT 1`,
      [id, slug]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Pending subscriber not found' });
    const cfg = await readFormConfig(slug);
    const sub = { id: rows[0].id, email: rows[0].email, unsubscribeToken: rows[0].unsubscribe_token };
    sendConfirmationEmail(cfg, sub).catch(e => console.error('[email]', e.message));
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Email log: paginated list with optional status filter
app.get('/api/admin/forms/:slug/email-log', adminAuth, async (req, res) => {
  try {
    const { slug } = req.params;
    const page   = Math.max(1, parseInt(req.query.page) || 1);
    const limit  = 50;
    const offset = (page - 1) * limit;
    const status = ['sent','failed'].includes(req.query.status) ? req.query.status : null;

    const conds  = status ? 'WHERE form_slug=$1 AND status=$2' : 'WHERE form_slug=$1';
    const params = status ? [slug, status] : [slug];

    const [countRes, rowRes] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM email_log ${conds}`, params),
      pool.query(
        `SELECT id, subscriber_id, email, subject, status, error, sent_at
           FROM email_log ${conds} ORDER BY sent_at DESC LIMIT ${limit} OFFSET ${offset}`,
        params
      )
    ]);
    res.json({
      rows:  rowRes.rows,
      total: parseInt(countRes.rows[0].count),
      page,
      pages: Math.ceil(parseInt(countRes.rows[0].count) / limit),
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Email log: resend welcome email for a specific log entry
// Email log: sent/failed counts (for stat card)
app.get('/api/admin/forms/:slug/email-log/counts', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT status, COUNT(*) AS n FROM email_log WHERE form_slug=$1 GROUP BY status`,
      [req.params.slug]
    );
    const counts = { sent: 0, failed: 0 };
    rows.forEach(r => { if (r.status in counts) counts[r.status] = parseInt(r.n); });
    res.json(counts);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Email log: clear all entries for a form
app.delete('/api/admin/forms/:slug/email-log', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM email_log WHERE form_slug=$1', [req.params.slug]);
    res.json({ deleted: rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Subscribers: delete ALL subscribers for a form (bulk GDPR purge)
app.delete('/api/admin/forms/:slug/subscribers', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM subscribers WHERE form_slug=$1', [req.params.slug]);
    res.json({ deleted: rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Email log: resend welcome email for a specific log entry
app.post('/api/admin/forms/:slug/email-log/:logId/resend', adminAuth, async (req, res) => {
  try {
    const { slug, logId } = req.params;
    const { rows: logRows } = await pool.query(
      'SELECT * FROM email_log WHERE id=$1 AND form_slug=$2', [logId, slug]);
    if (!logRows.length) return res.status(404).json({ error: 'Log entry not found' });

    const logEntry = logRows[0];
    if (!logEntry.subscriber_id) return res.status(400).json({ error: 'No subscriber linked — cannot resend' });

    const { rows: subRows } = await pool.query(
      'SELECT * FROM subscribers WHERE id=$1', [logEntry.subscriber_id]);
    if (!subRows.length) return res.status(404).json({ error: 'Subscriber deleted — cannot resend' });

    const cfg = await readFormConfig(slug);
    await sendWelcomeEmail(cfg, rowToSubscriber(subRows[0]));
    res.json({ ok: true });
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
  try {
    const templates = await readDesignTemplates();
    const withSize = await Promise.all(templates.map(async t => {
      const urls = [t.design.logoUrl, t.design.backgroundImage].filter(Boolean);
      let mediaSize = null;
      if (urls.length) {
        const { rows } = await pool.query(
          'SELECT COALESCE(SUM(size), 0) AS total FROM media WHERE url = ANY($1)', [urls]);
        mediaSize = parseInt(rows[0]?.total || 0, 10);
      }
      return { ...t, mediaSize };
    }));
    res.json(withSize);
  } catch(e) { res.status(500).json({ error: e.message }); }
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

app.patch('/api/admin/design-templates/:id', adminAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'name required' });
    const { rowCount } = await pool.query(
      'UPDATE design_templates SET name=$1 WHERE id=$2', [name.trim(), req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Icon Select presets ────────────────────────────────────────────────────────
app.get('/api/admin/isel-presets', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM isel_presets ORDER BY name ASC');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/isel-presets', adminAuth, async (req, res) => {
  try {
    const { name, items } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
    const { rows } = await pool.query(
      `INSERT INTO isel_presets (name, items) VALUES ($1, $2)
       ON CONFLICT (name) DO UPDATE SET items=EXCLUDED.items
       RETURNING *`,
      [name.trim(), JSON.stringify(items || [])]
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/isel-presets/:id', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM isel_presets WHERE id=$1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── IP Flags (admin management) ───────────────────────────────────────────────
app.get('/api/admin/ip-flags', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ip_hash, level, strike_count, reason, first_seen, last_seen, expires_at
       FROM ip_flags WHERE expires_at > NOW() ORDER BY last_seen DESC`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/ip-flags/:ipHash', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM ip_flags WHERE ip_hash=$1', [req.params.ipHash]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/ip-flags', adminAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM ip_flags WHERE expires_at > NOW()');
    res.json({ cleared: rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Global settings API ───────────────────────────────────────────────────────
app.get('/api/admin/global-settings', requireAdminOrSuperAdmin, async (req, res) => {
  // Return current in-memory cache (no secret key exposed — return masked placeholder)
  res.json({
    captchaMode:      globalSettings.captchaMode,
    hcaptchaSiteKey:  globalSettings.hcaptchaSiteKey,
    hcaptchaSecretKey: globalSettings.hcaptchaSecretKey ? '••••••••' : '',
    hcaptchaSecretKeySet: !!globalSettings.hcaptchaSecretKey,
  });
});

app.post('/api/admin/global-settings', adminAuth, async (req, res) => {
  try {
    if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Super-admin required' });
    const { captchaMode, hcaptchaSiteKey, hcaptchaSecretKey } = req.body;
    // If secret key is the masked placeholder, keep existing value
    const secretToSave = (hcaptchaSecretKey && hcaptchaSecretKey !== '••••••••')
      ? hcaptchaSecretKey
      : globalSettings.hcaptchaSecretKey;
    const value = {
      captchaMode:      captchaMode      || 'builtin',
      hcaptchaSiteKey:  hcaptchaSiteKey  || '',
      hcaptchaSecretKey: secretToSave    || '',
    };
    await pool.query(
      'INSERT INTO global_settings (id, value) VALUES (1,$1) ON CONFLICT (id) DO UPDATE SET value=$1',
      [value]
    );
    await loadGlobalSettings();
    logAudit(req, 'global_settings.save', 'global_settings', '1', { captchaMode: value.captchaMode });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Audit log API
app.get('/api/admin/audit-log', requireAdminOrSuperAdmin, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
    const offset = (page - 1) * limit;
    const [{ rows }, { rows: countRows }] = await Promise.all([
      pool.query(
        `SELECT id, timestamp, user_email, action, target_type, target_id, detail
         FROM audit_log ORDER BY timestamp DESC LIMIT $1 OFFSET $2`,
        [limit, offset]
      ),
      pool.query('SELECT COUNT(*) FROM audit_log')
    ]);
    const total = parseInt(countRows[0].count);
    res.json({ entries: rows, total, page, pages: Math.ceil(total / limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Current user context ──────────────────────────────────────────────────────
app.get('/api/admin/me', adminAuth, (req, res) => {
  const { dbId, systemRole, markets, email, name, picture } = req.session.user || {};
  res.json({ dbId, systemRole: systemRole || 'viewer', markets: markets || [], email, name, picture });
});

// ── Markets CRUD ──────────────────────────────────────────────────────────────
app.get('/api/admin/markets', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT m.*, COUNT(DISTINCT fm.form_slug) AS form_count,
              COUNT(DISTINCT um.user_id) AS user_count
       FROM markets m
       LEFT JOIN form_markets fm ON fm.market_id=m.id
       LEFT JOIN user_markets um ON um.market_id=m.id
       GROUP BY m.id ORDER BY m.name`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/markets', requireSuperAdmin, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Name required' });
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const { rows: [m] } = await pool.query(
      'INSERT INTO markets(name,slug) VALUES($1,$2) RETURNING *', [name, slug]);
    logAudit(req, 'market.create', 'market', m.id, { name, slug });
    res.json(m);
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Market name/slug already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/admin/markets/:id', requireSuperAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM markets WHERE id=$1', [req.params.id]);
    logAudit(req, 'market.delete', 'market', req.params.id, {});
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Users CRUD ────────────────────────────────────────────────────────────────
app.get('/api/admin/users', requireSuperAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.name, u.system_role, u.created_at, u.last_seen,
         COALESCE(json_agg(
           json_build_object('market_id',um.market_id,'role',um.role,'name',m.name,'slug',m.slug)
         ) FILTER (WHERE um.market_id IS NOT NULL), '[]') AS markets
       FROM sf_users u
       LEFT JOIN user_markets um ON um.user_id=u.id
       LEFT JOIN markets m ON m.id=um.market_id
       GROUP BY u.id ORDER BY u.created_at`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/users/:id', requireSuperAdmin, async (req, res) => {
  try {
    const { systemRole } = req.body;
    if (!['super-admin', 'viewer'].includes(systemRole))
      return res.status(400).json({ error: 'Invalid system_role' });
    await pool.query('UPDATE sf_users SET system_role=$1 WHERE id=$2', [systemRole, req.params.id]);
    logAudit(req, 'user.role_change', 'user', req.params.id, { systemRole });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id/markets', requireSuperAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM user_markets WHERE user_id=$1', [req.params.id]);
    for (const { market_id, role } of (req.body.markets || [])) {
      if (!['admin', 'editor', 'viewer'].includes(role)) continue;
      await pool.query(
        'INSERT INTO user_markets(user_id,market_id,role) VALUES($1,$2,$3)',
        [req.params.id, market_id, role]);
    }
    logAudit(req, 'user.markets_update', 'user', req.params.id, { count: req.body.markets?.length || 0 });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Form Markets ──────────────────────────────────────────────────────────────
app.get('/api/admin/forms/:slug/markets', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT m.* FROM form_markets fm JOIN markets m ON m.id=fm.market_id
       WHERE fm.form_slug=$1 ORDER BY m.name`, [req.params.slug]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/forms/:slug/markets', requireSuperAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM form_markets WHERE form_slug=$1', [req.params.slug]);
    for (const id of (req.body.marketIds || [])) {
      await pool.query(
        'INSERT INTO form_markets(form_slug,market_id) VALUES($1,$2)',
        [req.params.slug, id]);
    }
    logAudit(req, 'form.markets_update', 'form', req.params.slug, { count: req.body.marketIds?.length || 0 });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI Chat Upload ─────────────────────────────────────────────────────────────
// Uploads image for AI chat; stored under chat-uploads/ in S3, NOT in the media table.
app.post('/api/admin/chat-upload', adminAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowed.includes(req.file.mimetype))
      return res.status(400).json({ error: 'Only JPEG, PNG, GIF and WebP images are allowed' });
    if (req.file.size > 10 * 1024 * 1024)
      return res.status(400).json({ error: 'Max file size is 10 MB' });
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '');
    const key = `chat-uploads/${uuidv4()}.${ext}`;
    await s3.send(new PutObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: key,
      Body: req.file.buffer,
      ContentType: req.file.mimetype
    }));
    const url = `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
    res.json({ url });
  } catch(e) {
    console.error('Chat upload error:', e);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ── AI Chat ───────────────────────────────────────────────────────────────────
const _AI_TOOLS = [
  {
    name: 'get_form',
    description: 'Return the full config of a specific form (fields, design, email, embed). Use when the question is about a specific form\'s behaviour or settings.',
    input_schema: { type: 'object', properties: { slug: { type: 'string' } }, required: ['slug'] }
  },
  {
    name: 'get_analytics',
    description: 'Return visit/submit/error counts for a form. Use for conversion or performance questions.',
    input_schema: { type: 'object', properties: { slug: { type: 'string' } }, required: ['slug'] }
  },
  {
    name: 'get_subscribers_summary',
    description: 'Return subscriber counts by status plus 5 most recent subscriber emails. Never returns bulk PII.',
    input_schema: { type: 'object', properties: { slug: { type: 'string' } }, required: ['slug'] }
  },
  {
    name: 'get_form_list',
    description: 'Return all form slugs and names. Use when the question is not form-specific or the user asks what forms exist.',
    input_schema: { type: 'object', properties: {} }
  },
  {
    name: 'get_feedback',
    description: 'Query the feedback log (bugs, change requests, feature ideas). Filter by type and/or status. Use when the user asks what has been reported, what is open, or what features are planned.',
    input_schema: {
      type: 'object',
      properties: {
        type:   { type: 'string', enum: ['bug', 'change', 'feature', 'all'], description: 'Filter by type, or "all"' },
        status: { type: 'string', enum: ['open', 'in-progress', 'resolved', 'wont-fix', 'all'], description: 'Filter by status, or "all"' },
        limit:  { type: 'number', description: 'Max rows to return (default 20, max 50)' }
      }
    }
  },
  {
    name: 'submit_feedback',
    description: 'Save a bug report, change request, or feature request. Use ONLY after collecting a clear title and description from the user. Do not call speculatively.',
    input_schema: {
      type: 'object',
      properties: {
        type:        { type: 'string', enum: ['bug', 'change', 'feature'], description: 'bug = something broken; change = improve existing behaviour; feature = new capability' },
        title:       { type: 'string', description: 'Short one-line summary' },
        description: { type: 'string', description: 'What the issue/request is and why it matters' },
        steps:       { type: 'string', description: 'Steps to reproduce (bugs) or acceptance criteria (change/feature), or empty string' }
      },
      required: ['type', 'title', 'description']
    }
  },
  {
    name: 'create_form',
    description: 'Create a new form. ALWAYS describe the form name and slug to the user and ask "Shall I create it?" BEFORE calling this tool. Never call without explicit confirmation.',
    input_schema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Human-readable form name (e.g. "Summer Newsletter")' },
        slug: { type: 'string', description: 'URL slug — lowercase letters, numbers and hyphens only. Auto-derived from name if omitted.' }
      },
      required: ['name']
    }
  },
  {
    name: 'update_form_config',
    description: 'Update a form\'s display name and/or merge design settings into its existing design. ALWAYS describe what will change and ask "Shall I proceed?" BEFORE calling this tool.',
    input_schema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'Slug of the form to update' },
        name: { type: 'string', description: 'New display name for the form (optional)' },
        design_patch: { type: 'object', description: 'Partial design object to merge into the existing design (e.g. {"primaryColor":"#e63946","fontFamily":"Raleway"})' }
      },
      required: ['slug']
    }
  },
  {
    name: 'list_design_templates',
    description: 'List all saved design templates. Use when the user asks what templates exist or before applying one.',
    input_schema: { type: 'object', properties: {} }
  },
  {
    name: 'create_design_template',
    description: 'Save a design as a named template. ALWAYS show the template name and key colours/fonts to the user and ask "Shall I save this?" BEFORE calling.',
    input_schema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Template name (e.g. "Ocean Blue")' },
        design: { type: 'object', description: 'Full design settings object (primaryColor, bgColor, fontFamily, logoUrl, etc.)' }
      },
      required: ['name', 'design']
    }
  },
  {
    name: 'apply_design_template',
    description: 'Apply a saved design template to a form, replacing its current design. ALWAYS confirm the template name and target form with the user before calling.',
    input_schema: {
      type: 'object',
      properties: {
        template_id: { type: 'string', description: 'Template UUID from list_design_templates' },
        slug: { type: 'string', description: 'Form slug to apply the template to' }
      },
      required: ['template_id', 'slug']
    }
  },
  {
    name: 'analyze_website',
    description: 'Fetch a public website and extract brand colours, fonts, and logo candidate for design recommendations. Call this before suggesting or creating a brand template from a URL. No confirmation needed — read-only.',
    input_schema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Full URL to analyse (must start with http:// or https://)' }
      },
      required: ['url']
    }
  }
];

async function _executeAiTool(name, input) {
  const slug = (input.slug || '').replace(/[^a-z0-9-]/g, '');
  if (name === 'get_form_list') {
    const { rows } = await pool.query('SELECT slug, name FROM forms ORDER BY name');
    return rows;
  }
  const _NO_SLUG_TOOLS = ['get_form_list','get_feedback','submit_feedback','create_form','list_design_templates','create_design_template','analyze_website'];
  if (!slug && !_NO_SLUG_TOOLS.includes(name)) return { error: 'slug required' };
  if (name === 'get_form') {
    const { rows } = await pool.query('SELECT config FROM forms WHERE slug=$1', [slug]);
    return rows.length ? rows[0].config : { error: 'Form not found' };
  }
  if (name === 'get_analytics') {
    const { rows } = await pool.query('SELECT key, count FROM analytics WHERE form_slug=$1', [slug]);
    return Object.fromEntries(rows.map(r => [r.key, Number(r.count)]));
  }
  if (name === 'get_subscribers_summary') {
    const [counts, recent] = await Promise.all([
      pool.query('SELECT status, COUNT(*)::int FROM subscribers WHERE form_slug=$1 GROUP BY status', [slug]),
      pool.query('SELECT email, subscribed_at FROM subscribers WHERE form_slug=$1 ORDER BY subscribed_at DESC LIMIT 5', [slug])
    ]);
    return { counts: counts.rows, recent: recent.rows };
  }
  if (name === 'get_feedback') {
    const VALID_TYPES   = ['bug', 'change', 'feature', 'all'];
    const VALID_STATUSES = ['open', 'in-progress', 'resolved', 'wont-fix', 'all'];
    const fType   = VALID_TYPES.includes(input.type)     ? input.type   : 'all';
    const fStatus = VALID_STATUSES.includes(input.status) ? input.status : 'all';
    const limit   = Math.min(Math.max(1, parseInt(input.limit) || 20), 50);
    const conditions = [];
    const params = [];
    if (fType   !== 'all') { params.push(fType);   conditions.push(`type=$${params.length}`); }
    if (fStatus !== 'all') { params.push(fStatus);  conditions.push(`status=$${params.length}`); }
    params.push(limit);
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT type, title, description, steps, status, reported_by, created_at
       FROM bug_reports ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
      params
    );
    return { count: rows.length, items: rows };
  }
  if (name === 'submit_feedback') {
    const VALID_TYPES = ['bug', 'change', 'feature'];
    const type = VALID_TYPES.includes(input.type) ? input.type : 'bug';
    const title = (input.title || '').substring(0, 255);
    const description = (input.description || '').substring(0, 4000);
    const steps = (input.steps || '').substring(0, 2000);
    if (!title || !description) return { error: 'title and description are required' };
    const ctx = JSON.stringify(input._context || {});
    const { rows } = await pool.query(
      `INSERT INTO bug_reports (type, title, description, steps, context, reported_by)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6) RETURNING id, created_at`,
      [type, title, description, steps || null, ctx, input._reportedBy || null]
    );
    return { ok: true, id: rows[0].id, type, created_at: rows[0].created_at };
  }
  if (name === 'create_form') {
    const formName = (input.name || '').trim().substring(0, 100);
    if (!formName) return { error: 'name required' };
    let formSlug = (input.slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    if (!formSlug) formSlug = formName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').substring(0, 60);
    const { rows: ex } = await pool.query('SELECT slug FROM forms WHERE slug=$1', [formSlug]);
    if (ex.length) return { error: `Slug "${formSlug}" is already taken. Provide a different name or a custom slug.` };
    const defaultCfg = {
      fields: [{ id: 'email', type: 'email', label: 'Email address', required: true }],
      sections: [
        { id: 'logo', type: 'logo', visible: true },
        { id: 'hero', type: 'hero', visible: true },
        { id: 'form', type: 'form', visible: true },
        { id: 'footer', type: 'footer', visible: true }
      ],
      design: {}, email: {}
    };
    await pool.query(
      'INSERT INTO forms (slug, name, config, status) VALUES ($1,$2,$3::jsonb,$4)',
      [formSlug, formName, JSON.stringify(defaultCfg), 'draft']
    );
    return { ok: true, slug: formSlug, name: formName, status: 'draft' };
  }
  if (name === 'update_form_config') {
    const { rows } = await pool.query('SELECT slug FROM forms WHERE slug=$1', [slug]);
    if (!rows.length) return { error: 'Form not found' };
    const setClauses = []; const params = [slug];
    if (input.name && typeof input.name === 'string') {
      params.push(input.name.trim().substring(0, 100));
      setClauses.push(`name=$${params.length}`);
    }
    if (input.design_patch && typeof input.design_patch === 'object') {
      params.push(JSON.stringify(input.design_patch));
      setClauses.push(`config = jsonb_set(config, '{design}', COALESCE(config->'design','{}') || $${params.length}::jsonb)`);
    }
    if (!setClauses.length) return { error: 'No updates provided — supply name and/or design_patch' };
    await pool.query(`UPDATE forms SET ${setClauses.join(', ')} WHERE slug=$1`, params);
    return { ok: true, slug, updated: setClauses.map(c => c.split('=')[0].trim()) };
  }
  if (name === 'list_design_templates') {
    const { rows } = await pool.query('SELECT id, name, created_at FROM design_templates ORDER BY name');
    return { count: rows.length, templates: rows };
  }
  if (name === 'create_design_template') {
    const tplName = (input.name || '').trim().substring(0, 100);
    if (!tplName) return { error: 'name required' };
    if (!input.design || typeof input.design !== 'object') return { error: 'design object required' };
    const { rows } = await pool.query(
      'INSERT INTO design_templates (name, design) VALUES ($1,$2::jsonb) RETURNING id, name',
      [tplName, JSON.stringify(input.design)]
    );
    return { ok: true, id: rows[0].id, name: rows[0].name };
  }
  if (name === 'apply_design_template') {
    const tplId = (input.template_id || '').trim();
    if (!tplId) return { error: 'template_id required' };
    const { rows: tpl } = await pool.query('SELECT design FROM design_templates WHERE id=$1', [tplId]);
    if (!tpl.length) return { error: 'Template not found' };
    const { rows: frm } = await pool.query('SELECT slug FROM forms WHERE slug=$1', [slug]);
    if (!frm.length) return { error: 'Form not found' };
    await pool.query(
      "UPDATE forms SET config = jsonb_set(config, '{design}', $1::jsonb) WHERE slug=$2",
      [JSON.stringify(tpl[0].design), slug]
    );
    return { ok: true, slug, template_id: tplId };
  }
  if (name === 'analyze_website') {
    const rawUrl = (input.url || '').trim();
    if (!rawUrl) return { error: 'url required' };
    let parsedUrl;
    try { parsedUrl = new URL(rawUrl); } catch(e) { return { error: 'Invalid URL' }; }
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) return { error: 'Only http/https URLs are supported' };
    const fetchHtml = (targetUrl) => new Promise((resolve, reject) => {
      const mod = targetUrl.startsWith('https') ? require('https') : require('http');
      const req = mod.get(targetUrl, { timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SignFlow/1.0)' } }, (res) => {
        if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
          resolve({ redirect: new URL(res.headers.location, targetUrl).href }); return;
        }
        let data = '';
        res.on('data', chunk => { data += chunk; if (data.length > 400000) req.destroy(); });
        res.on('end', () => resolve({ html: data }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
    let fetched = await fetchHtml(rawUrl);
    if (fetched.redirect) fetched = await fetchHtml(fetched.redirect).catch(() => ({ html: '' }));
    const html = fetched.html || '';
    const hexColors = [...new Set((html.match(/#[0-9a-fA-F]{6}\b/g) || []).map(c => c.toLowerCase()))].slice(0, 30);
    const cssVars = {};
    for (const m of html.matchAll(/--([a-zA-Z-]*(?:color|primary|secondary|accent|brand|bg|background|fore|text|heading)[a-zA-Z-]*)\s*:\s*(#[0-9a-fA-F]{3,6}|rgba?\([^)]+\)|[a-zA-Z]+)\s*[;}\n]/gi))
      cssVars[`--${m[1].trim()}`] = m[2].trim();
    const fonts = [...new Set((html.match(/font-family\s*:\s*([^;}"'\n]+)/gi) || [])
      .map(m => m.replace(/font-family\s*:\s*/i,'').replace(/['"]/g,'').split(',')[0].trim())
      .filter(Boolean))].slice(0, 5);
    const ogImage = (html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i) || [])[1] || null;
    const title = (html.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1]?.trim() || null;
    return { url: rawUrl, title, topColors: hexColors.slice(0,12), cssVars: Object.keys(cssVars).length ? cssVars : undefined, fonts: fonts.length ? fonts : undefined, suggestedLogo: ogImage };
  }
  return { error: 'Unknown tool' };
}

app.post('/api/admin/ai-chat', adminAuth, async (req, res) => {
  if (!_anthropic)
    return res.status(503).json({ error: 'AI not configured — add ANTHROPIC_API_KEY to .env' });

  const { message, context = {}, history = [], imageUrls = [] } = req.body;
  const _hasImages = Array.isArray(imageUrls) && imageUrls.length > 0;
  if (!message || typeof message !== 'string' || message.length > 2000)
    return res.status(400).json({ error: 'Invalid message' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders(); // Establish SSE connection immediately before any async work

  const _userRole = req.session?.user?.systemRole || 'admin';
  const _roleGuidance = _userRole === 'super-admin'
    ? `The current user is a super-admin: provide full technical detail including config paths, DB field names, code-level explanations, and exact server behaviour where relevant.`
    : `The current user is a market admin or editor (non-technical). Keep responses functional and jargon-free: describe what the issue is, give a plain-language workaround, and suggest logging a support ticket if the issue needs escalation. Avoid config paths, DB fields, or code-level detail.`;

  const systemPrompt =
    `You are a concise, knowledgeable SignFlow admin assistant. ` +
    `Answer in 2–4 sentences unless complexity genuinely requires more. ` +
    `Always reference exact UI locations (tab names, button labels, setting names). ` +
    `Never guess live data — use tools to fetch it first. ` +
    `${_roleGuidance} ` +
    `If the user wants to report a bug, request a change, or suggest a feature: ask for (1) a short title, (2) a description. For bugs also ask for steps to reproduce. Then call submit_feedback with the correct type (bug/change/feature). IMPORTANT: After submit_feedback returns, ALWAYS include the returned id as the reference number in your reply (e.g. "Logged — ref: abc123"). NEVER call submit_feedback more than once for the same report; if the user asks for a ref number after you already submitted, extract the id from the previous tool result in this conversation — do NOT submit again. Use get_feedback to look up existing reports.\n\n` +
    `WRITE OPERATIONS — create_form, update_form_config, create_design_template, apply_design_template: ALWAYS describe exactly what you will create or change (name, slug, colours, template, target form) and ask "Shall I proceed?" then WAIT for the user to confirm in their next message before calling the tool. Never call a write tool without explicit user confirmation.\n\n` +
    `BRAND TEMPLATES FROM WEBSITES: When the user provides a URL and asks to match or use its branding, call analyze_website first. Present the extracted colours, fonts, and logo to the user. Then propose a design_patch or template design, confirm with the user ("Shall I save this as a template?" or "Shall I apply these colours to [form]?"), and only then call create_design_template or update_form_config.\n\n` +
    `BRAND TEMPLATES FROM IMAGES: When the user uploads or shares an image (logo, screenshot, brand asset), analyse the colours and style visible in the image. Propose a matching design_patch covering primaryColor, bgColor, fontFamily and any other relevant fields. Confirm before calling any write tool.\n\n` +
    `Current admin context: tab="${context.currentTab || '?'}", ` +
    `form="${context.currentFormSlug || 'none'}", ` +
    `modal="${context.activeModal || 'none'}", panel="${context.panelTab || 'none'}", role="${_userRole}".` +
    (_helpContext ? `\n\n--- SignFlow Documentation ---\n${_helpContext}` : '');

  const messages = [
    ...history.slice(-10),
    {
      role: 'user',
      content: _hasImages
        ? [
            ...imageUrls.slice(0, 4).map(url => ({ type: 'image', source: { type: 'url', url } })),
            { type: 'text', text: message }
          ]
        : message
    }
  ];

  // Keepalive: prevent Nginx proxy_read_timeout from dropping the SSE connection
  // during silent gaps while the agentic loop awaits the Anthropic API response.
  const keepalive = setInterval(() => { try { res.write(': keepalive\n\n'); } catch(e) {} }, 10000);

  try {
    while (true) {
      const response = await _anthropic.messages.create({
        model: 'claude-sonnet-4-6',
        max_tokens: 1024,
        system: systemPrompt,
        tools: _AI_TOOLS,
        messages
      });

      if (response.stop_reason === 'end_turn') {
        for (const block of response.content)
          if (block.type === 'text')
            res.write(`data: ${JSON.stringify({ text: block.text })}\n\n`);
        break;
      }

      if (response.stop_reason === 'tool_use') {
        messages.push({ role: 'assistant', content: response.content });
        const toolResults = [];
        for (const block of response.content) {
          if (block.type !== 'tool_use') continue;
          res.write(`data: ${JSON.stringify({ tool: block.name })}\n\n`);
          let result;
          try {
            const toolInput = block.name === 'submit_feedback'
              ? { ...block.input, _context: context, _reportedBy: req.session?.user?.email || null }
              : block.input;
            result = await _executeAiTool(block.name, toolInput);
          }
          catch(e) { result = { error: e.message }; }
          toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: JSON.stringify(result) });
        }
        messages.push({ role: 'user', content: toolResults });
      } else {
        break;
      }
    }
  } catch(e) {
    res.write(`data: ${JSON.stringify({ error: e.message })}\n\n`);
  } finally {
    clearInterval(keepalive);
  }

  res.write('data: [DONE]\n\n');
  res.end();
});

// ── Bug Reports ───────────────────────────────────────────────────────────────
app.get('/api/admin/bug-reports', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, type, title, description, steps, context, reported_by, status, created_at, updated_at
       FROM bug_reports ORDER BY created_at DESC LIMIT 200`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/bug-reports/:id/status', adminAuth, async (req, res) => {
  const VALID = ['open', 'in-progress', 'resolved', 'wont-fix'];
  const { status } = req.body;
  if (!VALID.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const { rowCount } = await pool.query(
      `UPDATE bug_reports SET status=$1, updated_at=NOW() WHERE id=$2`,
      [status, req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/bug-reports/:id', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM bug_reports WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Internal read-only API (WebFetch / Claude Code access) ───────────────────
// Secured by INTERNAL_API_KEY env var. Read-only — no mutations.
// Usage: GET /api/internal/feedback?key=<INTERNAL_API_KEY>[&type=bug|change|feature][&status=open]
app.get('/api/internal/feedback', async (req, res) => {
  const key = process.env.INTERNAL_API_KEY;
  if (!key || req.query.key !== key)
    return res.status(401).json({ error: 'Unauthorized' });

  const VALID_TYPES    = ['bug', 'change', 'feature', 'all'];
  const VALID_STATUSES = ['open', 'in-progress', 'resolved', 'wont-fix', 'all'];
  const fType   = VALID_TYPES.includes(req.query.type)     ? req.query.type   : 'all';
  const fStatus = VALID_STATUSES.includes(req.query.status) ? req.query.status : 'all';
  const limit   = Math.min(Math.max(1, parseInt(req.query.limit) || 50), 100);

  const conditions = [];
  const params = [];
  if (fType   !== 'all') { params.push(fType);   conditions.push(`type=$${params.length}`); }
  if (fStatus !== 'all') { params.push(fStatus); conditions.push(`status=$${params.length}`); }
  params.push(limit);
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  try {
    const { rows } = await pool.query(
      `SELECT id, type, title, description, steps, status, reported_by, context, created_at, updated_at
       FROM bug_reports ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
      params
    );
    res.json({ count: rows.length, filters: { type: fType, status: fStatus }, items: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/internal/query?key=<INTERNAL_API_KEY>
// Body: { "sql": "SELECT ...", "params": [] }
// Read-only: only SELECT statements are accepted. Max 200 rows returned.
app.post('/api/internal/query', async (req, res) => {
  const key = process.env.INTERNAL_API_KEY;
  if (!key || req.query.key !== key)
    return res.status(401).json({ error: 'Unauthorized' });

  const { sql = '', params = [] } = req.body;
  const trimmed = sql.trim().toLowerCase();

  // Strict read-only guard — must start with SELECT and contain no mutation keywords
  if (!trimmed.startsWith('select'))
    return res.status(400).json({ error: 'Only SELECT statements are allowed' });
  const banned = /\b(insert|update|delete|drop|truncate|alter|create|grant|revoke|copy|execute|perform|do\s+\$\$)\b/i;
  if (banned.test(sql))
    return res.status(400).json({ error: 'Statement contains disallowed keywords' });
  if (!Array.isArray(params))
    return res.status(400).json({ error: 'params must be an array' });
  if (params.length > 20)
    return res.status(400).json({ error: 'Max 20 params' });

  try {
    // Wrap in a read-only transaction for extra safety
    await pool.query('BEGIN READ ONLY');
    let rows;
    try {
      ({ rows } = await pool.query(sql, params));
      await pool.query('COMMIT');
    } catch(e) {
      await pool.query('ROLLBACK');
      throw e;
    }
    // Cap at 200 rows to avoid huge responses
    const capped = rows.length > 200;
    res.json({ count: rows.length, capped, rows: rows.slice(0, 200) });
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

// Per-form unsubscribe page (GET) — lists all active subscriptions for that email
app.get('/:slug/unsubscribe/:token', async (req, res) => {
  const { slug, token } = req.params;
  let cfg, subscriber = null, allSubs = [], sharedFonts = [];
  try { cfg = await readFormConfig(slug); } catch(e) { return res.status(404).send('Form not found'); }
  try {
    const { rows } = await pool.query(
      `SELECT * FROM subscribers WHERE form_slug=$1 AND unsubscribe_token=$2 LIMIT 1`,
      [slug, token]
    );
    subscriber = rows[0] ? rowToSubscriber(rows[0]) : null;
    if (subscriber) {
      const { rows: sr } = await pool.query(
        `SELECT form_slug, subscribed_at FROM subscribers WHERE email=$1 AND status='active' ORDER BY subscribed_at`,
        [subscriber.email]
      );
      allSubs = sr;
    }
    sharedFonts = await readSharedFonts();
  } catch(e) { /* render with what we have */ }
  res.send(renderUnsubscribePage(cfg, { subscriber, allSubs, token }, sharedFonts));
});

// Per-form unsubscribe page (POST) — handles unsub-one / unsub-all / delete-all actions
app.post('/:slug/unsubscribe/:token', async (req, res) => {
  const { slug, token } = req.params;
  const { action, form_slug } = req.body;
  let cfg, subscriber = null, allSubs = [], sharedFonts = [], message = '', success = false;
  try { cfg = await readFormConfig(slug); } catch(e) { return res.status(404).send('Form not found'); }
  try {
    const { rows } = await pool.query(
      `SELECT * FROM subscribers WHERE form_slug=$1 AND unsubscribe_token=$2 LIMIT 1`,
      [slug, token]
    );
    subscriber = rows[0] ? rowToSubscriber(rows[0]) : null;
    sharedFonts = await readSharedFonts();
    if (!subscriber) {
      message = 'Token not found or already processed.';
    } else if (action === 'unsub-one' && form_slug) {
      await pool.query(
        `UPDATE subscribers SET status='unsubscribed', unsubscribed_at=NOW()
         WHERE email=$1 AND form_slug=$2 AND status='active'`,
        [subscriber.email, form_slug]
      );
      bumpAnalytic(form_slug, 'unsubscribes');
      message = `Unsubscribed from ${form_slug}.`;
      success = true;
    } else if (action === 'unsub-all') {
      const { rows: active } = await pool.query(
        `SELECT form_slug FROM subscribers WHERE email=$1 AND status='active'`,
        [subscriber.email]
      );
      await pool.query(
        `UPDATE subscribers SET status='unsubscribed', unsubscribed_at=NOW() WHERE email=$1 AND status='active'`,
        [subscriber.email]
      );
      for (const r of active) bumpAnalytic(r.form_slug, 'unsubscribes');
      message = 'Unsubscribed from all forms.';
      success = true;
    } else if (action === 'delete-all') {
      await pool.query(`DELETE FROM subscribers WHERE email=$1`, [subscriber.email]);
      subscriber = null;
      message = 'All your data has been permanently deleted.';
      success = true;
    }
    if (subscriber) {
      const { rows: sr } = await pool.query(
        `SELECT form_slug, subscribed_at FROM subscribers WHERE email=$1 AND status='active' ORDER BY subscribed_at`,
        [subscriber.email]
      );
      allSubs = sr;
    }
  } catch(e) { message = 'An error occurred. Please try again.'; }
  res.send(renderUnsubscribePage(cfg, { subscriber, allSubs, token, message, success }, sharedFonts));
});

// Double opt-in confirmation
app.get('/:slug/confirm/:token', async (req, res) => {
  const { slug, token } = req.params;
  let cfg, sharedFonts = [];
  try { cfg = await readFormConfig(slug); } catch(e) { return res.status(404).send('Form not found'); }
  try { sharedFonts = await readSharedFonts(); } catch(e) {}
  try {
    const { rows } = await pool.query(
      `SELECT id, email, status FROM subscribers WHERE form_slug=$1 AND unsubscribe_token=$2 LIMIT 1`,
      [slug, token]
    );
    const sub = rows[0];
    if (!sub) return res.send(renderConfirmPage(cfg, sharedFonts, 'invalid'));
    if (sub.status === 'active') return res.send(renderConfirmPage(cfg, sharedFonts, 'already'));
    if (sub.status !== 'pending') return res.send(renderConfirmPage(cfg, sharedFonts, 'invalid'));
    await pool.query(`UPDATE subscribers SET status='active', subscribed_at=NOW() WHERE id=$1`, [sub.id]);
    const record = { id: sub.id, email: sub.email, unsubscribeToken: token, customFields: {} };
    sendWelcomeEmail(cfg, record).catch(e => console.error('[email]', e.message));
    bumpAnalytic(slug, 'submits');
    res.send(renderConfirmPage(cfg, sharedFonts, 'confirmed'));
  } catch(e) {
    console.error('[confirm]', e.message);
    res.status(500).send('Error processing confirmation.');
  }
});

// Email open tracking (1×1 GIF)
const TRACKING_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
app.get('/:slug/track/o/:logId', (req, res) => {
  res.set({ 'Content-Type': 'image/gif', 'Cache-Control': 'no-store, no-cache, must-revalidate', Pragma: 'no-cache' });
  res.send(TRACKING_GIF);
  pool.query(
    `UPDATE email_log SET open_count=open_count+1, first_opened_at=COALESCE(first_opened_at,NOW()) WHERE id=$1`,
    [req.params.logId]
  ).catch(e => console.error('[track-open]', e.message));
});

// Email click tracking (redirect)
app.get('/:slug/track/c/:logId', (req, res) => {
  const url = req.query.u ? decodeURIComponent(req.query.u) : null;
  if (!url || !/^https?:\/\//.test(url)) return res.redirect('/');
  res.redirect(url);
  pool.query(
    `UPDATE email_log SET click_count=click_count+1, last_clicked_at=NOW() WHERE id=$1`,
    [req.params.logId]
  ).catch(e => console.error('[track-click]', e.message));
});

// Prize reveal page
app.get('/:slug/prize/:token', async (req, res) => {
  const { slug, token } = req.params;
  let cfg;
  try { cfg = await readFormConfig(slug); } catch(e) { return res.status(404).send('Form not found'); }
  try {
    const { rows } = await pool.query(
      'SELECT custom_fields FROM subscribers WHERE form_slug=$1 AND unsubscribe_token=$2 LIMIT 1',
      [slug, token]
    );
    if (!rows[0]) return res.status(404).send('Prize not found');
    const prizedrawField = (cfg.fields || []).find(f => f.type === 'prizedraw');
    if (!prizedrawField) return res.status(404).send('Prize not found');
    const raw = (rows[0].custom_fields || {})[prizedrawField.id];
    let prize = null;
    try { prize = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch(e) {}
    if (!prize) return res.status(404).send('Prize not found');
    const d = cfg.design || {};
    const accent = d.accentColor || '#e94560';
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your Prize</title>
<style>
  body{margin:0;padding:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:${d.pageBg||'#f5f5f5'};font-family:${d.bodyFont||'sans-serif'}}
  .card{background:${d.cardBg||'#fff'};border-radius:${d.cardRadius||16}px;padding:40px 32px;max-width:420px;width:90%;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,0.12)}
  h1{margin:0 0 8px;font-size:1.5rem;color:${d.headingColor||'#222'}}
  .prize-name{font-size:1.8rem;font-weight:700;color:${accent};margin:20px 0}
  .prize-img{width:120px;height:120px;object-fit:cover;border-radius:50%;margin:0 auto 16px;display:block;border:4px solid ${accent}}
  .emoji{font-size:3rem;margin-bottom:8px}
  p{color:${d.textColor||'#555'};margin:0 0 24px}
  a.btn{display:inline-block;background:${d.btnBg||accent};color:${d.btnTextColor||'#fff'};text-decoration:none;padding:12px 28px;border-radius:${d.btnBorderRadius||8}px;font-weight:600;font-size:0.95rem}
</style></head><body>
<div class="card">
  <div class="emoji">🎉</div>
  ${prize.icon ? `<img class="prize-img" src="${escapeHtml(prize.icon)}" alt="${escapeHtml(prize.label)}">` : ''}
  <h1>Congratulations!</h1>
  <p>You won:</p>
  <div class="prize-name">${escapeHtml(prize.label)}</div>
  <p>This reward is waiting for you. Check your email for details.</p>
  <a class="btn" href="/${escapeHtml(slug)}">Visit us again</a>
</div>
</body></html>`;
    res.send(html);
  } catch (e) {
    console.error('[prize]', e.message);
    res.status(500).send('Error');
  }
});

// Public form page
app.get('/:slug', async (req, res) => {
  const { slug } = req.params;
  if (RESERVED_SLUGS.has(slug)) return res.status(404).send('Not found');
  try {
    // Check status first — only one extra DB round-trip, avoids rendering expensive pages unnecessarily
    const { rows: [statusRow] } = await pool.query(
      'SELECT status, testing_pin FROM forms WHERE slug=$1', [slug]);
    if (!statusRow) return res.status(404).send('<p>Page not found.</p>');

    const { status, testing_pin } = statusRow;

    // Draft / Archived — branded status page (200 with form design, no form)
    // Admin previews bypass the status gate (query param _preview=1 requires adminAuth; _tplPreview is fine)
    if ((status === 'draft' || status === 'archived') && !req.query._preview && !req.query._tplPreview) {
      let formCfg = await readFormConfig(slug);
      const sharedFonts = await readSharedFonts();
      formCfg._status = status;
      return res.send(renderFormStatusPage(formCfg, sharedFonts));
    }

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
    res.send(renderPublicPage(formCfg, sharedFonts, templates,
      { testingPin: status === 'testing' ? testing_pin : null }));
  }
  catch(e) { res.status(404).send('<p>Page not found.</p>'); }
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
    // Status check before expensive rendering
    const { rows: [statusRow] } = await pool.query(
      'SELECT status, testing_pin FROM forms WHERE slug=$1', [req.params.slug]);
    if (!statusRow) return res.status(404).send('Form not found');

    const { status, testing_pin } = statusRow;
    if (status === 'draft' || status === 'archived')
      return res.status(403).send('This form is not publicly available.');

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
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://www.googletagmanager.com https://connect.facebook.net; " +
      "script-src-attr 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com https://*.amazonaws.com; img-src 'self' data: blob: https:; " +
      "connect-src 'self' https://api.hcaptcha.com https://www.google-analytics.com https://region1.google-analytics.com https://www.facebook.com; " +
      "frame-src https://www.youtube.com https://player.vimeo.com; " +
      `frame-ancestors ${faVal}; object-src 'none'; base-uri 'self'`);
    res.send(renderEmbedPage(cfg, sharedFonts, templates,
      { testingPin: status === 'testing' ? testing_pin : null }));
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

// Challenge endpoint — returns flag level + timing token + optional math challenge
// Called by the public page on load to configure anti-bot layers
app.get('/:slug/challenge', async (req, res) => {
  const ipHash = hashIp(req.ip);
  const level  = await getIpFlagLevel(ipHash);
  const ts     = genTimingToken();
  if (level >= 3) return res.json({ level: 3, blocked: true, ts });
  const resp = { level, ts };
  if (level >= 2) resp.challenge = genChallenge();
  res.json(resp);
});

// Form submission
app.post('/:slug/subscribe', submitLimiter, async (req, res) => {
  const { slug } = req.params;
  let cfg;
  try { cfg = await readFormConfig(slug); }
  catch(e) { return res.status(404).json({ error: 'Form not found' }); }
  // Block submissions to draft and archived forms
  try {
    const { rows: [sr] } = await pool.query('SELECT status FROM forms WHERE slug=$1', [slug]);
    if (!sr || sr.status === 'draft' || sr.status === 'archived')
      return res.status(403).json({ error: 'This form is not accepting submissions.' });
  } catch(_) { /* non-fatal — proceed if status check fails */ }
  const body = req.body;
  // Top-level safety net — ensures a response is always sent even on unexpected errors
  try {

  // ── Anti-bot layers ──────────────────────────────────────────────────────────
  const ipHash = hashIp(req.ip);

  // Layer 1 — Honeypot: bots fill hidden fields, humans never see them
  if (body._hp) {
    await flagIp(ipHash, 'honeypot');
    bumpAnalytic(slug, 'errors');
    return res.status(400).json({ error: 'Invalid submission.' });
  }

  // Layer 2 — Timing: reject submissions that arrive impossibly fast
  const timing = verifyTimingToken(body._ts);
  if (!timing.ok) {
    if (timing.reason === 'too_fast') {
      await flagIp(ipHash, 'too_fast');
      bumpAnalytic(slug, 'errors');
      return res.status(400).json({ error: 'Please take a moment to fill in the form.' });
    }
    if (timing.reason === 'expired') {
      return res.status(400).json({ error: 'The form has expired — please reload the page.' });
    }
    // missing/malformed token: page may be cached; don't flag but continue
  }

  // Layer 3 — Flag level gate
  const flagLevel = await getIpFlagLevel(ipHash);
  if (flagLevel >= 3) {
    bumpAnalytic(slug, 'errors');
    return res.status(429).json({ error: 'Too many failed attempts. Please try again later.' });
  }

  // Layer 4 — Proof-of-work (flagged level 1+)
  if (flagLevel >= 1) {
    const nonce     = parseInt(body._pow_nonce);
    const challenge = (body._pow_challenge || '').trim();
    if (!challenge || isNaN(nonce) || nonce < 0) {
      await flagIp(ipHash, 'missing_pow');
      bumpAnalytic(slug, 'errors');
      return res.status(400).json({ error: 'Security check failed. Please reload and try again.' });
    }
    const hash = crypto.createHash('sha256').update(challenge + nonce).digest('hex');
    if (!hash.startsWith('000')) {
      await flagIp(ipHash, 'bad_pow');
      bumpAnalytic(slug, 'errors');
      return res.status(400).json({ error: 'Security check failed. Please reload and try again.' });
    }
  }

  // Layer 5 — Math challenge (flagged level 2+)
  if (flagLevel >= 2) {
    const chalToken  = body._chal_token  || '';
    const chalAnswer = parseInt(body._chal_answer);
    if (!verifyChallenge(chalToken, chalAnswer)) {
      await flagIp(ipHash, 'bad_challenge');
      bumpAnalytic(slug, 'errors');
      return res.status(400).json({ error: 'Incorrect answer — please try again.' });
    }
  }

  if (globalSettings.captchaMode === 'hcaptcha' && globalSettings.hcaptchaSecretKey) {
    const captchaToken = body['h-captcha-response'] || '';
    if (!captchaToken) { bumpAnalytic(slug, 'errors'); return res.status(400).json({ error: 'Please complete the CAPTCHA.' }); }
    try {
      const vp = new URLSearchParams({ secret: globalSettings.hcaptchaSecretKey, response: captchaToken, remoteip: req.ip });
      const vr = await fetch('https://api.hcaptcha.com/siteverify', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: vp.toString() });
      const vj = await vr.json();
      if (!vj.success) { bumpAnalytic(slug, 'errors'); return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' }); }
    } catch(e) { return res.status(500).json({ error: 'CAPTCHA service error. Please try again.' }); }
  }

  // ── Disclaimer checkbox validation ───────────────────────────────────────
  if (cfg.site.gdprCheckboxRequired && body['_gdpr_check'] !== 'on') {
    bumpAnalytic(slug, 'errors');
    return res.status(400).json({ error: 'Please tick the checkbox to continue.' });
  }

  // ── Joi input validation ──────────────────────────────────────────────────
  const schemaShape = { email: Joi.string().email({ tlds: { allow: false } }).max(254).required() };
  cfg.fields.filter(f => !f.system).forEach(f => {
    if (f.type === 'tel') {
      // Phone-specific validation: format check + optional country restriction
      const countries = f.phoneCountries || [];
      schemaShape[f.id] = Joi.string().custom((val, helpers) => {
        if (!val || !val.trim()) return val;
        const { ok, msg } = validatePhoneNumber(val, countries);
        if (!ok) return helpers.message(msg);
        return val;
      }).allow('').optional();
    } else if (['year', 'yearmonth', 'yearmonthday'].includes(f.type)) {
      // Date-picker validation: ensure submitted value represents a real date
      schemaShape[f.id] = Joi.string().custom((val, helpers) => {
        if (!val || !val.trim()) return val;
        const parts = val.split('-').map(Number);
        if (f.type === 'year') {
          if (parts.length < 1 || isNaN(parts[0]) || parts[0] < 1800 || parts[0] > 2200)
            return helpers.message('Invalid year');
        } else if (f.type === 'yearmonth') {
          if (parts.length < 2 || isNaN(parts[0]) || isNaN(parts[1]) || parts[1] < 1 || parts[1] > 12)
            return helpers.message('Invalid year or month');
        } else { // yearmonthday
          if (parts.length < 3 || parts.some(isNaN))
            return helpers.message('Invalid date');
          // Verify the day actually exists in that month (e.g. rejects Feb 31)
          const d = new Date(parts[0], parts[1] - 1, parts[2]);
          if (d.getFullYear() !== parts[0] || d.getMonth() + 1 !== parts[1] || d.getDate() !== parts[2])
            return helpers.message('Invalid date — that day does not exist in the selected month');
        }
        return val;
      }).allow('').optional();
    } else {
      schemaShape[f.id] = Joi.string().max(1000).allow('').optional();
    }
  });
  const { error: valErr, value: validated } = Joi.object(schemaShape).unknown(true).validate(body);
  if (valErr) {
    bumpAnalytic(slug, 'errors');
    return res.status(400).json({ error: valErr.details[0].message });
  }
  const email = validated.email.trim().toLowerCase();

  // ── Duplicate / uniqueness check ─────────────────────────────────────────────
  // Build a WHERE clause from the configured key fields.
  // Field IDs are validated as /^[a-zA-Z][a-zA-Z0-9_]*$/ so safe to interpolate in JSONB path.
  const allowDup  = cfg.site.allowDuplicateEmail || false;
  const keyFields = allowDup
    ? (cfg.site.uniqueKeyFields || ['email']).filter(Boolean)
    : ['email'];
  const dupConds  = ['form_slug=$1'];
  const dupParams = [slug];
  let   dupIdx    = 2;
  if (keyFields.includes('email')) {
    dupConds.push(`email=$${dupIdx++}`);
    dupParams.push(email);
  }
  keyFields.filter(f => f !== 'email').forEach(fieldId => {
    dupConds.push(`custom_fields->>'${fieldId}'=$${dupIdx++}`);
    dupParams.push((body[fieldId] || '').trim());
  });
  const { rows: existingRows } = await pool.query(
    `SELECT id, status FROM subscribers WHERE ${dupConds.join(' AND ')} LIMIT 1`, dupParams);
  const existing = existingRows[0] || null;
  if (existing && existing.status === 'active') {
    bumpAnalytic(slug, 'errors');
    return res.status(409).json({ error: 'This email is already subscribed.' });
  }

  const doubleOptIn = cfg.site.doubleOptIn || false;

  // Double opt-in: pending subscriber re-submits → resend confirmation
  if (doubleOptIn && existing && existing.status === 'pending') {
    const newToken = uuidv4();
    await pool.query(`UPDATE subscribers SET unsubscribe_token=$1, subscribed_at=NOW() WHERE id=$2`, [newToken, existing.id]);
    sendConfirmationEmail(cfg, { id: existing.id, email, unsubscribeToken: newToken }).catch(e => console.error('[email]', e.message));
    return res.json({ success: true, pendingConfirmation: true });
  }

  const customFields = {};
  cfg.fields.filter(f => !f.system).forEach(f => {
    if (f.type === 'prizedraw') return; // handled separately
    customFields[f.id] = (body[f.id] || '').trim();
  });
  // Prize draw: server picks winner weighted by probability
  let prizeResult = null;
  const prizedrawField = cfg.fields.find(f => f.type === 'prizedraw');
  if (prizedrawField && (prizedrawField.prizes || []).length) {
    const prizes = prizedrawField.prizes;
    const total = prizes.reduce((s, p) => s + (+(p.probability || 1)), 0);
    let r = Math.random() * total, cum = 0, winIdx = prizes.length - 1;
    for (let i = 0; i < prizes.length; i++) { cum += +(prizes[i].probability || 1); if (r <= cum) { winIdx = i; break; } }
    const winner = prizes[winIdx];
    prizeResult = { fieldId: prizedrawField.id, index: winIdx, label: winner.label || '', value: winner.value || '', image: winner.image || winner.icon || '' };
    customFields[prizedrawField.id] = JSON.stringify(prizeResult);
  }

  const id             = uuidv4();
  const token          = uuidv4();
  const now            = new Date().toISOString();
  const insertStatus   = doubleOptIn ? 'pending' : 'active';
  const record         = { id, email, status: insertStatus, subscribedAt: now, unsubscribedAt: null,
                           unsubscribeToken: token, consentGiven: true, consentTimestamp: now,
                           ipAddress: req.ip, customFields };

  if (existing) {
    // Re-activate a previously unsubscribed record
    await pool.query(
      `UPDATE subscribers SET status=$1, subscribed_at=NOW(), unsubscribed_at=NULL,
       unsubscribe_token=$2, consent_given=TRUE, consent_timestamp=$3,
       ip_address=$4, custom_fields=$5 WHERE id=$6`,
      [insertStatus, token, now, req.ip, customFields, existing.id]
    );
    record.id = existing.id;
  } else {
    // No matching key-field combo found — INSERT a new record.
    // For allowDup=false: uniqueness is enforced by the SELECT check above.
    // For allowDup=true: same email + different key fields is intentionally allowed,
    //   so we always INSERT (the unique index was downgraded to non-unique at startup).
    await pool.query(
      `INSERT INTO subscribers
       (id, form_slug, email, status, subscribed_at, unsubscribed_at,
        unsubscribe_token, consent_given, consent_timestamp, ip_address, custom_fields)
       VALUES($1,$2,$3,$4,NOW(),NULL,$5,TRUE,$6,$7,$8)`,
      [id, slug, email, insertStatus, token, now, req.ip, customFields]
    );
  }

  if (doubleOptIn) {
    // Don't count as a submit until confirmed — bump happens in the confirm route
    sendConfirmationEmail(cfg, record).catch(e => console.error('[email]', e.message));
    return res.json({ success: true, pendingConfirmation: true });
  }
  bumpAnalytic(slug, 'submits');
  // Fire-and-forget welcome email (never blocks the response)
  sendWelcomeEmail(cfg, record).catch(e => console.error('[email]', e.message));
  res.json({ success: true, ...(prizeResult ? { prizeResult } : {}) });
  } catch(routeErr) {
    console.error('[subscribe]', routeErr.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
  }
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

// ── Analytics snippets ────────────────────────────────────────────────────────
function ga4Snippet(measurementId) {
  if (!measurementId || !measurementId.trim()) return '';
  const id = measurementId.trim();
  return `<script async src="https://www.googletagmanager.com/gtag/js?id=${id}"></script>\n` +
    `<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}` +
    `gtag('js',new Date());gtag('config','${id}',{send_page_view:true});</script>`;
}

function metaPixelSnippet(pixelId) {
  if (!pixelId || !pixelId.trim()) return '';
  const id = pixelId.trim();
  return `<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?` +
    `n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;` +
    `n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;` +
    `s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}` +
    `(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');` +
    `fbq('init','${id}');fbq('track','PageView');</script>` +
    `<noscript><img height="1" width="1" style="display:none" ` +
    `src="https://www.facebook.com/tr?id=${id}&ev=PageView&noscript=1"/></noscript>`;
}

// Embeds tracking config as a JSON data block read by the consent manager JS.
// Scripts are NOT injected at page load — the consent manager injects them
// dynamically only after the visitor grants the relevant consent category.
function trackingConfigBlock(siteCfg) {
  const ga4 = (siteCfg.ga4MeasurementId || '').trim();
  const pixel = (siteCfg.metaPixelId || '').trim();
  if (!ga4 && !pixel) return '';
  return `<script type="application/json" id="sf-tc">${JSON.stringify({ ga4, pixel })}</script>`;
}

function gdprHtml(siteCfg) {
  const text = siteCfg.gdprText ||
    'By subscribing you agree to our <a href="{privacyUrl}" target="_blank">Privacy Policy</a>. We store your data securely and you can unsubscribe or request deletion at any time.';
  const resolved = text.replace(/\{privacyUrl\}/g, siteCfg.privacyPolicyUrl || '#');
  if (siteCfg.gdprCheckboxRequired) {
    return `<label class="sf-gdpr-check"><input type="checkbox" name="_gdpr_check" required> <span>${resolved}</span></label>`;
  }
  return resolved;
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
      <div class="sf-picker-wrap"${f.pickerHeight ? ` style="--sf-picker-h:${parseInt(f.pickerHeight)}px"` : ''}>
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
      <div class="sf-picker-wrap sf-picker-dual"${f.pickerHeight ? ` style="--sf-picker-h:${parseInt(f.pickerHeight)}px"` : ''}>
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

  // ── yearmonthday ──
  if (f.type === 'yearmonthday') {
    const minY  = f.minYear || 1920;
    const maxY  = f.maxYear || new Date().getFullYear();
    const midY  = Math.round((minY + maxY) / 2);
    const years = [];
    for (let y = maxY; y >= minY; y--) years.push(y);
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const days   = [];
    for (let d = 1; d <= 31; d++) days.push(d);
    return `<div class="sf-field sf-field--picker"${condAttr}>
      <label>${escapeHtml(f.label)}${req}</label>
      <div class="sf-picker-wrap sf-picker-triple"${f.pickerHeight ? ` style="--sf-picker-h:${parseInt(f.pickerHeight)}px"` : ''}>
        <div class="sf-picker-drum" id="sf_drum_d_${f.id}">
          ${days.map(d => `<div class="sf-pick-item" data-val="${String(d).padStart(2,'0')}">${d}</div>`).join('')}
        </div>
        <div class="sf-picker-drum" id="sf_drum_m_${f.id}">
          ${months.map((m,i) => `<div class="sf-pick-item" data-val="${String(i+1).padStart(2,'0')}">${m}</div>`).join('')}
        </div>
        <div class="sf-picker-drum" id="sf_drum_y_${f.id}">
          ${years.map(y => `<div class="sf-pick-item" data-val="${y}">${y}</div>`).join('')}
        </div>
        <div class="sf-picker-overlay"></div>
      </div>
      <input type="hidden" id="sf_${f.id}" name="${f.id}" value="${midY}-01-01"></div>`;
  }

  // ── iconselect ──
  if (f.type === 'iconselect') {
    const items           = f.iselItems           || [];
    const multi           = f.iselMulti           || false;
    const showLbls        = f.iselShowLabels       !== false;
    const tileSize        = f.iselTileSize         || 64;
    const selStyle        = f.iselSelStyle         || 'border';
    const selColor        = f.iselSelColor         || accent;
    const layout          = f.iselLayout           || 'scroll';   // 'scroll' | 'grid'
    const columns         = f.iselColumns          || 4;
    const flow            = f.iselFlow             || 'row';      // 'row' | 'col'
    const tileBg          = f.iselTileBg           || '#ffffff';
    const tileBorderColor = f.iselTileBorderColor  || '#e0e0e0';
    const tileBorderWidth = f.iselTileBorderWidth  != null ? f.iselTileBorderWidth : 2;
    const minSel          = f.iselMinSel           || 0;          // 0 = no minimum
    const maxSel          = f.iselMaxSel           || 0;          // 0 = unlimited
    const iselAlign       = f.iselAlign            || 'left';     // 'left'|'center'|'right'
    const sizeMode        = f.iselSizeMode         || 'fixed';    // 'fixed'|'fill'
    const showArrows      = layout === 'scroll' && (f.iselShowArrows !== false);

    const tilesHtml = items.map(item => {
      let iconHtml = '';
      if (item.iconType === 'material') {
        iconHtml = `<span class="sf-isel-icon sf-isel-mat">${escapeHtml(item.icon || '')}</span>`;
      } else if (item.iconType === 'image') {
        iconHtml = `<img class="sf-isel-icon sf-isel-img" src="${escapeHtml(item.icon || '')}" alt="" loading="lazy">`;
      } else if (item.iconType === 'text') {
        const fontStyle = item.iconFont ? `font-family:'${escapeHtml(item.iconFont)}',sans-serif;` : '';
        iconHtml = `<span class="sf-isel-icon sf-isel-txt" style="${fontStyle}">${escapeHtml(item.icon || '')}</span>`;
      } else {
        iconHtml = `<span class="sf-isel-icon sf-isel-emoji">${escapeHtml(item.icon || '')}</span>`;
      }
      const lblHtml = `<span class="sf-isel-lbl${showLbls ? '' : ' sf-isel-lbl-hide'}">${escapeHtml(item.label || item.value || '')}</span>`;
      const perTileStyle = [
        item.tileBg          ? `--sf-tile-bg:${item.tileBg}`              : '',
        item.tileTextColor   ? `--sf-tile-text:${item.tileTextColor}`     : '',
        item.tileBorderColor ? `--sf-tile-border:${item.tileBorderColor}` : '',
      ].filter(Boolean).join(';');
      return `<div class="sf-isel-tile"${perTileStyle ? ` style="${perTileStyle}"` : ''} data-val="${escapeHtml(item.value || '')}" role="option" aria-selected="false" tabindex="0">${iconHtml}${lblHtml}</div>`;
    }).join('');

    // Layout extras
    let wrapClass = 'sf-isel-wrap';
    let trackClass = 'sf-isel-track';
    let gridVars = '';
    const alignVal = iselAlign === 'center' ? 'center' : iselAlign === 'right' ? 'flex-end' : 'flex-start';
    if (layout === 'grid') {
      wrapClass += ' sf-isel-grid';
      if (sizeMode === 'fill') {
        gridVars = `;--sf-isel-cols:${columns}`;
      } else {
        gridVars = `;--sf-isel-cols:${columns}`;
      }
      if (flow === 'col') {
        const nRows = Math.ceil(items.length / columns);
        gridVars += `;--sf-isel-rows:${nRows}`;
        trackClass += ' sf-isel-track-col';
      }
      if (sizeMode === 'fill') wrapClass += ' sf-isel-fill-w';
    } else {
      // scroll layout
      if (sizeMode === 'fill') wrapClass += ' sf-isel-fill-w';
      if (showArrows) wrapClass += ' sf-isel-has-arrows';
    }
    const sizeVar = sizeMode === 'fill' ? '' : `;--sf-isel-size:${tileSize}px`;
    const tileShape = f.iselTileShape || 'square';

    const wrapHtml = `<div class="${wrapClass}" data-multi="${multi}" data-sel-style="${selStyle}" data-min-sel="${minSel}" data-max-sel="${maxSel}" data-tile-shape="${tileShape}" style="--sf-isel-accent:${selColor}${sizeVar};--sf-isel-tile-bg:${tileBg};--sf-isel-border:${tileBorderColor};--sf-isel-bw:${tileBorderWidth}px;--sf-isel-align:${alignVal}${gridVars}">
        ${showArrows ? '<button type="button" class="sf-isel-arrow sf-isel-arrow-l" aria-label="Scroll left">&#8249;</button>' : ''}
        <div class="sf-isel-scroll"><div class="${trackClass}">${tilesHtml}</div></div>
        ${showArrows ? '<button type="button" class="sf-isel-arrow sf-isel-arrow-r" aria-label="Scroll right">&#8250;</button>' : ''}
        <input type="hidden" id="sf_${f.id}" name="${f.id}" value="" ${f.required ? 'required' : ''}>
      </div>`;

    return `<div class="sf-field sf-field--isel"${condAttr}>
      <label>${escapeHtml(f.label)}${req}</label>
      ${wrapHtml}</div>`;
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

  // ── tel (phone) — explicit case for better UX attributes + country hint ──
  if (f.type === 'tel') {
    const ph = escapeHtml(f.placeholder || '+1 234 567 8900');
    const countriesHint = (f.phoneCountries && f.phoneCountries.length)
      ? `<small style="display:block;margin-top:3px;font-size:0.8em;color:#666">Accepted countries: ${escapeHtml(f.phoneCountries.join(', '))}</small>`
      : '';
    return `<div class="sf-field"${condAttr}>
    <label for="sf_${f.id}">${escapeHtml(f.label)}${req}</label>
    <input type="tel" id="sf_${f.id}" name="${f.id}" placeholder="${ph}" inputmode="tel" autocomplete="tel" ${f.required ? 'required' : ''}>${countriesHint}</div>`;
  }

  // ── email — explicit case to add autocomplete + maxlength ──
  if (f.type === 'email') {
    return `<div class="sf-field"${condAttr}>
    <label for="sf_${f.id}">${escapeHtml(f.label)}${req}</label>
    <input type="email" id="sf_${f.id}" name="${f.id}" placeholder="${escapeHtml(f.placeholder || '')}" autocomplete="email" maxlength="254" ${f.required ? 'required' : ''}></div>`;
  }

  // ── prizedraw — rendered by renderCntItem when in a confirmation container ──
  if (f.type === 'prizedraw') return '';

  // ── default (text, number, textarea handled above, etc.) ──
  return `<div class="sf-field"${condAttr}>
    <label for="sf_${f.id}">${escapeHtml(f.label)}${req}</label>
    <input type="${f.type || 'text'}" id="sf_${f.id}" name="${f.id}"
      placeholder="${escapeHtml(f.placeholder || '')}" ${f.required ? 'required' : ''}></div>`;
}

// ── Slider + picker CSS (injected into page <style>) ─────────────────────────
function sliderPickerCSS(accent) {
  return `
  /* Picker (year / yearmonth / yearmonthday) */
  .sf-field--picker .sf-picker-wrap{position:relative;height:var(--sf-picker-h,120px);overflow:hidden;border:2px solid #e0e0e0;border-radius:8px;background:#fafafa;user-select:none;}
  .sf-picker-dual,.sf-picker-triple{display:flex;}
  .sf-picker-dual .sf-picker-drum,.sf-picker-triple .sf-picker-drum{flex:1;border-right:1px solid #e0e0e0;}
  .sf-picker-dual .sf-picker-drum:last-child,.sf-picker-triple .sf-picker-drum:last-child{border-right:none;}
  .sf-picker-triple .sf-picker-drum:first-child{flex:0 0 22%;max-width:22%;}
  .sf-picker-triple .sf-picker-drum:nth-child(2){flex:0 0 30%;max-width:30%;}
  .sf-picker-triple .sf-picker-drum:nth-child(3){flex:1;}
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
  .sf-arc-handle{transition:transform .05s linear;}

  /* Icon Select */
  .sf-field--isel .sf-isel-wrap{position:relative;padding:4px 0 8px;}
  .sf-isel-has-arrows{padding-left:28px;padding-right:28px;}
  /* sf-isel-scroll = the actual overflow/scroll container (arrows sit outside it in sf-isel-wrap) */
  .sf-isel-scroll{display:flex;flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none;justify-content:var(--sf-isel-align,flex-start);}
  .sf-isel-scroll::-webkit-scrollbar{display:none;}
  .sf-isel-track{display:flex;gap:8px;width:max-content;padding:2px;flex-shrink:0;}
  .sf-isel-tile{width:var(--sf-isel-size,64px);height:var(--sf-isel-size,64px);border-radius:10px;border:var(--sf-isel-bw,2px) solid var(--sf-tile-border,var(--sf-isel-border,#e0e0e0));display:flex;flex-direction:column;align-items:center;justify-content:center;cursor:pointer;transition:border-color 150ms,background 150ms,box-shadow 150ms,color 150ms;background:var(--sf-tile-bg,var(--sf-isel-tile-bg,#fff));color:var(--sf-tile-text,currentColor);flex-shrink:0;user-select:none;-webkit-tap-highlight-color:transparent;padding:4px;box-sizing:border-box;}
  .sf-isel-tile:hover{border-color:#bbb;}
  .sf-isel-tile.sf-isel-sel.sf-isel-bdr{border-color:var(--sf-isel-accent);box-shadow:0 0 0 1px var(--sf-isel-accent);}
  .sf-isel-tile.sf-isel-sel.sf-isel-fill{background:var(--sf-isel-accent);border-color:var(--sf-isel-accent);}
  .sf-isel-tile.sf-isel-sel.sf-isel-fill .sf-isel-icon,.sf-isel-tile.sf-isel-sel.sf-isel-fill .sf-isel-lbl{color:#fff!important;}
  .sf-isel-icon{line-height:1;pointer-events:none;display:block;text-align:center;}
  .sf-isel-mat{font-family:'Material Icons Round',sans-serif;font-weight:normal;font-style:normal;font-size:calc(var(--sf-isel-size,64px)*0.42);font-feature-settings:'liga';}
  .sf-isel-emoji{font-size:calc(var(--sf-isel-size,64px)*0.40);}
  .sf-isel-img{width:calc(var(--sf-isel-size,64px)*0.55);height:calc(var(--sf-isel-size,64px)*0.55);object-fit:contain;}
  .sf-isel-txt{font-size:calc(var(--sf-isel-size,64px)*0.38);line-height:1;display:block;text-align:center;font-weight:600;color:inherit;}
  .sf-isel-lbl{font-size:11px;margin-top:3px;text-align:center;max-width:calc(var(--sf-isel-size,64px) - 6px);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;pointer-events:none;line-height:1.2;}
  .sf-isel-lbl-hide{display:none;}
  /* Tile shapes */
  .sf-isel-wrap[data-tile-shape="rounded"] .sf-isel-tile{border-radius:12px!important}
  .sf-isel-wrap[data-tile-shape="circle"] .sf-isel-tile{border-radius:50%!important}
  .sf-isel-wrap[data-tile-shape="pill"] .sf-isel-tile{border-radius:100px!important}
  .sf-isel-wrap[data-tile-shape="diamond"] .sf-isel-tile{clip-path:polygon(50% 0%,100% 50%,50% 100%,0% 50%);border-radius:0!important}
  .sf-isel-wrap[data-tile-shape="octagon"] .sf-isel-tile{clip-path:polygon(30% 0%,70% 0%,100% 30%,100% 70%,70% 100%,30% 100%,0% 70%,0% 30%);border-radius:0!important}
  .sf-isel-wrap[data-tile-shape="skewed"] .sf-isel-tile{clip-path:polygon(8% 0%,100% 0%,92% 100%,0% 100%);border-radius:0!important}
  /* Scroll arrows — positioned relative to sf-isel-wrap (non-scrolling) so they never drift */
  .sf-isel-arrow{position:absolute;top:50%;transform:translateY(-50%);z-index:2;width:24px;height:32px;background:rgba(255,255,255,0.88);border:1px solid #ddd;border-radius:6px;cursor:pointer;font-size:18px;line-height:1;display:flex;align-items:center;justify-content:center;padding:0;color:#444;box-shadow:0 1px 4px rgba(0,0,0,.1);}
  .sf-isel-arrow:hover{background:#fff;color:#000;}
  .sf-isel-arrow-l{left:0;}
  .sf-isel-arrow-r{right:0;}
  .sf-isel-arrow[hidden]{display:none;}
  /* Fill-width layout */
  .sf-isel-fill-w .sf-isel-scroll{width:100%;}
  .sf-isel-fill-w .sf-isel-track{display:flex;width:100%;}
  .sf-isel-fill-w .sf-isel-tile{flex:1;min-width:0;width:auto;height:var(--sf-isel-size,64px);}
  /* Grid layout */
  .sf-isel-grid .sf-isel-scroll{overflow:visible;}
  .sf-isel-grid .sf-isel-track{display:grid;grid-template-columns:repeat(var(--sf-isel-cols,4),var(--sf-isel-size,64px));width:auto;}
  .sf-isel-grid.sf-isel-fill-w .sf-isel-track{grid-template-columns:repeat(var(--sf-isel-cols,4),1fr);width:100%;}
  .sf-isel-grid .sf-isel-track-col{grid-auto-flow:column;grid-template-rows:repeat(var(--sf-isel-rows,4),var(--sf-isel-size,64px));grid-template-columns:unset;}
  .sf-isel-grid.sf-isel-fill-w .sf-isel-track-col{grid-template-rows:repeat(var(--sf-isel-rows,4),var(--sf-isel-size,64px));}`;
}

// ── Slider + picker JS (injected at end of page <script>) ────────────────────
function sliderPickerJS() {
  return `
(function(){
  /* ── Picker drums (year / yearmonth / yearmonthday) ── */
  document.querySelectorAll('.sf-picker-drum').forEach(function(drum){
    var inp=drum.closest('.sf-field--picker').querySelector('input[type=hidden]');
    var isMonth=drum.id&&drum.id.includes('_m_');
    var isDay  =drum.id&&drum.id.includes('_d_');
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
      var cur=inp.value||'';var p=cur.split('-');
      // p[0]=YYYY  p[1]=MM  p[2]=DD (optional)
      if(isDay){
        inp.value=(p[0]||new Date().getFullYear())+'-'+(p[1]||'01')+'-'+val;
      } else if(isMonth){
        inp.value=(p[0]||new Date().getFullYear())+'-'+val+(p[2]?'-'+p[2]:'');
      } else {
        // year drum
        if(p.length>=3) inp.value=val+'-'+(p[1]||'01')+'-'+(p[2]||'01');
        else if(p.length===2) inp.value=val+'-'+(p[1]||'01');
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

  /* ── Icon Select ── */
  document.querySelectorAll('.sf-isel-wrap').forEach(function(wrap){
    var multi=wrap.dataset.multi==='true';
    var sty=wrap.dataset.selStyle||'border';
    var inp=wrap.querySelector('input[type=hidden]');
    var styleClass=sty==='fill'?'sf-isel-fill':'sf-isel-bdr';
    var minSel=parseInt(wrap.dataset.minSel||0)||0;
    var maxSel=parseInt(wrap.dataset.maxSel||0)||0;
    wrap.querySelectorAll('.sf-isel-tile').forEach(function(tile){
      tile.classList.add(styleClass);
      tile.addEventListener('click',function(){
        if(multi){
          var sel=wrap.querySelectorAll('.sf-isel-tile.sf-isel-sel');
          var isSelected=tile.classList.contains('sf-isel-sel');
          if(!isSelected&&maxSel>0&&sel.length>=maxSel)return;
          if(isSelected&&minSel>0&&sel.length<=minSel)return;
          tile.classList.toggle('sf-isel-sel');
          tile.setAttribute('aria-selected',tile.classList.contains('sf-isel-sel'));
        }else{
          wrap.querySelectorAll('.sf-isel-tile').forEach(function(t){t.classList.remove('sf-isel-sel');t.setAttribute('aria-selected','false');});
          tile.classList.add('sf-isel-sel');
          tile.setAttribute('aria-selected','true');
        }
        inp.value=Array.from(wrap.querySelectorAll('.sf-isel-tile.sf-isel-sel')).map(function(t){return t.dataset.val;}).join(',');
      });
      tile.addEventListener('keydown',function(e){
        if(e.key===' '||e.key==='Enter'){e.preventDefault();tile.click();}
      });
    });
    /* ── Scroll arrows (A2) ── */
    /* Arrows live in wrap (non-scrolling); actual scroll happens on sf-isel-scroll inside */
    var arrowL=wrap.querySelector('.sf-isel-arrow-l');
    var arrowR=wrap.querySelector('.sf-isel-arrow-r');
    if(arrowL&&arrowR){
      var scroll=wrap.querySelector('.sf-isel-scroll')||wrap;
      function updateArrows(){
        arrowL.hidden=scroll.scrollLeft<=0;
        arrowR.hidden=scroll.scrollLeft>=scroll.scrollWidth-scroll.clientWidth-1;
      }
      var tilePx=parseInt(getComputedStyle(wrap).getPropertyValue('--sf-isel-size'))||64;
      arrowL.addEventListener('click',function(){scroll.scrollBy({left:-(tilePx+8),behavior:'smooth'});});
      arrowR.addEventListener('click',function(){scroll.scrollBy({left:tilePx+8,behavior:'smooth'});});
      scroll.addEventListener('scroll',updateArrows,{passive:true});
      updateArrows();
    }
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
    ${globalSettings.captchaMode === 'hcaptcha' && globalSettings.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${globalSettings.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
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
function renderSectionBlock(section, cfg, formSection, formFields, opts = {}) {
  if (section.visible === false) return '';
  const d = cfg.design;
  const s = cfg.site;

  // Logo
  if (section.id === 'logo' || section.type === 'logo') {
    if (!d.logoUrl) return '';
    return `<div class="sf-logo"><img src="${escapeHtml(d.logoUrl)}" alt="Logo" style="max-width:${escapeHtml(d.logoWidth||'180px')}"></div>`;
  }

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
    ${globalSettings.captchaMode === 'hcaptcha' && globalSettings.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${globalSettings.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
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
    const swId   = `sf_sw_${section.id.replace(/[^a-z0-9]/gi,'_')}`;
    const colors = JSON.stringify(rewards.map(r => r.color || '#e94560'));
    const labels = JSON.stringify(rewards.map(r => r.label || ''));
    const probs  = JSON.stringify(rewards.map(r => +(r.probability || 1)));
    const images = JSON.stringify(rewards.map(r => r.image  || ''));
    const sz     = parseInt(section.canvasSize) || 280;
    const ctr    = sz / 2;
    const rad    = ctr - 10; // inner radius leaving 10px border
    return `<div style="text-align:center;margin:20px 0">
    <canvas id="${swId}" width="${sz}" height="${sz}" style="max-width:100%;display:block;margin:0 auto;border-radius:50%;cursor:pointer"></canvas>
    <button class="sf-btn" style="margin-top:16px;max-width:${sz}px" id="${swId}_btn">${escapeHtml(section.spinButtonText || 'Spin!')}</button>
    <p id="${swId}_res" style="margin-top:12px;font-weight:700;font-size:1.1rem;min-height:1.6em"></p>
  </div>
  <script>(function(){
    var C=document.getElementById('${swId}'),ctx=C.getContext('2d');
    var colors=${colors},labels=${labels},probs=${probs},imageUrls=${images};
    var n=colors.length,TAU=Math.PI*2,arc=TAU/n,rot=0,spinning=false;
    var ctr=${ctr},rad=${rad};
    /* Pre-load segment images — each onload triggers a redraw */
    var imgs=imageUrls.map(function(u,i_){
      if(!u)return null;
      var m=new Image();
      m.onerror=function(){imgs[i_]=null;draw(rot);};
      m.onload=function(){draw(rot);};
      m.src=u;return m;
    });
    function draw(r){
      ctx.clearRect(0,0,C.width,C.height);
      for(var i=0;i<n;i++){
        /* Segment */
        ctx.beginPath();ctx.moveTo(ctr,ctr);ctx.arc(ctr,ctr,rad,r+arc*i,r+arc*(i+1));
        ctx.fillStyle=colors[i];ctx.fill();ctx.strokeStyle='#fff';ctx.lineWidth=2;ctx.stroke();
        ctx.save();ctx.translate(ctr,ctr);ctx.rotate(r+arc*i+arc/2);
        /* Image at ~55% radius (centred on segment midpoint ray) */
        var imgSize=Math.round(rad*0.31);
        if(imgs[i]&&imgs[i].complete&&imgs[i].naturalWidth){
          ctx.drawImage(imgs[i],Math.round(rad*0.4)-imgSize/2,-imgSize/2,imgSize,imgSize);
        }
        /* Label near outer rim */
        ctx.textAlign='right';ctx.fillStyle='#fff';
        ctx.font='bold '+Math.round(rad*0.09)+'px sans-serif';
        ctx.shadowColor='rgba(0,0,0,.5)';ctx.shadowBlur=3;
        ctx.fillText(labels[i],Math.round(rad*0.9),Math.round(rad*0.04));
        ctx.restore();
      }
      /* Centre hub */
      ctx.beginPath();ctx.arc(ctr,ctr,Math.round(rad*0.1),0,TAU);
      ctx.fillStyle='#fff';ctx.fill();ctx.strokeStyle='#ddd';ctx.lineWidth=2;ctx.stroke();
      /* Pointer triangle at top */
      ctx.beginPath();ctx.moveTo(ctr,ctr-rad-2);ctx.lineTo(ctr-9,ctr-rad+14);ctx.lineTo(ctr+9,ctr-rad+14);
      ctx.closePath();ctx.fillStyle='#333';ctx.fill();
    }
    draw(rot);
    document.getElementById('${swId}_btn').addEventListener('click',function(){
      if(spinning)return;spinning=true;
      var total=probs.reduce(function(a,b){return a+b;},0),r=Math.random()*total,sum=0,pick=0;
      for(var i=0;i<n;i++){sum+=probs[i];if(r<=sum){pick=i;break;}}
      var extra=TAU*5+(TAU/n)*(n-pick-0.5),start=null,dur=3500,from=rot;
      document.getElementById('${swId}_res').innerHTML='';
      function anim(ts){
        if(!start)start=ts;
        var p=Math.min((ts-start)/dur,1),e=1-Math.pow(1-p,4),cur=from+extra*e;
        draw(cur);
        if(p<1){requestAnimationFrame(anim);}
        else{
          rot=cur%TAU;spinning=false;
          var imgHtml=imageUrls[pick]?'<img src="'+imageUrls[pick]+'" style="display:block;margin:8px auto 0;max-height:90px;max-width:180px;border-radius:6px;object-fit:contain">':'';
          document.getElementById('${swId}_res').innerHTML='\uD83C\uDF89 '+labels[pick]+imgHtml;
        }
      }
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
      hasStyle ? `border-radius:${radiusStr}` : '',
      style.padding != null ? `padding:${style.padding}px` : (hasStyle ? 'padding:16px 20px' : ''),
      'margin:12px 0',
      cols === 2 ? 'display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start' : '',
    ].filter(Boolean).join(';');
    const renderCntItem = (item) => {
      if (!item) return '';
      if (item.type === 'field') {
        const f = (cfg.fields||[]).find(fd => fd.id === item.fieldId);
        if (!f) return '';
        // prizedraw widget has its own canvas+script — only render in confirmation context
        // to avoid duplicate canvas IDs (main form also iterates cfg.fields)
        if (f.type === 'prizedraw') {
          return opts.confirmationCtx ? renderPrizeDrawWidget(f, cfg) : '';
        }
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
        ${globalSettings.captchaMode === 'hcaptcha' && globalSettings.hcaptchaSiteKey ? `<div class="sf-captcha"><div class="h-captcha" data-sitekey="${globalSettings.hcaptchaSiteKey}" data-theme="light"></div></div>` : ''}
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

function renderPrizeDrawWidget(field, cfg, opts = {}) {
  const prizes = field.prizes || [];
  if (!prizes.length) return '';
  const sz         = parseInt(field.canvasSize) || 280;
  const ctr        = sz / 2;
  const rad        = ctr - 10;
  const labels     = JSON.stringify(prizes.map(r => r.label || ''));
  const colors     = JSON.stringify(prizes.map(r => r.color || '#e94560'));
  const probs      = JSON.stringify(prizes.map(r => +(r.probability || 1)));
  const images     = JSON.stringify(prizes.map(r => r.image || ''));
  const values     = JSON.stringify(prizes.map(r => r.value || ''));
  const iconTypes  = JSON.stringify(prizes.map(r => r.iconType || 'none'));
  const iconChars  = JSON.stringify(prizes.map(r => r.iconChar || ''));
  const iconFonts  = JSON.stringify(prizes.map(r => r.iconFont || ''));
  const iconSizes  = JSON.stringify(prizes.map(r => +(r.iconSize || 20)));
  const accent     = (cfg.design && cfg.design.accentColor) || '#e94560';
  const btnText    = escapeHtml(field.buttonText || 'Spin!');
  const fid        = field.id;
  const auto       = field.autoSpin !== false;
  const imageOnly  = !!field.imageOnlyMode;
  const showRes    = field.showResult !== false;
  const resultTpl  = JSON.stringify(field.resultTemplate || '🎉 {{prize_name}}');
  const presetIdx  = (opts.presetIndex != null) ? opts.presetIndex : -1;
  return `
<div class="sf-prizedraw sf-prizedraw--${escapeHtml(field.drawMethod||'spinwheel')}" id="sf-pd-${fid}" data-field-id="${fid}" style="text-align:center;margin:16px auto;max-width:${sz+40}px">
  <div style="position:relative;display:inline-block">
    <canvas id="sf-pd-canvas-${fid}" width="${sz}" height="${sz}" style="display:block;border-radius:50%;box-shadow:0 4px 24px rgba(0,0,0,0.18)"></canvas>
    <div style="position:absolute;top:-18px;left:50%;transform:translateX(-50%);width:0;height:0;border-left:12px solid transparent;border-right:12px solid transparent;border-top:22px solid ${accent}"></div>
  </div>
  ${!auto ? `<div style="margin-top:16px"><button id="sf-pd-btn-${fid}" class="sf-btn" onclick="sfPdSpin_${fid}(-1)">${btnText}</button></div>` : ''}
  <div id="sf-pd-result-${fid}" style="margin-top:18px;min-height:${showRes?'40px':'0'};display:${showRes?'block':'none'};font-size:1.1rem;font-weight:600;color:${accent}"></div>
</div>
<script>
(function(){
  var labels=${labels},colors=${colors},probs=${probs},images_=${images},values_=${values};
  var iconTypes_=${iconTypes},iconChars_=${iconChars},iconFonts_=${iconFonts},iconSizes_=${iconSizes};
  var sz=${sz},ctr=${ctr},rad=${rad},fid='${fid}',auto=${auto},presetIdx=${presetIdx};
  var imageOnly=${imageOnly},showRes=${showRes},resultTpl=${resultTpl};
  var rotation=0,spinning=false,n=labels.length;
  var imgs=images_.map(function(src,i_){
    if(!src)return null;
    var img=new Image();
    img.onerror=function(){imgs[i_]=null;if(!spinning)draw(rotation);};
    img.onload=function(){if(!spinning)draw(rotation);};
    img.src=src;return img;
  });
  function draw(rot){
    var cvs=document.getElementById('sf-pd-canvas-'+fid);if(!cvs)return;
    var ctx=cvs.getContext('2d'),arc=2*Math.PI/n;
    ctx.clearRect(0,0,sz,sz);
    for(var i=0;i<n;i++){
      var s=rot+i*arc,e=rot+(i+1)*arc;
      ctx.beginPath();ctx.moveTo(ctr,ctr);ctx.arc(ctr,ctr,rad,s,e);ctx.closePath();
      ctx.fillStyle=colors[i]||'#e94560';ctx.fill();
      ctx.strokeStyle='rgba(255,255,255,0.3)';ctx.lineWidth=1;ctx.stroke();
      ctx.save();ctx.translate(ctr,ctr);ctx.rotate(s+arc/2);
      var im=imgs[i],hasImg=im&&im.complete&&im.naturalWidth;
      if(hasImg){
        var isz=imageOnly?rad*0.55:rad*0.28;
        var ix=imageOnly?rad*0.38-isz/2:rad*0.45-isz/2;
        try{ctx.drawImage(im,ix,-isz/2,isz,isz);}catch(e2){}
      }
      if(!imageOnly||!hasImg){
        var itype=iconTypes_[i],ichar=iconChars_[i];
        if(itype&&itype!=='none'&&ichar){
          var ifont=iconFonts_[i]||'',isize=iconSizes_[i]||20;
          ctx.fillStyle='#fff';
          ctx.font=isize+'px '+(ifont?'"'+ifont+'",sans-serif':'sans-serif');
          ctx.textAlign='center';ctx.textBaseline='middle';
          ctx.shadowColor='rgba(0,0,0,0.25)';ctx.shadowBlur=2;
          ctx.fillText(ichar,rad*(hasImg?0.68:0.60),0);
        } else {
          ctx.fillStyle='#fff';ctx.font='bold '+Math.round(sz*0.058)+'px sans-serif';
          ctx.textAlign='left';ctx.textBaseline='middle';
          ctx.shadowColor='rgba(0,0,0,0.25)';ctx.shadowBlur=3;
          ctx.fillText(labels[i]||'',rad*(hasImg?0.68:0.55),0);
        }
      }
      ctx.restore();
    }
    ctx.beginPath();ctx.arc(ctr,ctr,rad*0.13,0,2*Math.PI);
    ctx.fillStyle='#fff';ctx.shadowColor='rgba(0,0,0,0.2)';ctx.shadowBlur=6;ctx.fill();ctx.shadowBlur=0;
  }
  function spin(targetIdx){
    if(spinning)return;spinning=true;
    var btn=document.getElementById('sf-pd-btn-'+fid);if(btn)btn.disabled=true;
    var arc=2*Math.PI/n;
    var target=targetIdx>=0?targetIdx:(function(){var tot=probs.reduce(function(a,b){return a+b},0),r=Math.random()*tot,cum=0;for(var i=0;i<n;i++){cum+=probs[i];if(r<=cum)return i;}return n-1;})();
    var targetAngle=-Math.PI/2-(target*arc+arc/2);
    var extra=5+Math.floor(Math.random()*3);
    var endAngle=rotation+extra*2*Math.PI+((targetAngle-rotation)%(2*Math.PI)+2*Math.PI)%(2*Math.PI);
    var startAngle=rotation,duration=3500,start_=null;
    function ease(t){
      var t1=2/7,t2=3/7;
      if(t<t1){var s=t/t1;return 0.25*s*s;}
      if(t<t2){return 0.25+0.25*(t-t1)/(t2-t1);}
      var s=(t-t2)/(1-t2);return 0.5+0.5*(1-Math.pow(1-s,2));
    }
    function frame(ts){
      if(!start_)start_=ts;
      var p=Math.min((ts-start_)/duration,1);
      rotation=startAngle+(endAngle-startAngle)*ease(p);
      draw(rotation);
      if(p<1){requestAnimationFrame(frame);}
      else{rotation=endAngle;draw(rotation);spinning=false;showResult(target);}
    }
    requestAnimationFrame(frame);
  }
  function showResult(idx){
    if(!showRes)return;
    var el=document.getElementById('sf-pd-result-'+fid);if(!el)return;
    var prizeName=labels[idx]||values_[idx]||'';
    var prizeImgUrl=images_[idx]||'';
    var imgTag=prizeImgUrl?'<img src="'+prizeImgUrl+'" style="width:56px;height:56px;object-fit:cover;border-radius:8px;vertical-align:middle;margin:0 8px 0 4px">':'';
    var html=resultTpl
      .replace(/\{\{prize_name\}\}/g,prizeName)
      .replace(/\{\{prize_image_url\}\}/g,imgTag);
    el.innerHTML=html;el.style.display='block';
  }
  draw(0);
  window['sfPdSpinTo_'+fid]=function(idx){spin(idx>=0?idx:-1);};
  if(auto&&presetIdx>=0){setTimeout(function(){spin(presetIdx);},400);}
})();
<\/script>`;
}

// ── Branded status page (draft / archived) ────────────────────────────────────
// Renders the form's visual design but shows a status message instead of the form.
function renderFormStatusPage(cfg, sharedFonts = []) {
  const d = cfg.design || {};
  const s = cfg.site || {};
  const status = cfg._status || 'draft';
  const isArchived = status === 'archived';
  const heading = isArchived ? 'No Longer Available' : 'Coming Soon';
  const sub = isArchived
    ? 'This form has been archived and is no longer accepting submissions.'
    : 'This form isn\'t available yet. Check back soon.';

  const primaryColor = d.primaryColor || '#1a1a2e';
  const accentColor  = d.accentColor  || '#e94560';
  const bgColor      = d.backgroundColor || '#f8f5f0';
  const textColor    = d.textColor    || '#1a1a2e';
  const bgImage      = d.backgroundImage || '';
  const bgOverlay    = d.backgroundOverlay !== undefined ? d.backgroundOverlay : 0.4;
  const bgOverlayColor = d.backgroundOverlayColor || '#000000';
  const containerWidth = d.containerWidth || '560px';
  const cardPadding  = d.cardPadding  || '48px 40px';
  const cardRadius   = d.cardRadius   || '12px';
  const logoUrl      = d.logoUrl      || '';
  const logoWidth    = d.logoWidth    || '180px';
  const gFont        = d.googleFont   || 'Playfair Display';
  const bFont        = d.bodyFont     || 'Lato';
  const customFonts  = (d.customFonts || []).filter(f => f.name && f.url);

  const googleFontLink = `https://fonts.googleapis.com/css2?family=${encodeURIComponent(gFont)}:wght@400;700&family=${encodeURIComponent(bFont)}:wght@400;700&display=swap`;
  const customFontFaces = customFonts.map(f =>
    `@font-face{font-family:${JSON.stringify(f.name)};src:url(${JSON.stringify(f.url)});font-display:swap;}`).join('');
  const sharedFontFaces = sharedFonts.filter(f => f.name && f.url).map(f =>
    `@font-face{font-family:${JSON.stringify(f.name)};src:url(${JSON.stringify(f.url)});font-display:swap;}`).join('');

  const bodyStyle = bgImage
    ? `background:linear-gradient(${bgOverlayColor}${Math.round(bgOverlay*255).toString(16).padStart(2,'0')},${bgOverlayColor}${Math.round(bgOverlay*255).toString(16).padStart(2,'0')}),url(${JSON.stringify(bgImage)}) center/cover no-repeat fixed;`
    : `background-color:${bgColor};`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(s.title || cfg.name || 'Form')}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="${googleFontLink}">
<style>
${customFontFaces}${sharedFontFaces}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:${JSON.stringify(bFont)},system-ui,sans-serif;${bodyStyle}}
.sf-status-card{background:#fff;border-radius:${cardRadius};padding:${cardPadding};
  max-width:${containerWidth};width:90%;text-align:center;
  box-shadow:0 8px 40px rgba(0,0,0,0.15);}
.sf-status-logo{max-width:${logoWidth};height:auto;margin:0 auto 24px;display:block}
.sf-status-icon{font-size:3rem;margin-bottom:16px;opacity:0.6}
.sf-status-heading{font-family:${JSON.stringify(gFont)},serif;font-size:1.8rem;font-weight:700;
  color:${primaryColor};margin-bottom:12px}
.sf-status-sub{color:${textColor};opacity:0.7;font-size:0.95rem;line-height:1.6;max-width:320px;margin:0 auto}
.sf-status-accent{display:inline-block;width:48px;height:3px;background:${accentColor};
  border-radius:2px;margin:20px auto 0}
</style>
</head>
<body>
<div class="sf-status-card">
  ${logoUrl ? `<img src="${escapeHtml(logoUrl)}" class="sf-status-logo" alt="Logo">` : ''}
  <div class="sf-status-icon">${isArchived ? '📦' : '🚧'}</div>
  <h1 class="sf-status-heading">${escapeHtml(heading)}</h1>
  <p class="sf-status-sub">${escapeHtml(sub)}</p>
  <div class="sf-status-accent"></div>
</div>
</body>
</html>`;
}

function buildPinOverlayHtml(pin, primaryColor) {
  const accent = primaryColor || '#1a1a2e';
  const slug = '${location.pathname.replace(/\\/+$/,"").split("/").pop()}';
  return `<div id="sf-pin-gate" data-pin="${escapeHtml(pin)}" style="position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.75);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)">
  <div style="background:#fff;border-radius:16px;padding:40px 32px;text-align:center;max-width:320px;width:90%;box-shadow:0 24px 80px rgba(0,0,0,0.4)">
    <div style="font-size:2.4rem;margin-bottom:8px">🔒</div>
    <h2 style="font-size:1.25rem;font-weight:700;color:#111;margin-bottom:8px">Test Access</h2>
    <p style="color:#666;font-size:0.875rem;margin-bottom:24px;line-height:1.5">This form is in testing mode. Enter the 4-digit PIN to continue.</p>
    <div id="sf-pin-digits" style="display:flex;gap:10px;justify-content:center;margin-bottom:12px">
      <input class="sf-pin-d" type="text" inputmode="numeric" maxlength="1" style="width:54px;height:62px;font-size:1.8rem;text-align:center;border:2px solid #ddd;border-radius:10px;outline:none;transition:border-color .15s">
      <input class="sf-pin-d" type="text" inputmode="numeric" maxlength="1" style="width:54px;height:62px;font-size:1.8rem;text-align:center;border:2px solid #ddd;border-radius:10px;outline:none;transition:border-color .15s">
      <input class="sf-pin-d" type="text" inputmode="numeric" maxlength="1" style="width:54px;height:62px;font-size:1.8rem;text-align:center;border:2px solid #ddd;border-radius:10px;outline:none;transition:border-color .15s">
      <input class="sf-pin-d" type="text" inputmode="numeric" maxlength="1" style="width:54px;height:62px;font-size:1.8rem;text-align:center;border:2px solid #ddd;border-radius:10px;outline:none;transition:border-color .15s">
    </div>
    <div id="sf-pin-err" style="min-height:18px;font-size:0.82rem;color:#c00;margin-bottom:4px"></div>
    <button id="sf-pin-btn" onclick="sfPinSubmit()" style="margin-top:8px;padding:10px 32px;background:${escapeHtml(accent)};color:#fff;border:none;border-radius:8px;font-size:0.95rem;font-weight:600;cursor:pointer;width:100%">Unlock</button>
  </div>
</div>
<style>
.sf-pin-d:focus{border-color:${escapeHtml(accent)}!important;box-shadow:0 0 0 3px ${escapeHtml(accent)}30}
@keyframes sfPinShake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
</style>
<script>
(function(){
  var gate=document.getElementById('sf-pin-gate');
  if(!gate)return;
  var slug=location.pathname.replace(/\\/+$/,'').split('/').pop()||'form';
  var key='sf_pin_'+slug;
  try{if(sessionStorage.getItem(key)===gate.dataset.pin){gate.remove();return;}}catch(e){}
  var inputs=Array.from(gate.querySelectorAll('.sf-pin-d'));
  inputs.forEach(function(inp,i){
    inp.addEventListener('input',function(){
      inp.value=inp.value.replace(/[^0-9]/g,'').slice(-1);
      if(inp.value&&i<inputs.length-1)inputs[i+1].focus();
      if(inputs.every(function(d){return d.value.length===1;}))sfPinSubmit();
    });
    inp.addEventListener('keydown',function(e){
      if(e.key==='Backspace'&&!inp.value&&i>0){inputs[i-1].focus();inputs[i-1].value='';}
    });
    inp.addEventListener('paste',function(e){
      e.preventDefault();
      var t=(e.clipboardData||window.clipboardData).getData('text').replace(/[^0-9]/g,'').slice(0,4);
      inputs.forEach(function(d,j){d.value=t[j]||'';});
      if(t.length===4)sfPinSubmit();
    });
  });
  inputs[0].focus();
  window.sfPinSubmit=function(){
    var entered=inputs.map(function(d){return d.value;}).join('');
    if(entered.length<4)return;
    if(entered===gate.dataset.pin){
      try{sessionStorage.setItem(key,entered);}catch(e){}
      gate.style.transition='opacity .3s';gate.style.opacity='0';
      setTimeout(function(){gate.remove();},320);
    } else {
      document.getElementById('sf-pin-err').textContent='Incorrect PIN — try again';
      document.getElementById('sf-pin-digits').style.animation='sfPinShake .4s';
      setTimeout(function(){
        document.getElementById('sf-pin-digits').style.animation='';
        inputs.forEach(function(d){d.value='';});
        document.getElementById('sf-pin-err').textContent='';
        inputs[0].focus();
      },500);
    }
  };
})();
<\/script>`;
}

function renderPublicPage(cfg, sharedFonts = [], templates = [], opts = {}) {
  let d = cfg.design || {};
  if (cfg.designTemplateId) {
    const tpl = templates.find(t => t.id === cfg.designTemplateId);
    if (tpl && tpl.design) d = { ...tpl.design, customFonts: (cfg.design || {}).customFonts };
  }
  const s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');

  // Fields placed in custom containers should not also render in the default form section
  const _fieldsInContainers = new Set(
    (cfg.sections||[]).filter(s => s.type === 'container' && s.visible !== false)
      .flatMap(s => (s.items||[]).filter(i => i.type === 'field').map(i => i.fieldId))
  );
  const formFields = cfg.fields.filter(f => !_fieldsInContainers.has(f.id)).map(f => renderFormField(f, cfg)).join('');

  const overlayRgb = hexToRgb(d.backgroundOverlayColor||'#000000');
  const bgStyle = d.backgroundImage
    ? `background: linear-gradient(rgba(${overlayRgb},${d.backgroundOverlay}),rgba(${overlayRgb},${d.backgroundOverlay})), url('${d.backgroundImage}') center/cover no-repeat fixed; color: #fff;`
    : `background: ${d.backgroundColor};`;

  const confirmationBlocks = (cfg.confirmation || []).map(sec => renderSectionBlock(sec, cfg, null, '', {confirmationCtx: true})).join('\n  ');
  // Find prizedraw fields already placed inside a confirmation container so we don't double-render them
  const _pdPlaced = new Set();
  (cfg.confirmation || []).forEach(sec => {
    if (sec.type === 'container') (sec.items || []).forEach(it => { if (it.type === 'field') _pdPlaced.add(it.fieldId); });
  });
  const prizedrawFields = (cfg.fields || []).filter(f => f.type === 'prizedraw');
  // Only append widgets that aren't already placed in a container
  const prizedrawWidgets = prizedrawFields.filter(f => !_pdPlaced.has(f.id)).map(f => renderPrizeDrawWidget(f, cfg)).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(s.title)}</title>
${googleFontTag(cfg, d, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
${(cfg.fields||[]).some(f=>f.type==='iconselect'&&(f.iselItems||[]).some(i=>i.iconType==='material')) ? '<link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">' : ''}
${[...new Set((cfg.fields||[]).filter(f=>f.type==='iconselect').flatMap(f=>(f.iselItems||[]).filter(i=>i.iconType==='text'&&i.iconFont&&!i.iconFont.startsWith('custom:')).map(i=>i.iconFont)))].map(font=>`<link href="https://fonts.googleapis.com/css2?family=${encodeURIComponent(font)}&display=swap" rel="stylesheet">`).join('\n')}
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
  .sf-gdpr-check { display: flex; align-items: flex-start; gap: 9px; font-size: 0.78rem; color: #999; margin-top: 16px; line-height: 1.5; cursor: pointer; text-align: left; }
  .sf-gdpr-check input[type=checkbox] { margin-top: 2px; flex-shrink: 0; width: 15px; height: 15px; accent-color: var(--accent); cursor: pointer; }
  .sf-gdpr-check a { color: var(--accent); }
  .sf-footer { text-align: center; margin-top: 28px; font-size: 0.82rem; color: #aaa; }
  /* ── Cookie Consent Manager ─────────────────────────────────────── */
  #sf-consent{position:fixed;bottom:0;left:0;right:0;background:#1a1a1a;color:#eee;padding:18px 22px;z-index:9999;font-size:0.87rem;line-height:1.5;box-shadow:0 -4px 18px rgba(0,0,0,.4);}
  #sf-consent a{color:var(--accent);}
  #sf-cm-main{display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;}
  #sf-cm-text{flex:1;min-width:200px;}
  #sf-cm-btns{display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap;}
  .sf-cb{border:none;padding:7px 16px;border-radius:4px;cursor:pointer;font-size:0.83rem;white-space:nowrap;font-family:inherit;}
  .sf-cb-primary{background:var(--accent);color:#fff;}
  .sf-cb-ghost{background:transparent;color:#ccc;border:1px solid #555;}
  .sf-cb-link{background:none;border:none;color:#999;font-size:0.8rem;text-decoration:underline;cursor:pointer;padding:0;font-family:inherit;}
  #sf-cm-prefs{display:none;margin-top:14px;border-top:1px solid #333;padding-top:14px;}
  .sf-cat{display:flex;align-items:flex-start;gap:10px;margin-bottom:12px;}
  .sf-cat-info{flex:1;}
  .sf-cat-label{font-weight:600;font-size:0.84rem;color:#eee;}
  .sf-cat-desc{font-size:0.77rem;color:#aaa;margin-top:2px;}
  .sf-cat-always{font-size:0.77rem;color:#777;font-style:italic;align-self:center;white-space:nowrap;}
  .sf-tgl{position:relative;display:inline-block;width:34px;height:18px;flex-shrink:0;margin-top:3px;}
  .sf-tgl input{opacity:0;width:0;height:0;}
  .sf-tgl-s{position:absolute;inset:0;border-radius:18px;background:#444;cursor:pointer;transition:background 180ms;}
  .sf-tgl-s:before{content:'';position:absolute;left:2px;top:2px;width:14px;height:14px;border-radius:50%;background:#fff;transition:transform 180ms;}
  .sf-tgl input:checked+.sf-tgl-s{background:var(--accent);}
  .sf-tgl input:checked+.sf-tgl-s:before{transform:translateX(16px);}
  #sf-cm-save-row{display:flex;justify-content:flex-end;margin-top:6px;}
  #sf-cookie-link{display:none;position:fixed;bottom:6px;right:10px;font-size:0.72rem;color:#aaa;text-decoration:underline;z-index:9998;background:transparent;border:none;cursor:pointer;font-family:inherit;}
  .sf-captcha { margin: 16px 0 4px; display: flex; justify-content: center; }
  @media(max-width:500px){ .sf-card { padding: 32px 20px; } }
  ${sliderPickerCSS(d.accentColor)}
</style>
${globalSettings.captchaMode === 'hcaptcha' && globalSettings.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
</head>
<body>
${opts.testingPin ? buildPinOverlayHtml(opts.testingPin, d.primaryColor) : ''}
<div class="sf-card">
  <form id="sf-form" novalidate>
    <div id="sf-form-content">
      ${(() => { const secs = (cfg.sections||[]).some(s => s.id==='logo') ? cfg.sections : [{id:'logo',type:'logo',visible:true}, ...cfg.sections]; return secs.map(sec => renderSectionBlock(sec, cfg, formSection, formFields)).join('\n  '); })()}
    </div>
    <!-- Anti-bot honeypot — invisible to humans, bots fill it in -->
    <div style="position:absolute;left:-9999px;top:-9999px;height:0;overflow:hidden" aria-hidden="true">
      <label>Leave this empty<input type="text" name="_hp" tabindex="-1" autocomplete="off" value=""></label>
    </div>
    <!-- Anti-bot timing token (server-signed) -->
    <input type="hidden" name="_ts" id="sf-ts" value="${genTimingToken()}">
    <!-- Anti-bot PoW + math challenge fields (populated by JS for flagged IPs) -->
    <input type="hidden" name="_pow_challenge" id="sf-pow-c" value="">
    <input type="hidden" name="_pow_nonce"     id="sf-pow-n" value="">
    <input type="hidden" name="_chal_token"    id="sf-chal-tok" value="">
    <div id="sf-ip-chal" style="display:none;padding:12px 0 4px">
      <label id="sf-chal-q" style="display:block;font-size:0.88rem;font-weight:600;margin-bottom:6px;color:${d.primaryColor||'#1a1a2e'}"></label>
      <input type="number" name="_chal_answer" id="sf-chal-ans" placeholder="Your answer"
             style="width:130px;padding:7px 10px;border:1.5px solid ${d.fieldBorderColor||'#ccc'};border-radius:6px;font-size:0.9rem">
    </div>
  </form>
  ${(confirmationBlocks || prizedrawWidgets) ? `<div id="sf-confirmation" style="display:none">${confirmationBlocks}${prizedrawWidgets}</div>` : ''}
</div>

<!-- "Cookie settings" link — shown after first consent is recorded -->
<button id="sf-cookie-link" aria-label="Manage cookie preferences">Cookie settings</button>

${trackingConfigBlock(s)}

<!-- Cookie Consent Manager -->
<div id="sf-consent" role="dialog" aria-label="Cookie consent" aria-modal="true" style="display:none">
  <div id="sf-cm-main">
    <div id="sf-cm-text">
      ${sanitizeWysiwyg(s.cookieBannerText || 'We use <strong>necessary cookies</strong> to keep this site running. With your consent, analytics and marketing cookies help us improve our service.')}
      <a href="${s.privacyPolicyUrl}" target="_blank" rel="noopener noreferrer">Privacy Policy</a>
    </div>
    <div id="sf-cm-btns">
      <button class="sf-cb sf-cb-link" id="sf-c-manage" aria-expanded="false" aria-controls="sf-cm-prefs">Manage preferences</button>
      <button class="sf-cb sf-cb-ghost" id="sf-c-reject">Necessary only</button>
      <button class="sf-cb sf-cb-primary" id="sf-c-accept">Accept all</button>
    </div>
  </div>
  <div id="sf-cm-prefs" role="region" aria-label="Cookie category preferences">
    <div class="sf-cat">
      <label class="sf-tgl"><input type="checkbox" disabled checked><span class="sf-tgl-s"></span></label>
      <div class="sf-cat-info">
        <div class="sf-cat-label">Necessary</div>
        <div class="sf-cat-desc">Session management, CSRF protection, and your consent record. Required for the site to function correctly.</div>
      </div>
      <span class="sf-cat-always">Always active</span>
    </div>
    <div class="sf-cat" id="sf-cat-analytics">
      <label class="sf-tgl"><input type="checkbox" id="sf-tgl-analytics"><span class="sf-tgl-s"></span></label>
      <div class="sf-cat-info">
        <div class="sf-cat-label">Analytics</div>
        <div class="sf-cat-desc">Measures page visits and signup conversions via Google Analytics (GA4). No personally identifiable information is shared with Google.</div>
      </div>
    </div>
    <div class="sf-cat" id="sf-cat-marketing">
      <label class="sf-tgl"><input type="checkbox" id="sf-tgl-marketing"><span class="sf-tgl-s"></span></label>
      <div class="sf-cat-info">
        <div class="sf-cat-label">Marketing</div>
        <div class="sf-cat-desc">Enables conversion tracking via Meta Pixel to measure advertising campaign effectiveness on Facebook/Instagram.</div>
      </div>
    </div>
    <div id="sf-cm-save-row"><button class="sf-cb sf-cb-primary" id="sf-c-save">Save preferences</button></div>
  </div>
</div>

<script>
// ── Cookie Consent Manager ──────────────────────────────────────────────────
(function(){
  var CKEY='sf_consent', CVER=1;
  // Read tracking config injected by server (absent when no IDs configured)
  var tc={};
  try{var tcEl=document.getElementById('sf-tc');if(tcEl)tc=JSON.parse(tcEl.textContent);}catch(e){}
  var hasGa4=!!(tc.ga4&&tc.ga4.trim()), hasPx=!!(tc.pixel&&tc.pixel.trim());
  var banner=document.getElementById('sf-consent');
  var prefs=document.getElementById('sf-cm-prefs');
  var anaRow=document.getElementById('sf-cat-analytics');
  var mktRow=document.getElementById('sf-cat-marketing');
  var anaTgl=document.getElementById('sf-tgl-analytics');
  var mktTgl=document.getElementById('sf-tgl-marketing');
  var manBtn=document.getElementById('sf-c-manage');
  var acceptBtn=document.getElementById('sf-c-accept');
  var rejectBtn=document.getElementById('sf-c-reject');
  var saveBtn=document.getElementById('sf-c-save');
  var csLink=document.getElementById('sf-cookie-link');
  // Hide category rows for unconfigured providers
  if(anaRow)anaRow.style.display=hasGa4?'':'none';
  if(mktRow)mktRow.style.display=hasPx?'':'none';
  // When no optional cookies are present, simplify to a single acknowledgement
  if(!hasGa4&&!hasPx){
    if(rejectBtn)rejectBtn.style.display='none';
    if(manBtn)manBtn.style.display='none';
    if(acceptBtn)acceptBtn.textContent='OK';
  }
  function readConsent(){
    try{var c=JSON.parse(localStorage.getItem(CKEY)||'null');if(c&&c.v===CVER)return c;}catch(e){}
    return null;
  }
  // Dynamically inject GA4 only after analytics consent is granted
  function injectGa4(id){
    if(document.getElementById('sf-ga4-js'))return;
    window.dataLayer=window.dataLayer||[];
    window.gtag=function(){dataLayer.push(arguments);};
    gtag('js',new Date());gtag('config',id,{send_page_view:true});
    var s=document.createElement('script');
    s.id='sf-ga4-js';s.async=true;
    s.src='https://www.googletagmanager.com/gtag/js?id='+id;
    document.head.appendChild(s);
  }
  // Dynamically inject Meta Pixel only after marketing consent is granted
  function injectPixel(id){
    if(window.fbq)return;
    !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
    fbq('init',id);fbq('track','PageView');
  }
  function applyConsent(c){
    if(c.analytics&&hasGa4)injectGa4(tc.ga4.trim());
    if(c.marketing&&hasPx)injectPixel(tc.pixel.trim());
  }
  function saveAndApply(ana,mkt){
    var c={v:CVER,ts:Date.now(),necessary:true,analytics:!!ana,marketing:!!mkt};
    localStorage.setItem(CKEY,JSON.stringify(c));
    banner.style.display='none';
    if(csLink)csLink.style.display='block';
    applyConsent(c);
  }
  // On load: apply existing consent or show banner
  if(window.self===window.top){
    var existing=readConsent();
    if(existing){applyConsent(existing);if(csLink)csLink.style.display='block';}
    else{banner.style.display='block';}
  }
  if(acceptBtn)acceptBtn.addEventListener('click',function(){saveAndApply(true,true);});
  if(rejectBtn)rejectBtn.addEventListener('click',function(){saveAndApply(false,false);});
  if(saveBtn)saveBtn.addEventListener('click',function(){
    saveAndApply(anaTgl&&anaTgl.checked,mktTgl&&mktTgl.checked);
  });
  if(manBtn)manBtn.addEventListener('click',function(){
    var open=prefs.style.display==='block';
    prefs.style.display=open?'none':'block';
    manBtn.setAttribute('aria-expanded',String(!open));
  });
  // "Cookie settings" link re-opens the banner in preferences mode
  if(csLink)csLink.addEventListener('click',function(){
    var cur=readConsent();
    if(anaTgl)anaTgl.checked=!!(cur&&cur.analytics);
    if(mktTgl)mktTgl.checked=!!(cur&&cur.marketing);
    prefs.style.display='block';
    if(manBtn)manBtn.setAttribute('aria-expanded','true');
    banner.style.display='block';
    banner.scrollIntoView({behavior:'smooth'});
  });
})();

(function(){
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
        if(j.pendingConfirmation){
          if(msg){msg.className='sf-msg success'; msg.textContent='Almost done! Please check your email and click the confirmation link.';msg.style.display='block';}
          if(btn){btn.textContent='\u2713 Check your email';btn.style.opacity='0.7';}
        } else if(conf && conf.children.length > 0){
          if(fc) fc.style.display = 'none';
          conf.style.display = 'block';
          if(j.prizeResult){const fn=window['sfPdSpinTo_'+j.prizeResult.fieldId];if(fn)fn(j.prizeResult.index);}
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

// ── IP flag security — runs on every page load ────────────────────────────────
(async function sfSecurity(){
  try {
    const r = await fetch('/${cfg.slug}/challenge');
    const d = await r.json();
    // Refresh timing token with the server-issued one (fresher than the rendered one)
    const tsEl = document.getElementById('sf-ts');
    if (tsEl && d.ts) tsEl.value = d.ts;
    if (d.blocked) {
      // Level 3: disable the form entirely
      const btn = document.querySelector('#sf-form button[type=submit]');
      const msg = document.getElementById('sf-msg');
      if (btn) { btn.disabled = true; btn.textContent = 'Submissions blocked'; }
      if (msg) { msg.className = 'sf-msg error'; msg.textContent = 'Too many failed attempts from your connection. Please try again later.'; msg.style.display = 'block'; }
      return;
    }
    if (d.level >= 1) {
      // Solve proof-of-work in background (invisible to user, ~50-300ms)
      const challenge = Math.random().toString(36).slice(2) + Date.now().toString(36);
      document.getElementById('sf-pow-c').value = challenge;
      let nonce = 0;
      while (true) {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(challenge + nonce));
        const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
        if (hex.startsWith('000')) { document.getElementById('sf-pow-n').value = nonce; break; }
        nonce++;
        if (nonce % 500 === 0) await new Promise(ok => setTimeout(ok, 0)); // yield to UI
      }
    }
    if (d.level >= 2 && d.challenge) {
      // Show math puzzle above submit button
      const chal = document.getElementById('sf-ip-chal');
      const qEl  = document.getElementById('sf-chal-q');
      const tok  = document.getElementById('sf-chal-tok');
      if (chal && qEl && tok) {
        qEl.textContent = d.challenge.question;
        tok.value = d.challenge.token;
        chal.style.display = 'block';
      }
    }
  } catch(e) { /* fail open — network error should not block legit users */ }
})();
</script>
</body>
</html>`;
}

function renderConfirmPage(cfg, sharedFonts, state) {
  // state: 'confirmed' | 'already' | 'invalid'
  const d = cfg.design || {};
  const s = cfg.site || {};
  const ac = d.accentColor || d.primaryColor || '#e94560';
  const { title: msg, body, icon } = {
    confirmed: { icon: '✅', title: 'Subscription confirmed!', body: `Thank you for confirming. You're now subscribed to <strong>${escapeHtml(s.title || cfg.name)}</strong>.` },
    already:   { icon: '✔',  title: 'Already confirmed',       body: 'Your subscription is already active. No action needed.' },
    invalid:   { icon: '⚠️', title: 'Invalid or expired link', body: 'This confirmation link is invalid or has already been used. Please sign up again if needed.' },
  }[state] || { icon: '⚠️', title: 'Something went wrong', body: 'Please try again or contact support.' };
  const gf = googleFontTag(cfg, null, sharedFonts);
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(msg)} – ${escapeHtml(s.title || cfg.name)}</title>
${gf}
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:${d.backgroundColor||'#f8f5f0'};font-family:'${d.bodyFont||'Lato'}',sans-serif;padding:24px}
  .card{background:${d.cardBg||'#fff'};border-radius:${d.cardRadius||'12px'};
    padding:48px 40px;max-width:480px;width:100%;text-align:center;
    box-shadow:0 4px 32px rgba(0,0,0,0.08)}
  .icon{font-size:3rem;margin-bottom:16px}
  h1{font-size:1.5rem;font-weight:700;color:${d.textColor||'#1a1a2e'};margin-bottom:12px}
  p{color:${d.textColor||'#555'};line-height:1.6;font-size:0.95rem}
  .btn{display:inline-block;margin-top:24px;background:${ac};color:#fff;text-decoration:none;
    padding:11px 28px;border-radius:${d.buttonRadius||'4px'};font-weight:600;font-size:0.9rem}
</style>
</head><body>
<div class="card">
  <div class="icon">${icon}</div>
  <h1>${escapeHtml(msg)}</h1>
  <p>${body}</p>
  ${state === 'confirmed' ? `<a class="btn" href="/${cfg.slug}">Go to homepage</a>` : ''}
</div>
</body></html>`;
}

function renderUnsubscribePage(cfg, { subscriber, allSubs = [], token, message, success } = {}, sharedFonts = []) {
  const d = cfg.design;
  const ac = d.accentColor || d.primaryColor || '#c94b39';
  const pc = d.primaryColor || '#1a1a2e';
  const bg = d.backgroundColor || '#f4f4f4';
  const font = d.bodyFont || 'Inter';
  const hfont = d.googleFont || d.headingFont || font;
  const formBase = `/${cfg.slug}/unsubscribe/${token||''}`;
  const btnPrimary = `display:block;width:100%;padding:11px 20px;background:${ac};color:#fff;border:none;border-radius:8px;font-size:0.92rem;font-family:'${font}',sans-serif;font-weight:600;cursor:pointer;margin-bottom:8px;transition:opacity 120ms;`;
  const btnDanger  = `display:block;width:100%;padding:11px 20px;background:#c0392b;color:#fff;border:none;border-radius:8px;font-size:0.92rem;font-family:'${font}',sans-serif;font-weight:600;cursor:pointer;margin-bottom:0;transition:opacity 120ms;`;
  const btnGhost   = `background:none;border:1.5px solid ${ac};color:${ac};border-radius:6px;padding:5px 14px;font-size:0.8rem;cursor:pointer;font-family:'${font}',sans-serif;white-space:nowrap;`;

  const subRows = allSubs.map(s => `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #eee;">
      <span style="font-size:0.87rem;color:#444;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(s.form_slug)}</span>
      <form method="POST" action="${formBase}" style="margin:0;flex-shrink:0">
        <input type="hidden" name="action" value="unsub-one">
        <input type="hidden" name="form_slug" value="${escapeHtml(s.form_slug)}">
        <button type="submit" style="${btnGhost}">Unsubscribe</button>
      </form>
    </div>`).join('');

  const bodyContent = subscriber ? `
    <p style="font-size:0.85rem;color:#777;margin:0 0 16px">Signed in as <strong style="color:#444">${escapeHtml(subscriber.email)}</strong></p>
    ${allSubs.length ? `
      <div style="margin-bottom:20px;border-top:1px solid #eee">${subRows}</div>
      <form method="POST" action="${formBase}" style="margin-bottom:8px">
        <input type="hidden" name="action" value="unsub-all">
        <button type="submit" style="${btnPrimary}">Unsubscribe from all forms</button>
      </form>` : `<p style="color:#777;font-size:0.9rem;margin-bottom:20px">You have no active subscriptions.</p>`}
    <form method="POST" action="${formBase}" onsubmit="return confirm('Permanently delete all your data? This cannot be undone.')">
      <input type="hidden" name="action" value="delete-all">
      <button type="submit" style="${btnDanger}">Delete all my data</button>
    </form>` :
    `<p style="color:#777;font-size:0.9rem">Subscription not found or already processed.</p>`;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Manage Subscriptions · ${escapeHtml(cfg.site.title || 'SignFlow')}</title>
${googleFontTag(cfg, null, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'${font}',sans-serif;background:${bg};min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 16px;}
  .card{background:#fff;border-radius:14px;padding:36px 32px;max-width:480px;width:100%;box-shadow:0 8px 40px rgba(0,0,0,.12);}
  h1{font-family:'${hfont}',serif;color:${pc};font-size:1.5rem;margin-bottom:8px;}
  .sub-title{font-size:0.8rem;color:#aaa;margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid #eee;}
  .msg-ok{color:#155724;background:#d4edda;padding:12px 14px;border-radius:6px;font-size:0.87rem;margin-bottom:16px;}
  .msg-err{color:#721c24;background:#f8d7da;padding:12px 14px;border-radius:6px;font-size:0.87rem;margin-bottom:16px;}
  a{color:${ac};}
  button:hover{opacity:.88;}
</style></head><body>
<div class="card">
  <h1>Manage subscriptions</h1>
  <p class="sub-title">${escapeHtml(cfg.site.title || cfg.slug)}</p>
  ${message ? `<div class="${success ? 'msg-ok' : 'msg-err'}">${escapeHtml(message)}</div>` : ''}
  ${bodyContent}
  <p style="margin-top:20px;font-size:0.8rem"><a href="/">← Back to home</a></p>
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
  <h2>7. Cookies &amp; Tracking</h2>
  <p>We use a cookie consent manager to control what runs in your browser. Cookies are grouped into three categories:</p>
  <ul>
    <li><strong>Necessary</strong> — Always active. These include your session cookie, a CSRF security token, and the localStorage record of your cookie preferences. Without them the site cannot function.</li>
    <li><strong>Analytics</strong> — Only loaded with your consent. If enabled, Google Analytics (GA4) measures page visits and signup conversions. No personally identifiable information is shared with Google.</li>
    <li><strong>Marketing</strong> — Only loaded with your consent. If enabled, Meta Pixel measures advertising campaign effectiveness. Data is processed by Meta Platforms Ireland Ltd.</li>
  </ul>
  <p>You can review or withdraw your consent at any time using the <strong>Cookie settings</strong> link at the bottom of the page. Withdrawing consent does not affect the lawfulness of processing carried out before withdrawal.</p>
  <h2>8. Contact</h2>
  <p>For any data-related requests, please contact the site administrator.</p>
  <p style="margin-top:32px"><a href="/">← Back</a></p>`}
</div></body></html>`;
}

function renderEmbedPage(cfg, sharedFonts = [], templates = [], opts = {}) {
  let d = cfg.design || {};
  if (cfg.designTemplateId) {
    const tpl = templates.find(t => t.id === cfg.designTemplateId);
    if (tpl && tpl.design) d = { ...tpl.design, customFonts: (cfg.design || {}).customFonts };
  }
  const s = cfg.site;
  const formSection = cfg.sections.find(sec => sec.id === 'form');

  const _fieldsInContainers = new Set(
    (cfg.sections||[]).filter(s => s.type === 'container' && s.visible !== false)
      .flatMap(s => (s.items||[]).filter(i => i.type === 'field').map(i => i.fieldId))
  );
  const formFields = cfg.fields.filter(f => !_fieldsInContainers.has(f.id)).map(f => renderFormField(f, cfg)).join('');
  const confirmationBlocks = (cfg.confirmation || []).map(sec => renderSectionBlock(sec, cfg, null, '', {confirmationCtx: true})).join('\n  ');
  const _pdPlaced = new Set();
  (cfg.confirmation || []).forEach(sec => {
    if (sec.type === 'container') (sec.items || []).forEach(it => { if (it.type === 'field') _pdPlaced.add(it.fieldId); });
  });
  const prizedrawFields = (cfg.fields || []).filter(f => f.type === 'prizedraw');
  const prizedrawWidgets = prizedrawFields.filter(f => !_pdPlaced.has(f.id)).map(f => renderPrizeDrawWidget(f, cfg)).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${s.title}</title>
${googleFontTag(cfg, d, sharedFonts)}
${customFontFaceCSS(cfg, sharedFonts)}
${(cfg.fields||[]).some(f=>f.type==='iconselect'&&(f.iselItems||[]).some(i=>i.iconType==='material')) ? '<link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">' : ''}
${[...new Set((cfg.fields||[]).filter(f=>f.type==='iconselect').flatMap(f=>(f.iselItems||[]).filter(i=>i.iconType==='text'&&i.iconFont&&!i.iconFont.startsWith('custom:')).map(i=>i.iconFont)))].map(font=>`<link href="https://fonts.googleapis.com/css2?family=${encodeURIComponent(font)}&display=swap" rel="stylesheet">`).join('\n')}
${globalSettings.captchaMode === 'hcaptcha' && globalSettings.hcaptchaSiteKey ? `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}
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
  .sf-gdpr-check { display: flex; align-items: flex-start; gap: 8px; font-size: 0.74rem; color: #aaa; margin-top: 12px; line-height: 1.5; cursor: pointer; text-align: left; }
  .sf-gdpr-check input[type=checkbox] { margin-top: 2px; flex-shrink: 0; width: 14px; height: 14px; accent-color: var(--accent); cursor: pointer; }
  .sf-gdpr-check a { color: var(--accent); }
  .sf-footer { text-align: center; margin-top: 20px; font-size: 0.78rem; color: #bbb; }
  .sf-captcha { margin: 12px 0 4px; display: flex; justify-content: center; }
  ${sliderPickerCSS(d.accentColor)}
</style>
</head>
<body>
${opts.testingPin ? buildPinOverlayHtml(opts.testingPin, d.primaryColor) : ''}
  <form id="sf-form" novalidate>
    <div id="sf-form-content">
      ${(() => { const secs = (cfg.sections||[]).some(s => s.id==='logo') ? cfg.sections : [{id:'logo',type:'logo',visible:true}, ...cfg.sections]; return secs.map(sec => renderSectionBlock(sec, cfg, formSection, formFields)).join('\n  '); })()}
    </div>
  </form>
  ${(confirmationBlocks || prizedrawWidgets) ? `<div id="sf-confirmation" style="display:none">${confirmationBlocks}${prizedrawWidgets}</div>` : ''}

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
        if(j.pendingConfirmation){
          if(msg){msg.className='sf-msg success'; msg.textContent='Almost done! Please check your email and click the confirmation link.';msg.style.display='block';}
          if(btn){btn.textContent='\u2713 Check your email';btn.style.opacity='0.7';}
          reportHeight();
        } else if(conf && conf.children.length > 0){
          if(fc) fc.style.display = 'none';
          conf.style.display = 'block';
          window.parent.postMessage({ type: 'sf-success', slug: '${cfg.slug}' }, '*');
          if(window.gtag) gtag('event','generate_lead',{form_id:'${cfg.slug}'});
          if(window.fbq) fbq('track','Lead');
          reportHeight();
        } else {
          if(msg){msg.className='sf-msg success'; msg.textContent=${JSON.stringify((formSection && formSection.submitSuccessMessage) || "Thank you! You're subscribed.")};msg.style.display='block';}
          form.reset();
          window.parent.postMessage({ type: 'sf-success', slug: '${cfg.slug}' }, '*');
          if(window.gtag) gtag('event','generate_lead',{form_id:'${cfg.slug}'});
          if(window.fbq) fbq('track','Lead');
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
      var slug = e.data.slug || '';
      // Fire into parent page's existing GA4 (if present)
      if (w.gtag) w.gtag('event', 'generate_lead', { form_id: slug });
      // Fire into parent page's existing Meta Pixel (if present)
      if (w.fbq) w.fbq('track', 'Lead');
      // Custom DOM event — developers can listen:
      // window.addEventListener('signflow:success', e => console.log(e.detail.slug))
      w.dispatchEvent(new CustomEvent('signflow:success', { detail: { slug: slug } }));
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
  await loadGlobalSettings();
  await initAuth0();
  app.listen(PORT, () => {
    console.log(`\n✅ SignFlow running at http://localhost:${PORT}`);
    console.log(`   Admin panel : http://localhost:${PORT}/admin`);
    console.log(`   Auth login  : http://localhost:${PORT}/auth/login`);
    console.log(`   Auth0 domain: ${AUTH0_DOMAIN || '(not configured)'}\n`);
  });
})();
