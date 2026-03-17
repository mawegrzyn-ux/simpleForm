'use strict';
// ── Integrations router ────────────────────────────────────────────────────────
// Mounted at /api/admin/integrations by server.js (adminAuth + csrfCheck applied there)
// req.pool  — pg Pool injected by server.js
// req.app.locals._helpReady — Voyage AI readiness flag
// req.app.locals.s3 — AWS S3 client
// req.app.locals.S3_BUCKET — bucket name
// req.app.locals.transporter — nodemailer transporter
// req.app.locals.AUTH0_DOMAIN — Auth0 domain

const { Router } = require('express');
const https = require('https');
const router = Router();

// Portal URLs shown as external links on each card
const PORTALS = {
  anthropic:  'https://console.anthropic.com',
  voyage:     'https://dash.voyageai.com',
  s3:         'https://s3.console.aws.amazon.com',
  auth0:      'https://manage.auth0.com',
  smtp:       'https://myaccount.google.com/security',
  mailchimp:  'https://login.mailchimp.com',
  klaviyo:    'https://www.klaviyo.com/login',
  hubspot:    'https://app.hubspot.com',
  salesforce: 'https://login.salesforce.com',
  postgres:   'https://lightsail.aws.amazon.com',
};

// ── Helper: lightweight HTTP GET with timeout ─────────────────────────────────
function httpGet(url, headers = {}, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      { hostname: u.hostname, path: u.pathname + u.search, headers, method: 'GET' },
      res => {
        let body = '';
        res.on('data', d => { body += d; });
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }
    );
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ── Individual service checks ─────────────────────────────────────────────────
async function checkAnthropic() {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return { status: 'unconfigured', detail: 'No API key in .env' };
  const t = Date.now();
  try {
    const r = await httpGet('https://api.anthropic.com/v1/models',
      { 'x-api-key': key, 'anthropic-version': '2023-06-01' });
    if (r.status === 200) return { status: 'ok', detail: 'claude-haiku-4-5', latencyMs: Date.now() - t };
    const err = JSON.parse(r.body);
    return { status: 'error', detail: err?.error?.message || `HTTP ${r.status}` };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkVoyage(app) {
  const key = process.env.VOYAGE_API_KEY;
  if (!key) return { status: 'unconfigured', detail: 'No VOYAGE_API_KEY in .env' };
  const ready = app.locals._helpReady;
  const chunks = app.locals._helpChunks?.length || 0;
  if (!ready) return { status: 'error', detail: 'Embedding not ready yet' };
  return { status: 'ok', detail: `${chunks} sections embedded` };
}

async function checkS3(app) {
  const bucket = process.env.S3_BUCKET;
  const s3 = app.locals.s3;
  if (!bucket || !s3) return { status: 'unconfigured', detail: 'S3_BUCKET not configured' };
  const t = Date.now();
  try {
    const { HeadBucketCommand } = require('@aws-sdk/client-s3');
    await s3.send(new HeadBucketCommand({ Bucket: bucket }));
    return { status: 'ok', detail: bucket, latencyMs: Date.now() - t };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkAuth0() {
  const domain = process.env.AUTH0_DOMAIN;
  if (!domain) return { status: 'unconfigured', detail: 'AUTH0_DOMAIN not configured' };
  const t = Date.now();
  try {
    const r = await httpGet(`https://${domain}/.well-known/openid-configuration`);
    if (r.status === 200) return { status: 'ok', detail: domain, latencyMs: Date.now() - t };
    return { status: 'error', detail: `HTTP ${r.status}` };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkSmtp(app) {
  const host = process.env.SMTP_HOST;
  const transporter = app.locals.transporter;
  if (!host || !transporter) return { status: 'unconfigured', detail: 'SMTP_HOST not configured' };
  const t = Date.now();
  try {
    await transporter.verify();
    return { status: 'ok', detail: host, latencyMs: Date.now() - t };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkMailchimp(pool) {
  try {
    const { rows } = await pool.query(`SELECT value->'integrations'->>'mailchimp_key' AS k FROM global_settings WHERE id=1`);
    const key = rows[0]?.k;
    if (!key) return { status: 'unconfigured', detail: 'Not configured' };
    const dc = key.split('-').pop();
    const t = Date.now();
    const r = await httpGet(`https://${dc}.api.mailchimp.com/3.0/ping`,
      { Authorization: `Basic ${Buffer.from('anystring:'+key).toString('base64')}` });
    if (r.status === 200) return { status: 'ok', detail: 'Connected', latencyMs: Date.now() - t };
    return { status: 'error', detail: `HTTP ${r.status}` };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkKlaviyo(pool) {
  try {
    const { rows } = await pool.query(`SELECT value->'integrations'->>'klaviyo_key' AS k FROM global_settings WHERE id=1`);
    const key = rows[0]?.k;
    if (!key) return { status: 'unconfigured', detail: 'Not configured' };
    const t = Date.now();
    const r = await httpGet('https://a.klaviyo.com/api/accounts/',
      { Authorization: `Klaviyo-API-Key ${key}`, revision: '2024-02-15' });
    if (r.status === 200) return { status: 'ok', detail: 'Connected', latencyMs: Date.now() - t };
    return { status: 'error', detail: `HTTP ${r.status}` };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkHubSpot(pool) {
  try {
    const { rows } = await pool.query(`SELECT value->'integrations'->>'hubspot_token' AS k FROM global_settings WHERE id=1`);
    const token = rows[0]?.k;
    if (!token) return { status: 'unconfigured', detail: 'Not configured' };
    const t = Date.now();
    const r = await httpGet('https://api.hubapi.com/crm/v3/objects/contacts?limit=1',
      { Authorization: `Bearer ${token}` });
    if (r.status === 200) return { status: 'ok', detail: 'Connected', latencyMs: Date.now() - t };
    return { status: 'error', detail: `HTTP ${r.status}` };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkSalesforce(pool) {
  try {
    const { rows } = await pool.query(`SELECT value->'integrations'->>'salesforce_instance' AS inst, value->'integrations'->>'salesforce_token' AS tok FROM global_settings WHERE id=1`);
    const { inst, tok } = rows[0] || {};
    if (!inst || !tok) return { status: 'unconfigured', detail: 'Not configured' };
    const t = Date.now();
    const r = await httpGet(`https://${inst}/services/data/`,
      { Authorization: `Bearer ${tok}` });
    if (r.status === 200) return { status: 'ok', detail: inst, latencyMs: Date.now() - t };
    return { status: 'error', detail: `HTTP ${r.status}` };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

async function checkPostgres(pool) {
  const t = Date.now();
  try {
    await pool.query('SELECT 1');
    return { status: 'ok', detail: 'Connected', latencyMs: Date.now() - t };
  } catch(e) { return { status: 'error', detail: e.message }; }
}

// ── Run one named check ───────────────────────────────────────────────────────
async function runCheck(id, pool, app) {
  switch (id) {
    case 'anthropic':  return checkAnthropic();
    case 'voyage':     return checkVoyage(app);
    case 's3':         return checkS3(app);
    case 'auth0':      return checkAuth0();
    case 'smtp':       return checkSmtp(app);
    case 'mailchimp':  return checkMailchimp(pool);
    case 'klaviyo':    return checkKlaviyo(pool);
    case 'hubspot':    return checkHubSpot(pool);
    case 'salesforce': return checkSalesforce(pool);
    case 'postgres':   return checkPostgres(pool);
    default: return { status: 'error', detail: 'Unknown service' };
  }
}

const SERVICE_META = [
  { id: 'anthropic',  name: 'Anthropic (McFry AI)',  icon: 'smart_toy' },
  { id: 'voyage',     name: 'Voyage AI',              icon: 'travel_explore' },
  { id: 's3',         name: 'Amazon S3',              icon: 'cloud' },
  { id: 'postgres',   name: 'PostgreSQL',             icon: 'storage' },
  { id: 'auth0',      name: 'Auth0',                  icon: 'lock' },
  { id: 'smtp',       name: 'SMTP / Email',           icon: 'mail' },
  { id: 'mailchimp',  name: 'Mailchimp',              icon: 'campaign' },
  { id: 'klaviyo',    name: 'Klaviyo',                icon: 'campaign' },
  { id: 'hubspot',    name: 'HubSpot',                icon: 'hub' },
  { id: 'salesforce', name: 'Salesforce',             icon: 'cloud_sync' },
];

// ── GET /status — all services in parallel ────────────────────────────────────
router.get('/status', async (req, res) => {
  const pool = req.pool;
  const app  = req.app;
  const now  = new Date().toISOString();
  const results = await Promise.allSettled(
    SERVICE_META.map(svc => runCheck(svc.id, pool, app))
  );
  const services = SERVICE_META.map((svc, i) => ({
    id:          svc.id,
    name:        svc.name,
    icon:        svc.icon,
    portal:      PORTALS[svc.id] || null,
    lastChecked: now,
    ...(results[i].status === 'fulfilled' ? results[i].value : { status: 'error', detail: results[i].reason?.message || 'Check failed' })
  }));
  res.json({ services });
});

// ── POST /test/:service — single service re-check ─────────────────────────────
router.post('/test/:service', async (req, res) => {
  const id = req.params.service;
  if (!SERVICE_META.find(s => s.id === id))
    return res.status(400).json({ error: 'Unknown service' });
  try {
    const result = await runCheck(id, req.pool, req.app);
    res.json({ id, lastChecked: new Date().toISOString(), ...result });
  } catch(e) {
    res.json({ id, status: 'error', detail: e.message });
  }
});

// ── GET /config — masked integration keys ─────────────────────────────────────
router.get('/config', async (req, res) => {
  try {
    const { rows } = await req.pool.query(`SELECT value->'integrations' AS cfg FROM global_settings WHERE id=1`);
    const cfg = rows[0]?.cfg || {};
    // Mask key values — only show last 4 chars
    const mask = v => v ? '••••••••' + String(v).slice(-4) : '';
    res.json({
      mailchimp_key:       mask(cfg.mailchimp_key),
      klaviyo_key:         mask(cfg.klaviyo_key),
      hubspot_token:       mask(cfg.hubspot_token),
      salesforce_instance: cfg.salesforce_instance || '',
      salesforce_token:    mask(cfg.salesforce_token),
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PATCH /config — save integration keys ─────────────────────────────────────
router.patch('/config', async (req, res) => {
  const allowed = ['mailchimp_key','klaviyo_key','hubspot_token','salesforce_instance','salesforce_token'];
  const patch = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) patch[k] = req.body[k];
  }
  if (!Object.keys(patch).length) return res.status(400).json({ error: 'No valid fields' });
  try {
    // Merge into existing integrations object
    await req.pool.query(
      `UPDATE global_settings
       SET value = jsonb_set(COALESCE(value,'{}'), '{integrations}',
         COALESCE(value->'integrations','{}') || $1::jsonb)
       WHERE id=1`,
      [JSON.stringify(patch)]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
