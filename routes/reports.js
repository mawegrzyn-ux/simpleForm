'use strict';
// ── Reports router ─────────────────────────────────────────────────────────────
// Mounted at /api/admin/reports by server.js (adminAuth + csrfCheck applied there)
// req.pool — pg Pool injected by server.js

const { Router } = require('express');
const router = Router();

// ── Helpers ───────────────────────────────────────────────────────────────────
function periodToInterval(period) {
  switch (period) {
    case '90d':  return '90 days';
    case '1y':   return '1 year';
    default:     return '30 days';
  }
}

// ── GET /summary — platform-wide totals ───────────────────────────────────────
router.get('/summary', async (req, res) => {
  try {
    const pool = req.pool;
    const [forms, subs, emails, submissions] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS n FROM forms WHERE status != 'archived'`),
      pool.query(`SELECT COUNT(*)::int AS n FROM subscribers WHERE status='active'`),
      pool.query(`SELECT COUNT(*)::int AS n FROM email_log WHERE status='sent'`),
      pool.query(`SELECT COALESCE(SUM(count),0)::int AS n FROM analytics WHERE key='submit'`),
    ]);
    res.json({
      forms:       forms.rows[0].n,
      subscribers: subs.rows[0].n,
      emailsSent:  emails.rows[0].n,
      submissions: submissions.rows[0].n,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GET /subscribers — daily new subscriber counts ────────────────────────────
router.get('/subscribers', async (req, res) => {
  const interval = periodToInterval(req.query.period);
  try {
    const { rows } = await req.pool.query(
      `SELECT DATE(subscribed_at) AS day, COUNT(*)::int AS count
       FROM subscribers
       WHERE subscribed_at >= NOW() - INTERVAL '${interval}'
       GROUP BY day ORDER BY day ASC`
    );
    res.json({ rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GET /forms — per-form performance ─────────────────────────────────────────
router.get('/forms', async (req, res) => {
  try {
    const pool = req.pool;
    const [forms, analytics, subs] = await Promise.all([
      pool.query(`SELECT slug, name FROM forms WHERE status != 'archived' ORDER BY name`),
      pool.query(`SELECT form_slug, key, count FROM analytics WHERE key IN ('visit','submit','error')`),
      pool.query(`SELECT form_slug, COUNT(*)::int AS n FROM subscribers WHERE status='active' GROUP BY form_slug`),
    ]);
    const analyticsMap = {};
    for (const r of analytics.rows) {
      if (!analyticsMap[r.form_slug]) analyticsMap[r.form_slug] = {};
      analyticsMap[r.form_slug][r.key] = Number(r.count);
    }
    const subsMap = {};
    for (const r of subs.rows) subsMap[r.form_slug] = r.n;

    const rows = forms.rows.map(f => {
      const a = analyticsMap[f.slug] || {};
      const visits  = a.visit  || 0;
      const submits = a.submit || 0;
      const errors  = a.error  || 0;
      const conv = visits > 0 ? Math.round((submits / visits) * 100) : 0;
      return {
        slug: f.slug, name: f.name,
        visits, submissions: submits, errors,
        conversionPct: conv,
        subscribers: subsMap[f.slug] || 0,
      };
    });
    res.json({ rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GET /email — email metrics per form ───────────────────────────────────────
router.get('/email', async (req, res) => {
  const interval = periodToInterval(req.query.period);
  try {
    const { rows } = await req.pool.query(
      `SELECT
         form_slug,
         COUNT(*)::int                                        AS sent,
         SUM(CASE WHEN open_count > 0 THEN 1 ELSE 0 END)::int AS opened,
         SUM(CASE WHEN click_count > 0 THEN 1 ELSE 0 END)::int AS clicked,
         SUM(CASE WHEN status='bounced' THEN 1 ELSE 0 END)::int AS bounced
       FROM email_log
       WHERE sent_at >= NOW() - INTERVAL '${interval}'
         AND status = 'sent'
       GROUP BY form_slug ORDER BY form_slug`
    );
    const withPct = rows.map(r => ({
      ...r,
      openPct:  r.sent > 0 ? Math.round((r.opened  / r.sent) * 100) : 0,
      clickPct: r.sent > 0 ? Math.round((r.clicked / r.sent) * 100) : 0,
    }));
    res.json({ rows: withPct });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GET /export — CSV of form performance summary ─────────────────────────────
router.get('/export', async (req, res) => {
  try {
    const pool = req.pool;
    const [forms, analytics, subs] = await Promise.all([
      pool.query(`SELECT slug, name FROM forms WHERE status != 'archived' ORDER BY name`),
      pool.query(`SELECT form_slug, key, count FROM analytics WHERE key IN ('visit','submit','error')`),
      pool.query(`SELECT form_slug, COUNT(*)::int AS n FROM subscribers WHERE status='active' GROUP BY form_slug`),
    ]);
    const analyticsMap = {};
    for (const r of analytics.rows) {
      if (!analyticsMap[r.form_slug]) analyticsMap[r.form_slug] = {};
      analyticsMap[r.form_slug][r.key] = Number(r.count);
    }
    const subsMap = {};
    for (const r of subs.rows) subsMap[r.form_slug] = r.n;

    const lines = ['Form,Slug,Visits,Submissions,Conversion %,Active Subscribers,Errors'];
    for (const f of forms.rows) {
      const a = analyticsMap[f.slug] || {};
      const visits  = a.visit  || 0;
      const submits = a.submit || 0;
      const conv    = visits > 0 ? Math.round((submits / visits) * 100) : 0;
      lines.push(`"${f.name}",${f.slug},${visits},${submits},${conv}%,${subsMap[f.slug]||0},${a.error||0}`);
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="signflow-report.csv"');
    res.send(lines.join('\n'));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
