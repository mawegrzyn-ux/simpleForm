/**
 * SignFlow — One-time JSON → PostgreSQL + S3 migration script
 *
 * Run ONCE after provisioning the PostgreSQL database and S3 bucket:
 *   node scripts/import-json-to-pg.js
 *
 * Prerequisites:
 *   - DATABASE_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, S3_BUCKET in .env
 *   - npm install already run (pg, @aws-sdk/client-s3, @aws-sdk/lib-storage must be installed)
 *   - JSON data files must still exist in data/ directory
 *   - Existing uploads must still be in public/uploads/
 *
 * What it does:
 *   1. Creates all tables (idempotent — safe to run on an empty DB)
 *   2. Imports every form config + subscribers + analytics
 *   3. Uploads every media file to S3 and records the new URL in the media table
 *   4. Uploads every custom font to S3 and records in the fonts table
 *   5. Imports design templates
 *   6. Prints a summary of counts
 *
 * Idempotency: Uses INSERT ... ON CONFLICT DO NOTHING wherever possible.
 * Re-running is safe but may skip already-imported records.
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const fs   = require('fs');
const path = require('path');
const { Pool } = require('pg');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const pool      = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const s3        = new S3Client({ region: process.env.AWS_REGION || 'us-east-1' });
const S3_BUCKET = process.env.S3_BUCKET || '';

const DATA_DIR    = path.join(__dirname, '..', 'data');
const UPLOADS_DIR = path.join(__dirname, '..', 'public', 'uploads');

// ── Counters ──────────────────────────────────────────────────────────────────
const counts = { forms: 0, subscribers: 0, media: 0, fonts: 0, templates: 0, analytics: 0, errors: 0 };

function readJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch(e) { console.error(`⚠ Failed to read ${filePath}:`, e.message); counts.errors++; return null; }
}

async function uploadToS3(localPath, s3Key, contentType) {
  const content = fs.readFileSync(localPath);
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: s3Key,
    Body: content,
    ContentType: contentType || 'application/octet-stream',
  }));
  return `https://${S3_BUCKET}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com/${s3Key}`;
}

function mimeFromExt(ext) {
  const map = { '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.png':'image/png',
    '.gif':'image/gif', '.webp':'image/webp', '.svg':'image/svg+xml',
    '.woff':'font/woff', '.woff2':'font/woff2', '.ttf':'font/ttf', '.otf':'font/otf' };
  return map[ext.toLowerCase()] || 'application/octet-stream';
}

// ── DDL ───────────────────────────────────────────────────────────────────────
async function createTables(client) {
  await client.query(`
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
  console.log('✔ Tables created / verified');
}

// ── Import forms ──────────────────────────────────────────────────────────────
async function importForms(client) {
  const formsDir = path.join(DATA_DIR, 'forms');
  if (!fs.existsSync(formsDir)) {
    console.warn('⚠ data/forms/ directory not found — skipping form import');
    return;
  }
  const indexData = readJson(path.join(DATA_DIR, 'forms-index.json')) || [];
  for (const { slug, name, createdAt } of indexData) {
    const cfgPath = path.join(formsDir, slug + '.json');
    const cfg = readJson(cfgPath);
    if (!cfg) continue;
    try {
      await client.query(
        `INSERT INTO forms(slug, name, created_at, config)
         VALUES($1, $2, $3, $4)
         ON CONFLICT(slug) DO NOTHING`,
        [slug, name || cfg.name || slug, createdAt || new Date().toISOString(), cfg]
      );
      counts.forms++;
      console.log(`  ✔ Form: ${slug}`);
    } catch(e) { console.error(`  ✖ Form ${slug}:`, e.message); counts.errors++; }
  }
}

// ── Import subscribers ────────────────────────────────────────────────────────
async function importSubscribers(client) {
  const formsDir = path.join(DATA_DIR, 'forms');
  if (!fs.existsSync(formsDir)) return;
  const slugs = fs.readdirSync(formsDir).map(f => f.replace('.json', ''));
  for (const slug of slugs) {
    const subs = readJson(path.join(DATA_DIR, `subscribers-${slug}.json`)) || [];
    let n = 0;
    for (const s of subs) {
      try {
        await client.query(
          `INSERT INTO subscribers
           (id, form_slug, email, status, subscribed_at, unsubscribed_at,
            unsubscribe_token, consent_given, consent_timestamp, ip_address,
            custom_fields, exported, exported_at)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
           ON CONFLICT(form_slug, email) DO NOTHING`,
          [
            s.id, slug, s.email, s.status || 'active',
            s.subscribedAt || new Date().toISOString(),
            s.unsubscribedAt || null,
            s.unsubscribeToken || null,
            s.consentGiven || false,
            s.consentTimestamp || null,
            s.ipAddress || null,
            s.customFields || {},
            s.exported || false,
            s.exportedAt || null,
          ]
        );
        n++; counts.subscribers++;
      } catch(e) { console.error(`  ✖ Subscriber ${s.email} in ${slug}:`, e.message); counts.errors++; }
    }
    if (n) console.log(`  ✔ Subscribers for ${slug}: ${n}`);
  }
}

// ── Import analytics ──────────────────────────────────────────────────────────
async function importAnalytics(client) {
  const formsDir = path.join(DATA_DIR, 'forms');
  if (!fs.existsSync(formsDir)) return;
  const slugs = fs.readdirSync(formsDir).map(f => f.replace('.json', ''));
  for (const slug of slugs) {
    const analytics = readJson(path.join(DATA_DIR, `analytics-${slug}.json`));
    if (!analytics) continue;
    for (const [key, val] of Object.entries(analytics)) {
      if (key === 'lastUpdated' || typeof val !== 'number') continue;
      try {
        await client.query(
          `INSERT INTO analytics(form_slug, key, count, last_updated)
           VALUES($1,$2,$3,$4)
           ON CONFLICT(form_slug, key) DO UPDATE SET count=EXCLUDED.count`,
          [slug, key, val, analytics.lastUpdated || new Date().toISOString()]
        );
        counts.analytics++;
      } catch(e) { console.error(`  ✖ Analytics ${slug}/${key}:`, e.message); counts.errors++; }
    }
  }
  console.log(`  ✔ Analytics rows: ${counts.analytics}`);
}

// ── Import media ──────────────────────────────────────────────────────────────
async function importMedia(client) {
  // Per-form media
  const formsDir = path.join(DATA_DIR, 'forms');
  const slugs = fs.existsSync(formsDir)
    ? fs.readdirSync(formsDir).map(f => f.replace('.json', ''))
    : [];

  for (const slug of slugs) {
    const items = readJson(path.join(DATA_DIR, `media-${slug}.json`)) || [];
    await importMediaItems(client, items, slug);
  }

  // Shared media
  const sharedItems = readJson(path.join(DATA_DIR, 'media-shared.json')) || [];
  await importMediaItems(client, sharedItems, null);
}

async function importMediaItems(client, items, formSlug) {
  for (const item of items) {
    // item.url is like /uploads/uuid.ext
    const localPath = path.join(__dirname, '..', 'public', item.url);
    if (!fs.existsSync(localPath)) {
      console.warn(`  ⚠ File not found locally: ${localPath} — skipping`);
      continue;
    }
    const ext    = path.extname(item.url);
    const s3Key  = `uploads/${path.basename(item.url)}`; // preserve UUID-based filename
    const mime   = item.mimeType || mimeFromExt(ext);
    try {
      const s3Url = await uploadToS3(localPath, s3Key, mime);
      await client.query(
        `INSERT INTO media(id, form_slug, s3_key, url, original_name, mime_type, size, folder, uploaded_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT DO NOTHING`,
        [item.id, formSlug, s3Key, s3Url, item.name, mime,
         item.size || null, item.folder || '', item.uploadedAt || new Date().toISOString()]
      );
      counts.media++;
    } catch(e) { console.error(`  ✖ Media ${item.url}:`, e.message); counts.errors++; }
  }
  if (items.length) console.log(`  ✔ Media for ${formSlug || 'shared'}: ${items.length} → S3`);
}

// ── Import fonts ──────────────────────────────────────────────────────────────
async function importFonts(client) {
  const fonts = readJson(path.join(DATA_DIR, 'fonts-shared.json')) || [];
  for (const f of fonts) {
    const localPath = path.join(__dirname, '..', 'public', f.url);
    if (!fs.existsSync(localPath)) {
      console.warn(`  ⚠ Font file not found: ${localPath} — skipping`);
      continue;
    }
    const ext   = path.extname(f.url);
    const s3Key = `fonts/${path.basename(f.url)}`;
    const mime  = mimeFromExt(ext);
    try {
      const s3Url = await uploadToS3(localPath, s3Key, mime);
      await client.query(
        `INSERT INTO fonts(id, name, s3_key, url, uploaded_at)
         VALUES($1,$2,$3,$4,$5)
         ON CONFLICT(name) DO NOTHING`,
        [f.id, f.name, s3Key, s3Url, f.uploadedAt || new Date().toISOString()]
      );
      counts.fonts++;
    } catch(e) { console.error(`  ✖ Font ${f.name}:`, e.message); counts.errors++; }
  }
  if (fonts.length) console.log(`  ✔ Fonts uploaded to S3: ${fonts.length}`);
}

// ── Import design templates ───────────────────────────────────────────────────
async function importDesignTemplates(client) {
  const templates = readJson(path.join(DATA_DIR, 'design-templates.json')) || [];
  for (const t of templates) {
    try {
      await client.query(
        `INSERT INTO design_templates(id, name, design, created_at)
         VALUES($1,$2,$3,$4)
         ON CONFLICT DO NOTHING`,
        [t.id, t.name, t.design, t.createdAt || new Date().toISOString()]
      );
      counts.templates++;
    } catch(e) { console.error(`  ✖ Template ${t.name}:`, e.message); counts.errors++; }
  }
  if (templates.length) console.log(`  ✔ Design templates: ${templates.length}`);
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log('\n🚀 SignFlow — JSON → PostgreSQL + S3 migration\n');

  if (!process.env.DATABASE_URL) {
    console.error('✖ DATABASE_URL not set in .env — aborting');
    process.exit(1);
  }
  if (!S3_BUCKET) {
    console.error('✖ S3_BUCKET not set in .env — aborting');
    process.exit(1);
  }

  const client = await pool.connect();
  try {
    console.log('1. Creating tables…');
    await createTables(client);

    console.log('\n2. Importing forms…');
    await importForms(client);

    console.log('\n3. Importing subscribers…');
    await importSubscribers(client);

    console.log('\n4. Importing analytics…');
    await importAnalytics(client);

    console.log('\n5. Uploading media to S3…');
    await importMedia(client);

    console.log('\n6. Uploading fonts to S3…');
    await importFonts(client);

    console.log('\n7. Importing design templates…');
    await importDesignTemplates(client);

    console.log('\n✅ Migration complete!\n');
    console.table(counts);
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(e => {
  console.error('\n✖ Migration failed:', e);
  process.exit(1);
});
