/**
 * SignFlow — Fix local /uploads/ URLs in form configs after S3 migration
 *
 * The import-json-to-pg.js script migrated files to S3 but did not update
 * the URLs embedded inside form config JSONB. This script rewrites them.
 *
 * Run ONCE on the server after the S3 migration:
 *   node scripts/fix-config-urls.js
 *
 * What it does:
 *   1. Replaces all "/uploads/" URLs in form configs with full S3 URLs
 *   2. Replaces all font URLs that still point to local paths
 *   3. Prints a summary of what was updated
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { Pool } = require('pg');

const pool      = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const S3_BUCKET = process.env.S3_BUCKET || '';
const AWS_REGION = process.env.AWS_REGION || 'eu-west-3';
const S3_BASE   = `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com`;

async function main() {
  console.log('\n SignFlow — Fix /uploads/ URLs in form configs\n');
  console.log(`  S3 base URL: ${S3_BASE}`);

  // ── Get all forms ──────────────────────────────────────────────────────────
  const { rows: forms } = await pool.query('SELECT slug, config FROM forms');
  console.log(`\n  Found ${forms.length} form(s) to check\n`);

  let updatedForms = 0;

  for (const form of forms) {
    const configStr = JSON.stringify(form.config);

    // Check if any local /uploads/ paths exist
    if (!configStr.includes('/uploads/')) {
      console.log(`  ✔ ${form.slug} — no local URLs found, skipping`);
      continue;
    }

    // Replace /uploads/ with full S3 URL
    const fixedStr = configStr.replace(/\/uploads\//g, `${S3_BASE}/uploads/`);
    const fixedConfig = JSON.parse(fixedStr);

    await pool.query(
      'UPDATE forms SET config = $1 WHERE slug = $2',
      [fixedConfig, form.slug]
    );

    // Count how many replacements were made
    const count = (configStr.match(/\/uploads\//g) || []).length;
    console.log(`  ✅ ${form.slug} — fixed ${count} URL(s)`);
    updatedForms++;
  }

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log(`\n  Done. ${updatedForms} form(s) updated.\n`);

  if (updatedForms > 0) {
    console.log('  ⚡ Restart the server to see changes: pm2 restart signflow\n');
  }

  await pool.end();
}

main().catch(e => {
  console.error('\n  ✖ Failed:', e.message);
  pool.end();
  process.exit(1);
});
