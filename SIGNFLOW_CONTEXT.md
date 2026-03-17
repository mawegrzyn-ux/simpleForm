# SignFlow — Full Project Context
> For Claude Code or any AI assistant picking up this project.
> Last updated: 2026-03-17 (PostgreSQL/S3 architecture, Integrations & Reports pages)

---

## 1. What is SignFlow

SignFlow is a **self-hosted white-label newsletter signup platform** built and owned by Michal Wegrzyn (Obscure Kitty). It is NOT a SaaS product — it runs on a single AWS Lightsail instance. The codebase is intentionally dependency-light: no build step, no React, no frontend framework — just Node.js/Express backed by PostgreSQL and Amazon S3.

It supports **multiple forms** on the same instance, each with its own slug, config, and subscriber list. An AI assistant ("McFry") powered by Anthropic Claude (Haiku 4.5) + Voyage AI embeddings is built into the admin panel.

**Live URL:** https://wingvibes.com
**Admin panel:** https://wingvibes.com/admin
**Auth login:** https://wingvibes.com/auth/login

---

## 2. Infrastructure

| Item | Value |
|------|-------|
| Host | AWS Lightsail |
| OS | Ubuntu 24.04 LTS |
| Instance IP | 13.37.62.63 (static) |
| Domain | wingvibes.com |
| DNS | Custom nameservers pointing to AWS, A record set in Lightsail |
| SSL | Let's Encrypt via Certbot (auto-renewal via systemd timer) |
| Reverse proxy | Nginx 1.24 |
| Process manager | PM2 (app name: `signflow`) |
| Node version | 20 LTS |
| App directory | `/home/ubuntu/signflow` |
| Backups | `/home/ubuntu/backups/signflow` (daily 02:30 UTC, 7-day retention) |
| SSH user | `ubuntu` |

**Nginx config:** `/etc/nginx/sites-available/signflow`
Proxies all traffic to `localhost:3000`. `/:slug/embed` routes have `X-Frame-Options` removed for cross-domain iframe embedding.

**Firewall:** UFW + Lightsail console firewall. Ports open: 22 (SSH), 80 (HTTP), 443 (HTTPS).

**fail2ban:** Configured with `nftables-multiport` backend (Ubuntu 24.04 compatible), SSH 5 attempts → 1h ban.

---

## 3. GitHub Repository

**URL:** https://github.com/mawegrzyn-ux/simpleForm
**Branch:** `main`
**Deploy key:** `~/.ssh/signflow_deploy` (ed25519) — server → GitHub (read-only clone)
**GitHub Actions key:** `~/.ssh/github_actions` (ed25519) — GitHub → server (for CD pipeline)
**GitHub Actions secret:** `SSH_PRIVATE_KEY` = private key of `github_actions`

**CD workflow:** `.github/workflows/deploy.yml`
On push to `main`: SSH into server → `git pull` → `npm install --omit=dev` → `pm2 restart signflow`

---

## 4. Tech Stack

- **Runtime:** Node.js 20 LTS
- **Framework:** Express 4
- **Database:** PostgreSQL 16 (AWS Lightsail Managed Database, accessed via `pg` pool)
- **Object storage:** Amazon S3 (`@aws-sdk/client-s3`) — all media and font uploads
- **Auth:** Auth0 OIDC via `openid-client` v5 + `express-session`
- **Session:** `express-session` with `connect-pg-simple` (sessions stored in PostgreSQL `session` table)
- **AI assistant:** Anthropic SDK (`@anthropic-ai/sdk`) — Claude Haiku 4.5; Voyage AI (embeddings for semantic search over help docs)
- **Email:** Nodemailer (SMTP, credentials stored per global settings)
- **Security:** `helmet`, `express-rate-limit`, CSRF tokens, `fail2ban`, UFW
- **File uploads:** `multer` (validates MIME; forwards to S3)
- **HTML sanitisation:** `sanitize-html` (WYSIWYG block output)
- **Captcha:** hCaptcha (optional, configured per-form in admin)
- **SSL:** Let's Encrypt / Certbot

---

## 5. File Structure

```
/home/ubuntu/signflow/
├── server.js                     # Main Express app (~3000+ lines, all routes + rendering)
├── package.json
├── package-lock.json
├── .env                          # Secrets — NOT in git
├── .env.example                  # Template — IS in git
├── .gitignore
├── README.md
├── SIGNFLOW_CONTEXT.md           # This file
├── CLAUDE.md                     # Instructions for Claude Code AI assistant
├── nginx.conf.example
├── setup.sh                      # Full server setup script (Ubuntu 24.04)
├── routes/
│   ├── integrations.js           # /api/admin/integrations/* (status, test, config)
│   └── reports.js                # /api/admin/reports/* (summary, subscribers, forms, email, export)
├── admin/
│   ├── index.html                # Main admin SPA (vanilla JS, no build step)
│   ├── integrations/
│   │   └── index.html            # Integrations health board SPA (/admin/integrations)
│   └── reports/
│       └── index.html            # Analytics & reports SPA (/admin/reports)
├── scripts/
│   └── import-json-to-pg.js      # One-time migration from JSON flat files → PostgreSQL
└── data/                         # LEGACY JSON flat files — kept for migration reference only
    └── ...
```

**Not committed to git:** `.env`, `data/` runtime files, `node_modules/`
**All runtime data lives in PostgreSQL + S3** — the server has no local file state beyond code.

---

## 6. Environment Variables (.env)

```env
# App
PORT=3000
NODE_ENV=production
SESSION_SECRET=<64-char random hex>

# Auth0
AUTH0_DOMAIN=obscurekitty.uk.auth0.com
AUTH0_CLIENT_ID=<from Auth0 dashboard>
AUTH0_CLIENT_SECRET=<from Auth0 dashboard>
AUTH0_CALLBACK_URL=https://wingvibes.com/auth/callback
AUTH0_ADMIN_ROLE=signflow-admin

# PostgreSQL (AWS Lightsail Managed Database)
DATABASE_URL=postgresql://user:pass@host:5432/signflow

# Amazon S3
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
S3_BUCKET=signflow-uploads

# AI (McFry assistant)
ANTHROPIC_API_KEY=<from console.anthropic.com>
VOYAGE_API_KEY=<from dash.voyageai.com>

# Internal API (Claude Code read-only access to feedback/bug reports)
INTERNAL_API_KEY=<random secret>

# hCaptcha (optional — can also be configured per-form via admin)
SF_HCAPTCHA_SECRET=
```

---

## 7. Auth0 Configuration

| Item | Value |
|------|-------|
| Tenant | obscurekitty |
| Tenant domain | obscurekitty.uk.auth0.com |
| Application name | wingvibes |
| Application type | Regular Web Application |
| Allowed Callback URLs | https://wingvibes.com/auth/callback |
| Allowed Logout URLs | https://wingvibes.com |
| Admin role | `signflow-admin` |
| Assigned user | ma.wegrzyn@gmail.com (Michal Wegrzyn) |

**Auth0 Action** (Post Login trigger, deployed and active in Login flow):
```js
// Name: "Add roles to token"
// Trigger: Login / Post Login
// Runtime: Node 22
exports.onExecutePostLogin = async (event, api) => {
  const ns = 'https://signflow/roles';
  const roles = event.authorization?.roles || [];
  api.idToken.setCustomClaim(ns, roles);
  api.accessToken.setCustomClaim(ns, roles);
};
```
This action MUST remain deployed and active in the Login flow. Without it, the `signflow-admin` role is never injected into the token and all admin logins get "Access Denied".

---

## 8. Auth Flow (how it works)

1. Browser hits `/admin` → `adminAuth` middleware checks `req.session.user`
2. No session → redirect to `/auth/login`
3. `/auth/login` → generates PKCE challenge, stores `nonce`/`state`/`codeVerifier` in session, redirects to Auth0 Universal Login
4. User logs in at Auth0 → redirected back to `/auth/callback`
5. Server exchanges code for tokens, calls `tokenSet.claims()`
6. Checks for `https://signflow/roles` claim in token — must contain `signflow-admin`
7. If role present → stores claims in `req.session.user`, redirects to `/admin`
8. If role missing → shows Access Denied page with Sign Out button
9. All `/api/admin/*` routes protected by same `adminAuth` middleware
10. API routes return 401 JSON if not authenticated; browser routes redirect to `/auth/login`

**Critical server.js settings for HTTPS behind Nginx:**
```js
app.set('trust proxy', 1);  // MUST be set — enables secure cookies behind nginx

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,        // MUST be true — was the bug that caused "checks.state missing"
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000
  }
}));
```

---

## 9. Routes

### Public
| Route | Description |
|-------|-------------|
| `GET /` | Redirects to first form in index |
| `GET /:slug` | Live signup page for that form (server-rendered) |
| `POST /:slug/subscribe` | Form submission (rate limited: 10/15min) |
| `GET /privacy` | Privacy policy (uses first form's branding) |
| `GET /unsubscribe` | Unsubscribe via token (searches all forms) |
| `GET /delete-data` | GDPR data deletion via token (searches all forms) |
| `GET /:slug/embed` | Frameable version of signup page (X-Frame-Options removed) |
| `GET /:slug/embed.js` | Auto-inject script for embedding in external sites |

### Auth
| Route | Description |
|-------|-------------|
| `GET /auth/login` | Initiates Auth0 PKCE flow |
| `GET /auth/callback` | Auth0 callback, validates token, sets session |
| `GET /auth/logout` | Destroys session, redirects to Auth0 logout |
| `GET /auth/me` | Returns `{authenticated, name, email, picture}` from session |

### Admin HTML pages (all require Auth0 session)
| Route | Description |
|-------|-------------|
| `GET /admin` | Serves main admin SPA (`admin/index.html`) |
| `GET /admin/integrations` | Serves integrations health board SPA |
| `GET /admin/reports` | Serves analytics & reports SPA |

### Admin API (all require Auth0 session + CSRF token)
| Route | Description |
|-------|-------------|
| `GET /api/admin/csrf-token` | Returns CSRF token for the session |
| `GET /api/admin/me` | Returns `{email, name, role}` for current user |
| `GET /api/admin/forms` | List all forms with subscriber counts |
| `POST /api/admin/forms` | Create new form `{slug, name}` |
| `DELETE /api/admin/forms/:slug` | Delete a form and all its subscribers |
| `PATCH /api/admin/forms/:slug/meta` | Rename a form |
| `GET /api/admin/forms/:slug` | Get form config |
| `POST /api/admin/forms/:slug` | Save form config |
| `POST /api/admin/forms/:slug/upload` | Upload image to S3 |
| `POST /api/admin/forms/:slug/upload-font` | Upload custom font to S3 |
| `GET /api/admin/forms/:slug/subscribers` | Paginated subscriber list |
| `DELETE /api/admin/forms/:slug/subscribers/:id` | GDPR hard-delete subscriber |
| `GET /api/admin/forms/:slug/export` | Export as CSV or JSON |
| `GET /api/admin/design-templates` | List saved design templates |
| `POST /api/admin/design-templates` | Save a design template `{name, design}` |
| `DELETE /api/admin/design-templates/:id` | Delete a design template |
| `GET /api/admin/integrations/status` | Health snapshot of all 10 external services |
| `POST /api/admin/integrations/test/:service` | On-demand test for one service |
| `GET /api/admin/integrations/config` | Masked integration config from `global_settings` |
| `PATCH /api/admin/integrations/config` | Save integration credentials to `global_settings` |
| `GET /api/admin/reports/summary` | Platform totals (forms, subscribers, emails, submissions) |
| `GET /api/admin/reports/subscribers` | Subscriber growth by day (`?period=30d\|90d\|1y`) |
| `GET /api/admin/reports/forms` | Per-form: visits, submissions, conversion %, subscriber count |
| `GET /api/admin/reports/email` | Email metrics: sent, opens, clicks, bounces per form |
| `GET /api/admin/reports/export` | CSV of full form performance summary |
| `GET /api/admin/bug-reports` | List feedback/bug reports |
| `PATCH /api/admin/bug-reports/:id` | Update bug report status |
| `DELETE /api/admin/bug-reports/:id` | Delete bug report |
| `POST /api/admin/ai-chat` | SSE stream — McFry AI assistant (Anthropic Haiku 4.5) |

---

## 10. Multi-Form System

### How forms are stored
All form data is stored in **PostgreSQL**:
- `forms` table — `slug` PK, `name`, `config` JSONB, `status`, `testing_pin`, `created_at`
- `subscribers` table — per-form subscribers with `form_slug` FK
- `analytics` table — per-form event counters (`visit`, `submit`, `error`)
- `email_log` table — per-form email send history

Media and fonts are stored in **Amazon S3**:
- Images: `uploads/{uuid}.{ext}`
- Fonts: `fonts/{uuid}.{ext}`

### Slug rules
- Lowercase letters, numbers, hyphens only: `[a-z0-9-]+`
- Reserved slugs blocked: `admin`, `auth`, `api`, `privacy`, `unsubscribe`, `delete-data`, `embed`, `public`, `uploads`, `assets`, `integrations`, `reports`
- Must be unique

### Legacy migration
`scripts/import-json-to-pg.js` — one-time script to migrate old JSON flat files → PostgreSQL + S3.
`migrateIfNeeded()` is dead code, no longer called at startup.

---

## 11. Admin SPA

Three self-contained SPAs — no build step, no framework, no shared JS files:

### `admin/index.html` — Main admin panel
**Features:**
- Forms index view — create, rename, delete, open forms; hover any form card to preview it
- Per-form live visual editor with real-time preview iframe (desktop / tablet / mobile)
- Tab navigation: Build / Subscribers / Embed / Branding / Settings / Media / Help
- Section types: Hero, Form, Footer, Divider, Video, Spin Wheel, Container, Content
- Form field types: text, email, tel, number, select, checkbox, textarea, date, age, year, yearmonth, yearmonthday, slider (linear/angled/arc), iconselect
- Branding: label size, label weight, label colour, field border/bg, fonts, colours
- Conditional field visibility (show/hide based on another field's value)
- Typography: Google Fonts picker + custom font upload (.woff/.woff2/.ttf/.otf)
- Colours: primary, accent, background, text, field border/background
- Field border style, radius, and width controls
- Logo upload + hero image upload
- Background image upload + overlay opacity
- hCaptcha toggle + site key config
- GDPR settings: privacy policy URL, GDPR consent text
- Confirmation blocks: content shown after successful form submission
- Design templates: save/apply/delete named design presets
- Subscriber grid: search, filter by status, paginate, delete
- Export: CSV or JSON download
- Embed tab: copy-paste JS snippet + raw iframe code
- Settings tab: Auth0 info panel + Sign Out button
- McFry AI assistant sidebar (SSE streaming, Anthropic Haiku 4.5)
- Export JPEG preview (html2canvas, scroll-corrected)
- Bug/feedback reporting → `bug_reports` table

### `admin/integrations/index.html` — Integration health board
Live status for all 10 external services: Anthropic, Voyage AI, Amazon S3, Auth0, SMTP, Mailchimp, Klaviyo, HubSpot, Salesforce, PostgreSQL. Each card: status dot (ok/error/unconfigured/checking), latency, detail text, portal link (`open_in_new`), [Test] button, [Configure] panel. Configurable services (Mailchimp/Klaviyo/HubSpot/Salesforce) save credentials to `global_settings`. Auto-refreshes every 60 s.

### `admin/reports/index.html` — Analytics & reports
Summary KPIs, period picker (30d/90d/1y), SVG sparkline for subscriber growth (pure `<polyline>`, no external chart lib), form performance table (visits/submissions/conversion%/subscribers), email metrics table (sent/opens/clicks/bounces), CSV export.

**Auth pattern for all three SPAs:**
- On load: `GET /api/admin/csrf-token` — 401 → redirect to `/auth/login`
- Store token in `window._csrfToken`; all mutations send `X-CSRF-Token` header
- `GET /api/admin/me` → display user email in top bar

---

## 12. Embed System

Two methods for embedding the signup form in external sites:

**Method 1 — JS snippet (recommended):**
```html
<div data-signflow></div>
<script src="https://wingvibes.com/{slug}/embed.js"></script>
```
- Auto-resizing iframe via `postMessage` (reports height changes to parent)
- Success event: `window.addEventListener('signflow:success', ...)`
- Configurable via data attributes: `data-width`, `data-radius`, `data-shadow`, `data-min-height`

**Method 2 — Raw iframe:**
```html
<iframe src="https://wingvibes.com/{slug}/embed" width="100%" height="500"></iframe>
```

---

## 13. Field Types

| Type | Description |
|------|-------------|
| `text` | Plain text input |
| `email` | Email input (system field, always first) |
| `tel` | Phone number input |
| `number` | Numeric input |
| `select` | Dropdown with configurable options |
| `checkbox` | Single checkbox |
| `textarea` | Multi-line text |
| `date` | Date picker, supports min/max date and specific allowed dates |
| `age` | Number input with min/max age constraints |
| `year` | Scroll-wheel year picker |
| `yearmonth` | Dual scroll-wheel year + month picker |
| `slider` | Range slider — variants: `linear`, `angled`, `arc` |

All non-system fields support **conditional visibility** (show/hide based on another field's value with operators: eq, neq, contains, gt, lt, empty, notempty).

---

## 14. Section / Block Types

| Type | Description |
|------|-------------|
| `hero` | Heading + subheading + optional hero image |
| `form` | The signup form fields + submit button + GDPR text |
| `footer` | Small footer text |
| `divider` | Horizontal rule — styles: solid, dots, wave, space |
| `video` | YouTube/Vimeo embed or direct video URL |
| `spinwheel` | Prize wheel with configurable rewards + probabilities |
| `container` | Flexible block: mix of fields, submit, content elements. Supports 1 or 2 columns |
| `content` | Pure content block: headings, paragraphs, images, spacers, dividers, wysiwyg, video |

**Confirmation blocks** (`cfg.confirmation[]`): same section types, shown in place of the form after successful submission.

---

## 15. GDPR Compliance

- Cookie consent banner on public page
- Every subscriber gets a unique `unsubscribeToken`
- `/unsubscribe?token=X&email=Y` — sets status to `unsubscribed` (searches across all forms)
- `/delete-data?token=X&email=Y` — permanently removes record (searches across all forms)
- Admin can manually delete any subscriber (GDPR right to erasure)
- IP address stored at signup (disclosed in privacy policy)
- Consent timestamp recorded

---

## 16. Subscriber Data Schema

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "status": "active|unsubscribed",
  "subscribedAt": "ISO8601",
  "unsubscribedAt": "ISO8601|null",
  "unsubscribeToken": "uuid",
  "consentGiven": true,
  "consentTimestamp": "ISO8601",
  "ipAddress": "x.x.x.x",
  "customFields": {
    "firstName": "John",
    "lastName": "Doe"
  }
}
```

---

## 17. Form Config Schema

```json
{
  "slug": "my-form",
  "name": "My Form",
  "site": {
    "title": "Sign Up",
    "favicon": "",
    "cookieBannerText": "...",
    "gdprText": "By subscribing you agree to our <a href=\"{privacyUrl}\">Privacy Policy</a>...",
    "privacyPolicyUrl": "/privacy",
    "unsubscribeEnabled": true,
    "captchaEnabled": false,
    "hcaptchaSiteKey": "",
    "hcaptchaSecretKey": ""
  },
  "design": {
    "googleFont": "Playfair Display",
    "bodyFont": "Lato",
    "primaryColor": "#1a1a2e",
    "accentColor": "#e94560",
    "backgroundColor": "#f8f5f0",
    "textColor": "#1a1a2e",
    "buttonText": "Subscribe Now",
    "buttonRadius": "4px",
    "containerWidth": "560px",
    "backgroundImage": "",
    "backgroundOverlay": 0.4,
    "logoUrl": "",
    "logoWidth": "180px",
    "cardPadding": "48px 40px",
    "cardRadius": "12px",
    "fieldRadius": "6px",
    "fieldBg": "#fafafa",
    "fieldBorderColor": "#e0e0e0",
    "fieldBorderStyle": "solid",
    "fieldBorderWidth": 2,
    "customFonts": [{ "name": "MyFont", "url": "/uploads/fonts/uuid.woff2" }]
  },
  "sections": [ /* see Section/Block Types above */ ],
  "fields": [ /* see Field Types above */ ],
  "confirmation": [ /* same as sections — shown after successful submit */ ]
}
```

---

## 18. Useful Server Commands

```bash
# App status
pm2 status
pm2 logs signflow --lines 50
pm2 restart signflow

# Deploy latest
~/deploy.sh
# (does: git pull + npm install --omit=dev + pm2 restart signflow)

# Edit secrets
nano ~/signflow/.env

# Nginx
sudo nginx -t
sudo systemctl reload nginx
sudo cat /etc/nginx/sites-available/signflow

# SSL renewal (manual test)
sudo certbot renew --dry-run

# Backups
ls ~/backups/signflow/
~/signflow-backup.sh  # run manually

# Check what's listening
sudo ss -tlnp | grep :3000
```

---

## 19. Known Issues / History

- **Auth0 domain region:** Original `.env` had `obscurekitty.us.auth0.com` — correct is `obscurekitty.uk.auth0.com` (UK region tenant). Fixed in `.env`.
- **Session cookie bug:** `checks.state argument is missing` error was caused by `secure: process.env.NODE_ENV === 'production'` not working correctly behind Nginx proxy. Fixed by adding `app.set('trust proxy', 1)` and hardcoding `secure: true`.
- **Nginx symlink missing:** setup.sh created the config in `sites-available` but the symlink to `sites-enabled` wasn't created correctly. Fixed manually with `sudo ln -sf`.
- **www DNS:** `www.wingvibes.com` had no DNS record initially. Added manually, then Certbot rerun to include both domains.
- **Lightsail firewall:** Ports 80/443 were not open in the Lightsail console firewall (separate from UFW). Opened manually in Networking tab.
- **fail2ban on Ubuntu 24.04:** Original config used `iptables` banaction — fixed to use `nftables-multiport` which is the default on 24.04.

---

## 20. What's NOT implemented yet (potential next steps)

- Email sending (SMTP / transactional email for welcome + unsubscribe confirmation)
- Double opt-in confirmation flow
- Webhook on new subscriber
- Custom domain per white-label client
- Rate limiting on admin API (currently 200 req/15min, no per-IP granularity)
- PostgreSQL migration (planned in longer-term roadmap)
- MemoryStore for sessions → Redis or file-based store for production resilience (current MemoryStore leaks on long uptime — acceptable for single admin user, flagged in PM2 logs as warning)

---

## 21. Codebase Notes for Claude Code

- `server.js` is one large file (~3000+ lines) — intentional, no module splitting of core logic
- Exception: `routes/integrations.js` and `routes/reports.js` — standalone Express routers mounted via `app.use()`. They receive `req.pool` (PostgreSQL pool) injected by a middleware in `server.js`. Access live `app.locals` values for `s3`, `S3_BUCKET`, `transporter`, `_helpReady`, `_helpChunks` via `req.app.locals`.
- `app.locals` uses `Object.defineProperty` with getter functions for `_helpReady`, `_helpChunks`, and `transporter` — ensures route files always read the current module-level value, not a snapshot captured at startup.
- All HTML is rendered server-side via template literal functions in `server.js`
- Main admin SPA is entirely in `admin/index.html` — single file, no build. Two additional SPAs: `admin/integrations/index.html`, `admin/reports/index.html`.
- Form config is stored in PostgreSQL `forms.config` JSONB column. `readFormConfig(slug)` reads from DB. `writeFormConfig(slug, cfg)` upserts.
- The role namespace `https://signflow/roles` is hardcoded in both `server.js` and the Auth0 Action — must match exactly.
- Reserved slugs are defined in `RESERVED_SLUGS` Set at the top of `server.js`. Includes `integrations` and `reports`.
- `migrateIfNeeded()` is dead code — not called at startup. Migration is a one-time manual script.
- McFry AI: model is `claude-haiku-4-5`. Rate-limit errors (429) trigger a client-side countdown timer. Billing errors (400 + "credit balance") show a top-up message. Both handled in the SSE catch block of `/api/admin/ai-chat`.
- CSS custom properties for label typography: `--sf-lbl`, `--sf-lbl-size`, `--sf-lbl-weight` emitted into `:root` of both desktop and mobile public form templates in `server.js`.
