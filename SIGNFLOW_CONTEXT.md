# SignFlow — Full Project Context
> For Claude Code or any AI assistant picking up this project.
> Last updated: 2026-03-10 (multi-form architecture)

---

## 1. What is SignFlow

SignFlow is a **self-hosted white-label newsletter signup platform** built and owned by Michal Wegrzyn (Obscure Kitty). It is NOT a SaaS product — it runs on a single AWS Lightsail instance. The codebase is intentionally dependency-light: no build step, no React, no database — just Node.js/Express with JSON file storage.

It supports **multiple forms** on the same instance, each with its own slug, config, and subscriber list.

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
- **Storage:** JSON flat files (see File Structure below)
- **Auth:** Auth0 OIDC via `openid-client` v5 + `express-session`
- **Session:** `express-session` with MemoryStore (sufficient for single-process single-user admin)
- **Security:** `helmet`, `express-rate-limit`, `fail2ban`, UFW
- **File uploads:** `multer` (images to `public/uploads/`, fonts to `public/uploads/fonts/`)
- **Captcha:** hCaptcha (optional, configured per-form in admin)
- **SSL:** Let's Encrypt / Certbot

**package.json dependencies:**
```json
{
  "dotenv": "^16.4.5",
  "express": "^4.18.2",
  "express-rate-limit": "^7.1.5",
  "express-session": "^1.17.3",
  "helmet": "^7.1.0",
  "multer": "^1.4.5-lts.1",
  "openid-client": "^5.6.5",
  "uuid": "^9.0.0"
}
```

---

## 5. File Structure

```
/home/ubuntu/signflow/
├── server.js                     # Main Express app (~1713 lines, all routes + rendering)
├── package.json
├── package-lock.json
├── .env                          # Secrets — NOT in git
├── .env.example                  # Template — IS in git
├── .gitignore
├── README.md
├── SIGNFLOW_CONTEXT.md           # This file
├── nginx.conf.example
├── setup.sh                      # Full server setup script (Ubuntu 24.04)
├── admin/
│   └── index.html                # Single-file admin SPA (vanilla JS, no build step)
├── data/
│   ├── forms-index.json          # List of all forms [{slug, name, createdAt}] — NOT in git
│   ├── forms/
│   │   └── {slug}.json           # Per-form config — NOT in git
│   ├── subscribers-{slug}.json   # Per-form subscriber list — NOT in git
│   ├── design-templates.json     # Saved design templates — NOT in git
│   ├── config.json               # LEGACY single-form config (kept for migration only) — NOT in git
│   └── subscribers.json          # LEGACY single-form subscribers (kept for migration only) — NOT in git
└── public/
    └── uploads/                  # User-uploaded images + fonts (NOT in git)
        └── fonts/                # Custom font files (.woff/.woff2/.ttf/.otf)
```

**Not committed to git:** `.env`, all `data/` runtime files, `public/uploads/`, `node_modules/`

---

## 6. Environment Variables (.env)

```env
# Auth0
AUTH0_DOMAIN=obscurekitty.uk.auth0.com
AUTH0_CLIENT_ID=<from Auth0 dashboard>
AUTH0_CLIENT_SECRET=<from Auth0 dashboard>
AUTH0_CALLBACK_URL=https://wingvibes.com/auth/callback
AUTH0_ADMIN_ROLE=signflow-admin
SESSION_SECRET=<64-char random hex>

# hCaptcha (optional — overrides per-form config value)
SF_HCAPTCHA_SECRET=

# App
PORT=3000
NODE_ENV=production
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

### Admin (all require session)
| Route | Description |
|-------|-------------|
| `GET /admin` | Serves admin SPA |
| `GET /api/admin/forms` | List all forms with subscriber counts |
| `POST /api/admin/forms` | Create new form `{slug, name}` |
| `DELETE /api/admin/forms/:slug` | Delete a form and all its subscribers |
| `PATCH /api/admin/forms/:slug/meta` | Rename a form |
| `GET /api/admin/forms/:slug` | Get form config |
| `POST /api/admin/forms/:slug` | Save form config |
| `POST /api/admin/forms/:slug/upload` | Upload image (multer) |
| `POST /api/admin/forms/:slug/upload-font` | Upload custom font file |
| `GET /api/admin/forms/:slug/subscribers` | Paginated subscriber list |
| `DELETE /api/admin/forms/:slug/subscribers/:id` | GDPR delete subscriber |
| `GET /api/admin/forms/:slug/export` | Export as CSV or JSON |
| `GET /api/admin/design-templates` | List saved design templates |
| `POST /api/admin/design-templates` | Save a design template `{name, design}` |
| `DELETE /api/admin/design-templates/:id` | Delete a design template |

---

## 10. Multi-Form System

### How forms are stored
- `data/forms-index.json` — ordered list of all form metadata
- `data/forms/{slug}.json` — full config for each form
- `data/subscribers-{slug}.json` — subscribers for each form

### Slug rules
- Lowercase letters, numbers, hyphens only: `[a-z0-9-]+`
- Reserved slugs blocked: `admin`, `auth`, `api`, `privacy`, `unsubscribe`, `delete-data`, `embed`, `public`, `uploads`, `assets`
- Must be unique

### Migration from single-form
On first startup after upgrade, `migrateIfNeeded()` runs automatically:
- If `data/forms/` does NOT exist: creates it, converts `config.json` → `data/forms/default.json`, copies `subscribers.json` → `data/subscribers-default.json`
- Safe to run on a fresh install (just creates defaults if no old files exist)

---

## 11. Admin SPA

Single-file vanilla JS app at `admin/index.html`. No build step, no framework.

**Features:**
- Forms index view — create, rename, delete, open forms
- Per-form live visual editor with real-time preview iframe
- Tab navigation: Editor / Subscribers / Embed / Settings
- Section types: Hero, Form, Footer, Divider, Video, Spin Wheel, Container, Content
- Form field types: text, email, tel, number, select, checkbox, textarea, date, age, year, yearmonth, slider (linear/angled/arc)
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

**Auth in SPA:**
- On load calls `GET /auth/me` — if `authenticated: false`, shows "Sign in with Auth0" button
- Session cookie sent automatically with all fetch calls (no token headers)
- 401 responses redirect to `/auth/login`

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

- `server.js` is one large file (~1713 lines) — intentional, no module splitting
- All HTML is rendered server-side via template literal functions in `server.js`
- Admin SPA is entirely in `admin/index.html` — single file, no build
- Config is read fresh from disk on every request (`readFormConfig()`) — no in-memory caching
- The `ENV_HCAPTCHA_SECRET` env var overrides `config.json` value at read time
- `adminPassword` field still exists in form config schema but is never used — Auth0 replaced it
- The role namespace `https://signflow/roles` is hardcoded in both `server.js` and the Auth0 Action — must match exactly
- Reserved slugs are defined in `RESERVED_SLUGS` Set at the top of `server.js`
- `migrateIfNeeded()` runs at startup — safe to run repeatedly (no-ops if already migrated)
