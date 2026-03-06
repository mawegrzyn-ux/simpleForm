# SignFlow — Full Project Context
> For Claude Code or any AI assistant picking up this project.
> Last updated: 2026-03-06 (live and deployed)

---

## 1. What is SignFlow

SignFlow is a **self-hosted white-label newsletter signup platform** built and owned by Michal Wegrzyn (Obscure Kitty). It is NOT a SaaS product — it runs on a single AWS Lightsail instance and serves one signup form per deployment. The codebase is intentionally dependency-light, no build step, no React, no database — just Node.js/Express with JSON file storage.

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
Proxies all traffic to `localhost:3000`. `/embed` route has `X-Frame-Options` removed for cross-domain iframe embedding.

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
- **Storage:** JSON flat files (`data/subscribers.json`, `data/config.json`)
- **Auth:** Auth0 OIDC via `openid-client` v5 + `express-session`
- **Session:** `express-session` with MemoryStore (sufficient for single-process single-user admin)
- **Security:** `helmet`, `express-rate-limit`, `fail2ban`, UFW
- **File uploads:** `multer` (images to `public/uploads/`)
- **Captcha:** hCaptcha (optional, configured in admin)
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
├── server.js              # Main Express app (all routes, auth, rendering)
├── package.json
├── package-lock.json
├── .env                   # Secrets — NOT in git
├── .env.example           # Template — IS in git
├── .gitignore
├── README.md
├── nginx.conf.example
├── setup.sh               # Full server setup script (Ubuntu 24.04)
├── admin/
│   └── index.html         # Single-file admin SPA (vanilla JS, no build step)
├── data/
│   ├── config.json        # Site configuration (persisted, NOT in git)
│   └── subscribers.json   # Subscriber list (NOT in git)
└── public/
    └── uploads/           # User-uploaded images (NOT in git)
```

**Not committed to git:** `.env`, `data/subscribers.json`, `data/config.json`, `public/uploads/`, `node_modules/`

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

# hCaptcha (optional)
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
| `GET /` | Live signup page (server-rendered from config) |
| `POST /subscribe` | Form submission (rate limited: 10/15min) |
| `GET /privacy` | Privacy policy page |
| `GET /unsubscribe` | Unsubscribe via token |
| `GET /delete-data` | GDPR data deletion via token |
| `GET /embed` | Frameable version of signup page (X-Frame-Options removed) |
| `GET /embed.js` | Auto-inject script for embedding in external sites |

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
| `GET /api/admin/config` | Get full config |
| `POST /api/admin/config` | Save config |
| `POST /api/admin/upload` | Upload image (multer) |
| `GET /api/admin/subscribers` | Paginated subscriber list |
| `DELETE /api/admin/subscribers/:id` | GDPR delete subscriber |
| `GET /api/admin/export` | Export as CSV or JSON |

---

## 10. Admin SPA

Single-file vanilla JS app at `admin/index.html`. No build step, no framework.

**Features:**
- Live visual editor with real-time preview iframe
- Tab navigation: Editor / Subscribers / Embed / Settings
- Section controls: Hero (heading, subheading, image), Form (fields), Footer
- Custom fields: text, email, select, checkbox — add/remove/reorder
- Typography: Google Fonts picker for heading and body fonts
- Colours: primary, accent, background, text
- Logo upload
- hCaptcha toggle + site key config
- GDPR settings: privacy policy URL, cookie banner text
- Subscriber grid: search, filter by status, paginate, delete
- Export: CSV or JSON download
- Embed tab: copy-paste JS snippet + raw iframe code with customization options
- Settings tab: Auth0 info panel + Sign Out button (password management removed — handled by Auth0)

**Auth in SPA:**
- On load calls `GET /auth/me` — if `authenticated: false`, shows "Sign in with Auth0" button linking to `/auth/login`
- Session cookie is sent automatically with all fetch calls (no token headers)
- User avatar and Sign Out button shown in topbar when authenticated
- 401 responses redirect to `/auth/login`

---

## 11. Embed System

Two methods for embedding the signup form in external sites:

**Method 1 — JS snippet (recommended):**
```html
<div data-signflow></div>
<script src="https://wingvibes.com/embed.js"></script>
```
- Auto-resizing iframe via `postMessage` (reports height changes to parent)
- Success event: `window.addEventListener('signflow:success', ...)`
- Configurable: width, corner radius, shadow, min-height

**Method 2 — Raw iframe:**
```html
<iframe src="https://wingvibes.com/embed" width="100%" height="500"></iframe>
```

---

## 12. GDPR Compliance

- Cookie consent banner on public page
- Every subscriber gets a unique `unsubscribeToken`
- Unsubscribe link in footer of every email (when email sending is added)
- `/unsubscribe?token=X&email=Y` — sets status to `unsubscribed`
- `/delete-data?token=X&email=Y` — permanently removes record
- Admin can manually delete any subscriber (GDPR right to erasure)
- IP address stored at signup (disclosed in privacy policy)
- Consent timestamp recorded

---

## 13. Subscriber Data Schema

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

## 14. Useful Server Commands

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

## 15. Known Issues / History

- **Auth0 domain region:** Original `.env` had `obscurekitty.us.auth0.com` — correct is `obscurekitty.uk.auth0.com` (UK region tenant). Fixed in `.env`.
- **Session cookie bug:** `checks.state argument is missing` error was caused by `secure: process.env.NODE_ENV === 'production'` not working correctly behind Nginx proxy. Fixed by adding `app.set('trust proxy', 1)` and hardcoding `secure: true`.
- **Nginx symlink missing:** setup.sh created the config in `sites-available` but the symlink to `sites-enabled` wasn't created correctly. Fixed manually with `sudo ln -sf`.
- **www DNS:** `www.wingvibes.com` had no DNS record initially. Added manually, then Certbot rerun to include both domains.
- **Lightsail firewall:** Ports 80/443 were not open in the Lightsail console firewall (separate from UFW). Opened manually in Networking tab.
- **fail2ban on Ubuntu 24.04:** Original config used `iptables` banaction — fixed to use `nftables-multiport` which is the default on 24.04.

---

## 16. What's NOT implemented yet (potential next steps)

- Email sending (SMTP / transactional email for welcome + unsubscribe confirmation)
- Double opt-in confirmation flow
- Multiple forms / multi-tenant support
- Webhook on new subscriber
- Custom domain per white-label client
- Rate limiting on admin API (currently 200 req/15min, no per-IP granularity)
- PostgreSQL migration (planned in longer-term roadmap)
- MemoryStore for sessions → Redis or file-based store for production resilience (current MemoryStore leaks on long uptime — acceptable for single admin user, flagged in PM2 logs as warning)

---

## 17. Codebase Notes for Claude Code

- `server.js` is one large file (~930 lines) — intentional, no module splitting
- All HTML is rendered server-side via template literal functions in `server.js` (e.g. `renderPublicPage()`, `renderEmbedPage()`)
- Admin SPA is entirely in `admin/index.html` — single file, no build
- Config is read fresh from disk on every request (`readConfig()`) — no in-memory caching
- The `ENV_HCAPTCHA_SECRET` env var overrides `config.json` value at read time
- `adminPassword` field still exists in `config.json` schema but is no longer used — Auth0 replaced it
- The role namespace `https://signflow/roles` is hardcoded in both `server.js` and the Auth0 Action — must match exactly
