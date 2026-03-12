# SignFlow — Self-Hosted Newsletter Signup Platform

> White-label, multi-form, GDPR-compliant newsletter signup platform.
> Self-hosted on your own infrastructure. No SaaS lock-in. Full data ownership.

**Live demo:** wingvibes.com | **Admin:** wingvibes.com/admin
**Stack:** Node.js 20 · Express 4 · Vanilla JS SPA · PostgreSQL 16 · Amazon S3 · Auth0 OIDC · PM2 · Nginx · AWS Lightsail

---

## Changelog

### 2026-03-12
- **New field — Year+Month+Day picker**: three scroll-drum date picker submitting `YYYY-MM-DD`
- **New field — Icon / tile selector (`iconselect`)**: horizontal-scroll or grid layout of selectable tiles (Material Icons, emoji, or image via media library); single or multi-select; configurable tile size, highlight style (border/fill), highlight colour
- **Icon selector — grid layout**: fixed-column grid with row-first or column-first fill, 1–12 columns
- **Icon selector — Material icon picker**: searchable modal grid of 180+ Material Icons
- **Icon selector — media picker for image tiles**: image tiles use the media library; thumbnail previewed in editor
- **Submission deduplication**: Settings tab toggle to allow duplicate emails; configure a multi-field unique key (e.g. email + first name); server-side query built dynamically from selected fields
- **Email template**: body font size selector (13–20 px); branding colour swatches on all colour pickers
- **Branding preview**: `?slug=` param loads actual form custom fonts for accurate preview
- **Preview system**: template edits auto-save before reload; removed double-save; `_reloadDesignFrame()` / `_reloadAllFrames()` helpers
- **Preference centre crash fix**: `findAllSubscriptions()` properly awaited in GET/POST `/preferences` handlers
- **CSP fix**: `font-src` extended with `https://*.amazonaws.com` so S3-hosted custom fonts load

---

## Table of Contents

1. [Overview](#1-overview)
2. [Feature Matrix](#2-feature-matrix)
3. [Tech Stack](#3-tech-stack)
4. [Architecture](#4-architecture)
5. [Data Model](#5-data-model)
6. [Installation & Deployment](#6-installation--deployment)
7. [Configuration Reference](#7-configuration-reference)
8. [API Reference](#8-api-reference)
9. [Admin Panel Guide](#9-admin-panel-guide)
10. [Security](#10-security)
11. [GDPR & Data Protection](#11-gdpr--data-protection)
12. [Enterprise Roadmap](#12-enterprise-roadmap)

---

## 1. Overview

SignFlow is a self-hosted platform for building, managing, and embedding beautiful newsletter signup forms. It is intentionally a single-server, single-file architecture — no build step, no microservices, no external database. All data lives in flat JSON files on the host.

### Design goals

| Goal | How achieved |
|---|---|
| Zero vendor lock-in | All data in plain JSON; export CSV/JSON anytime |
| White-label | Per-form design, custom fonts, custom domain |
| GDPR-first | Consent timestamps, unsubscribe tokens, data deletion routes |
| Embeddable | iframe + script-tag embed on any site |
| Simple ops | PM2 + Nginx + Let's Encrypt; no Docker required |

---

## 2. Feature Matrix

### Form builder
| Feature | Details |
|---|---|
| Visual drag-and-drop editor | Live WYSIWYG with instant iframe preview |
| Block types | Field, Submit, Heading, Paragraph, Image, Spacer, Divider, WYSIWYG rich text, Video, Container (1- or 2-column) |
| Field types | Text, Email, Phone, Dropdown, Checkbox, Textarea, Date, Age, Year, Year+Month, Year+Month+Day, Slider (linear / angled / arc), Icon/tile selector (scroll or grid, Material Icons / emoji / image, single/multi-select) |
| Confirmation section | Separate post-submit block layout shown after successful signup |
| Spin-wheel section | Gamified prize wheel section on the form |
| Per-block formatting | Label colour, text colour, field background, font family, font size per field block; button colour per submit block |
| Container columns | Split any section into 1 or 2 columns; drop any block type into either column |

### Design & theming
| Feature | Details |
|---|---|
| Google Fonts | 20+ fonts for headings and body separately |
| Custom font upload | Upload .woff / .woff2 / .ttf / .otf; scoped to all forms (shared) or one form |
| Shared font library | Fonts uploaded once, available to all forms automatically |
| Color pickers | Brand color palette picker (BCP) + hex input for all design tokens |
| Design tokens | Primary, accent, text, background, field bg, button, link, border colours |
| Hero section | Full-width header with background image/color, overlay opacity, heading + sub |
| Responsive preview | Desktop / Tablet / Mobile live preview in admin |
| Design templates | Save current design as a named template; apply / delete templates; stored in `data/design-templates.json` |

### Media library
| Feature | Details |
|---|---|
| Upload | JPEG, PNG, GIF, WebP, SVG; stored in `public/uploads/` |
| Folders | Create named folders; drag items between folders |
| Shared library | Single media library across all forms |
| Insert | Click to insert into form blocks (images, hero, background) |
| Rename / Delete | Manage items inline |

### Subscribers
| Feature | Details |
|---|---|
| Table view | Paginated, sortable, searchable |
| Filter by status | Active / Unsubscribed / All |
| Export | CSV and JSON; records flagged `exported: true` on export |
| Export flag management | Clear export flag per-row or bulk "Clear all" |
| Admin unsubscribe | One-click unsubscribe per row; reversal (re-activate) available |
| GDPR delete | Hard-delete individual subscriber records |
| Deduplication control | Settings tab: allow duplicate emails with configurable multi-field unique key (e.g. email + first name) |

### Embed & distribution
| Feature | Details |
|---|---|
| iframe embed | `<iframe src="https://domain.com/{slug}/embed">` — styled, responsive |
| Script-tag embed | `<script src=".../embed.js">` auto-creates iframe, no jQuery |
| Custom slug | Each form has a unique URL slug |
| Multi-form | Unlimited forms; each with independent design, fields, subscribers |

### Email
| Feature | Details |
|---|---|
| Welcome email | HTML email sent on signup via SMTP (Nodemailer) |
| Subject + HTML body | Editable in Settings tab |
| Merge tags | `{{email}}`, `{{firstName}}`, `{{formName}}`, `{{unsubscribeUrl}}` |
| Unsubscribe URL | Points to `/unsubscribe?token=…&email=…` |

### Authentication
| Feature | Details |
|---|---|
| Auth0 OIDC | Production auth via Auth0, role-based (`signflow-admin`) |
| Secure cookies | `secure: true`, `httpOnly`, `sameSite: lax` |
| Proxy trust | `app.set('trust proxy', 1)` for Nginx HTTPS |

---

## 3. Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Runtime | Node.js | 20 LTS |
| Web framework | Express | 4.x |
| Auth | openid-client (Auth0 OIDC) | 5.x |
| Email | Nodemailer | latest |
| File uploads | Multer | latest |
| Process manager | PM2 | latest |
| Reverse proxy | Nginx | latest |
| TLS | Let's Encrypt (Certbot) | latest |
| Hosting | AWS Lightsail | Ubuntu 24.04 |
| Admin SPA | Vanilla JS (no build step) | — |
| UI icons | Google Material Icons Round | CDN |
| Fonts | Google Fonts API | CDN |
| Storage | JSON flat files | — |

### Intentional architectural choices

- **Single `server.js` file** (~1700+ lines) — deliberate; avoids module-split complexity for a single-developer project. All business logic is co-located and easy to navigate.
- **Single `admin/index.html` file** — full SPA with no bundler, no framework, no npm. Edit and deploy with no build step.
- **JSON flat files** — zero database setup, trivial backup (copy a directory), human-readable data. The tradeoff is no concurrent-write safety and limited query capability. See [Enterprise Roadmap §12](#12-enterprise-roadmap) for PostgreSQL migration path.

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Browser                                                │
│  ┌──────────────────┐   ┌──────────────────────────┐   │
│  │  Public Form     │   │  Admin SPA               │   │
│  │  /:slug          │   │  /admin (Auth0 protected)│   │
│  │  /:slug/embed    │   │  admin/index.html        │   │
│  └────────┬─────────┘   └────────────┬─────────────┘   │
└───────────┼──────────────────────────┼─────────────────┘
            │ HTTPS                    │ HTTPS + Auth cookie
            ▼                          ▼
┌─────────────────────────────────────────────────────────┐
│  Nginx (reverse proxy, TLS termination)                 │
│  Port 80/443 → proxy_pass localhost:3000                │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP (internal)
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Express (server.js) — Port 3000                        │
│                                                         │
│  Routes:                                                │
│  GET  /                  → redirect to first form       │
│  GET  /:slug             → renderPublicPage()           │
│  POST /:slug/subscribe   → validate + save + email      │
│  GET  /:slug/embed       → renderEmbedPage()            │
│  GET  /:slug/embed.js    → embed script                 │
│  GET  /unsubscribe       → mark unsubscribed            │
│  GET  /delete-data       → GDPR hard delete             │
│  GET  /privacy           → privacy policy page          │
│  GET  /admin             → serve admin/index.html       │
│  /api/admin/*            → Auth0-protected REST API     │
│                                                         │
│  Middleware:                                            │
│  express-rate-limit      → 10 subs/15min/IP             │
│  multer                  → image + font uploads         │
│  express-session         → Auth0 session storage        │
│  openid-client           → Auth0 OIDC flow              │
└───────────────────┬────────────────┬────────────────────┘
                    │                │
          ┌─────────▼──────┐  ┌──────▼──────────┐
          │  data/ (JSON)  │  │  public/uploads/ │
          │                │  │                  │
          │  forms-index   │  │  images/         │
          │  forms/{slug}  │  │  fonts/          │
          │  subscribers-* │  │                  │
          │  design-tpl    │  │                  │
          │  media-shared  │  │                  │
          │  fonts-shared  │  │                  │
          └────────────────┘  └──────────────────┘
```

### Request flow — form submission

```
1. Browser POST /:slug/subscribe
2. submitLimiter (rate limit: 10/15min/IP)
3. Validate required fields + email format
4. Check duplicate (email already in subscribers-{slug}.json)
5. Build subscriber record { id, email, fields, status, consentAt, ip, token }
6. Append to data/subscribers-{slug}.json
7. sendWelcomeEmail() → Nodemailer → SMTP
8. Render success page (or redirect to confirmation URL)
```

### Admin auth flow (Auth0 OIDC)

```
1. GET /admin → requireAuth middleware → session check
2. No session → redirect /auth/login
3. /auth/login → Auth0 authorize endpoint
4. Auth0 → POST /auth/callback → exchange code → get tokens
5. Check roles claim (https://signflow/roles includes 'signflow-admin')
6. Store user in session → redirect /admin
7. All /api/admin/* routes protected by adminAuth middleware
```

---

## 5. Data Model

### `data/forms-index.json`
```json
[
  { "slug": "default", "name": "My Newsletter", "createdAt": "2026-01-01T00:00:00.000Z" }
]
```

### `data/forms/{slug}.json` — Form config
```json
{
  "slug": "default",
  "site": {
    "title": "My Newsletter",
    "description": "Subscribe for updates",
    "logoUrl": "/uploads/logo.png",
    "faviconUrl": "",
    "privacyPolicyUrl": "",
    "emailFrom": "hello@example.com",
    "emailFromName": "My Newsletter",
    "emailSubject": "Welcome to {{formName}}!",
    "emailBodyHtml": "<p>Hi {{firstName}}, thanks for subscribing!</p>",
    "smtpHost": "smtp.example.com",
    "smtpPort": 587,
    "smtpUser": "user@example.com",
    "smtpPass": "••••••••",
    "smtpSecure": false,
    "confirmationRedirectUrl": "",
    "submitDisclaimerHtml": ""
  },
  "design": {
    "googleFont": "Lato",
    "h1Font": "Playfair Display",
    "bodyFont": ["Lato"],
    "btnFont": "",
    "primaryColor": "#1a1a2e",
    "accentColor": "#e94560",
    "textColor": "#333333",
    "bgColor": "#ffffff",
    "fieldBg": "#fafafa",
    "btnBg": "",
    "btnTextColor": "#ffffff",
    "linkColor": "#e94560",
    "borderColor": "#dddddd",
    "customFonts": [],
    "brandColors": []
  },
  "fields": [
    {
      "id": "f_abc123",
      "type": "email",
      "label": "Email address",
      "placeholder": "you@example.com",
      "required": true
    }
  ],
  "sections": [...],
  "confirmationSections": [...],
  "spinWheelSection": null
}
```

### `data/subscribers-{slug}.json` — Subscriber records
```json
[
  {
    "id": "sub_xyz789",
    "email": "user@example.com",
    "fields": { "firstName": "Jane", "phone": "+1234567890" },
    "status": "active",
    "consentAt": "2026-03-11T14:22:00.000Z",
    "ip": "1.2.3.4",
    "token": "tok_abc123",
    "exported": true,
    "exportedAt": "2026-03-11T15:00:00.000Z",
    "unsubscribedAt": null
  }
]
```

**Subscriber field reference:**

| Field | Type | Description |
|---|---|---|
| `id` | string | UUID, generated on signup |
| `email` | string | Subscriber email (indexed for lookups) |
| `fields` | object | Key-value of custom field responses |
| `status` | enum | `active` \| `unsubscribed` |
| `consentAt` | ISO 8601 | Timestamp of consent (GDPR evidence) |
| `ip` | string | IP at time of consent (GDPR evidence) |
| `token` | string | Unique unsubscribe/delete token |
| `exported` | boolean | True if included in a CSV/JSON export |
| `exportedAt` | ISO 8601 | Timestamp of last export |
| `unsubscribedAt` | ISO 8601 \| null | Timestamp of unsubscribe action |

### `data/design-templates.json`
```json
[
  {
    "id": "tpl_abc",
    "name": "Dark Mode",
    "design": { ...design object... },
    "createdAt": "2026-03-01T00:00:00.000Z"
  }
]
```

### `data/media-shared.json`
```json
[
  {
    "id": "med_abc",
    "filename": "hero.jpg",
    "url": "/uploads/hero.jpg",
    "folder": "logos",
    "uploadedAt": "2026-03-01T00:00:00.000Z"
  }
]
```

### `data/fonts-shared.json`
```json
[
  {
    "id": "fnt_abc",
    "name": "BrandSans",
    "url": "/uploads/fonts/BrandSans.woff2",
    "uploadedAt": "2026-03-01T00:00:00.000Z"
  }
]
```

---

## 6. Installation & Deployment

### Prerequisites
- Ubuntu 22.04 or 24.04 (AWS Lightsail recommended)
- Node.js 20
- PM2
- Nginx
- Auth0 free-tier account

### Step 1 — Server setup

```bash
sudo apt update && sudo apt upgrade -y

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# PM2
sudo npm install -g pm2

# Clone project
git clone https://github.com/your-user/signflow.git ~/signflow
cd ~/signflow
npm install
```

### Step 2 — Environment variables

Create `.env` in the project root (never commit this file):

```bash
PORT=3000
SESSION_SECRET=<long-random-string>

# Auth0
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=<client-id>
AUTH0_CLIENT_SECRET=<client-secret>
AUTH0_CALLBACK_URL=https://yourdomain.com/auth/callback
```

### Step 3 — Auth0 setup

1. Create an Auth0 application (Regular Web App)
2. Add `https://yourdomain.com/auth/callback` to **Allowed Callback URLs**
3. Add `https://yourdomain.com` to **Allowed Logout URLs** and **Allowed Web Origins**
4. Create an Auth0 **Action** (Login flow) to add role to ID token:
   ```js
   exports.onExecutePostLogin = async (event, api) => {
     const namespace = 'https://signflow/roles';
     const roles = event.authorization?.roles || [];
     api.idToken.setCustomClaim(namespace, roles);
   };
   ```
5. Create role `signflow-admin` in Auth0 dashboard and assign to your user

### Step 4 — Start with PM2

```bash
pm2 start server.js --name signflow
pm2 save
pm2 startup   # follow printed command
```

### Step 5 — Nginx reverse proxy

```bash
sudo apt install -y nginx
sudo nano /etc/nginx/sites-available/signflow
```

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    client_max_body_size 20M;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/signflow /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Step 6 — TLS (Let's Encrypt)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### Step 7 — Open firewall (Lightsail console)

Networking → Add rules: HTTP (80), HTTPS (443)

### Step 8 — Automated backups

```bash
crontab -e
# Daily backup of all data:
0 2 * * * tar czf /home/ubuntu/backups/signflow-data-$(date +\%Y\%m\%d).tar.gz /home/ubuntu/signflow/data/
# Retain 30 days:
0 3 * * * find /home/ubuntu/backups/ -name "signflow-data-*.tar.gz" -mtime +30 -delete
```

---

## 7. Configuration Reference

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | No | `3000` | Express listen port |
| `SESSION_SECRET` | Yes | — | Express session signing secret |
| `AUTH0_DOMAIN` | Yes | — | Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Yes | — | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | Yes | — | Auth0 application client secret |
| `AUTH0_CALLBACK_URL` | Yes | — | Full callback URL registered in Auth0 |

### Per-form SMTP settings (stored in form config)

| Setting | Description |
|---|---|
| `smtpHost` | SMTP server hostname |
| `smtpPort` | Typically 587 (STARTTLS) or 465 (SSL) |
| `smtpUser` | SMTP login username |
| `smtpPass` | SMTP login password |
| `smtpSecure` | Boolean — true for port 465 |
| `emailFrom` | From address |
| `emailFromName` | From display name |
| `emailSubject` | Subject line (supports merge tags) |
| `emailBodyHtml` | HTML body (supports merge tags) |

### Email merge tags

| Tag | Replaced with |
|---|---|
| `{{email}}` | Subscriber's email address |
| `{{firstName}}` | First custom field of type text, or email prefix |
| `{{formName}}` | Form title (`cfg.site.title`) |
| `{{unsubscribeUrl}}` | Full `/unsubscribe?token=…&email=…` URL |

---

## 8. API Reference

All `/api/admin/*` routes require a valid Auth0 session cookie. All request/response bodies are JSON.

### Forms

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/forms` | List all forms `[{slug, name, createdAt}]` |
| `POST` | `/api/admin/forms` | Create form `{name}` → `{slug, name}` |
| `GET` | `/api/admin/forms/:slug` | Get full form config |
| `POST` | `/api/admin/forms/:slug` | Save/update form config |
| `DELETE` | `/api/admin/forms/:slug` | Delete form and all its subscriber data |
| `POST` | `/api/admin/forms/:slug/rename` | Rename form `{name}` |

### Subscribers

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/forms/:slug/subscribers` | Paginated list. Query: `?page=1&limit=50&search=&status=` |
| `DELETE` | `/api/admin/forms/:slug/subscribers/:id` | GDPR hard delete |
| `POST` | `/api/admin/forms/:slug/subscribers/:id/unsubscribe` | Admin-initiated unsubscribe |
| `POST` | `/api/admin/forms/:slug/subscribers/:id/reactivate` | Reactivate unsubscribed record |
| `POST` | `/api/admin/forms/:slug/subscribers/:id/clear-export` | Clear exported flag on one record |
| `POST` | `/api/admin/forms/:slug/subscribers/clear-all-exports` | Clear exported flag on all records |

#### GET subscribers response
```json
{
  "subscribers": [...],
  "total": 1234,
  "page": 1,
  "limit": 50,
  "pages": 25
}
```

### Export

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/forms/:slug/export` | Export subscribers. Query: `?format=csv` or `?format=json`. Sets `exported:true` on all exported records. |

### Media

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/admin/forms/:slug/upload` | Upload image file. Returns `{url, id, filename}` |
| `GET` | `/api/admin/media` | List shared media library `[{id, url, filename, folder}]` |
| `POST` | `/api/admin/media/:id/rename` | Rename media item `{name}` |
| `POST` | `/api/admin/media/:id/folder` | Move to folder `{folder}` |
| `DELETE` | `/api/admin/media/:id` | Delete media item and file |
| `GET` | `/api/admin/media/folders` | List all folder names |
| `POST` | `/api/admin/media/folders` | Create folder `{name}` |
| `DELETE` | `/api/admin/media/folders/:name` | Delete folder (items move to root) |

### Fonts

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/admin/forms/:slug/upload-font` | Upload font file. Body: `{font, name, shared}`. Returns `{url, shared}` |
| `GET` | `/api/admin/fonts` | List shared font library |
| `DELETE` | `/api/admin/fonts/:id` | Delete font from shared library |

### Design Templates

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/design-templates` | List templates |
| `POST` | `/api/admin/design-templates` | Save template `{name, design}` |
| `DELETE` | `/api/admin/design-templates/:id` | Delete template |

### Public routes (no auth)

| Method | Path | Description |
|---|---|---|
| `GET` | `/:slug` | Render public form page |
| `POST` | `/:slug/subscribe` | Submit signup form |
| `GET` | `/:slug/embed` | Render embeddable iframe page |
| `GET` | `/:slug/embed.js` | Embed script (auto-creates iframe) |
| `GET` | `/unsubscribe` | Unsubscribe by token+email |
| `GET` | `/delete-data` | GDPR data deletion by token+email |
| `GET` | `/privacy` | Auto-generated privacy policy page |

---

## 9. Admin Panel Guide

The admin panel is a single-page application served at `/admin`. It is a single HTML file (`admin/index.html`) with all JS and CSS inlined.

### Top navigation

| Tab | Description |
|---|---|
| **Forms** | List of all forms; create / delete / switch between forms |
| **Help** | Searchable accordion: Getting Started, Form Builder, Design, Subscribers, Embed, Email, Settings, Keyboard Shortcuts, Enterprise Roadmap |

### Form subnav (active form)

| Tab | Description |
|---|---|
| **Build** | Visual form builder — drag blocks, edit fields, live preview |
| **Subscribers** | Subscriber table with search, filter, export, delete, unsubscribe |
| **Embed** | Embed code snippets + iframe/script preview |
| **Settings** | SMTP, email template, form metadata |
| **Media** | Shared media library (upload, organise, delete) |

### Build tab

The build panel has two areas:
- **Block palette** (left) — drag or click to add block types
- **Canvas** (right) — live iframe preview; blocks listed in order

**Sections:** The form is divided into sections (hero, form body, confirmation, spin wheel). Each section can be toggled on/off.

**Containers:** A container block holds a 1- or 2-column layout. Drop any block type into a column cell.

**Field blocks:** Click to edit field type, label, placeholder, validation, options. Use the format button (paint icon) to set per-field label colour, text colour, background, font family, font size.

**Submit blocks:** Edit button text, colour, text colour per submit block.

### Subscribers tab

- **Search** — live filter by email / field values
- **Status filter** — All / Active / Unsubscribed
- **Export** — Download CSV or JSON; records marked as exported
- **Exported badge** — Green badge on rows that have been exported; × button clears flag
- **Clear all exports** — Bulk clear export flags; button enabled only when ≥1 record flagged
- **Unsubscribe / Re-activate** — Per-row action buttons
- **Delete** — Hard GDPR delete; irreversible

### Settings tab

- **SMTP** — Host, port, user, password, from name/address
- **Email** — Subject line, HTML body editor (rich text modal)
- **Form metadata** — Title, description, redirect URL on confirm
- **Embed domain** — Allowed embed domain for CSP (future)

---

## 10. Security

### Current controls

| Control | Implementation |
|---|---|
| Authentication | Auth0 OIDC; role-checked on every admin request |
| Session | `express-session`; `httpOnly`, `secure`, `sameSite:lax`; signed with `SESSION_SECRET` |
| Rate limiting | `express-rate-limit`: 10 signups / 15 min / IP per form |
| Input sanitisation | HTML-encode all user-supplied values before rendering in pages |
| File upload restrictions | Multer: image types only for media; font types only for fonts; 10 MB limit |
| Unsubscribe tokens | UUID v4, stored per subscriber, validated on unsubscribe/delete |
| Environment secrets | `.gitignore` excludes `.env`; SMTP passwords stored in server-side JSON only |
| HTTPS | Enforced via Nginx + Let's Encrypt |
| Proxy trust | `app.set('trust proxy', 1)` + `X-Forwarded-For` for accurate IP rate limiting |

### Threat model

| Threat | Current mitigation | Gap |
|---|---|---|
| Brute-force signup | Rate limit 10/15min/IP | No CAPTCHA |
| Admin credential theft | Auth0 (MFA available) | Session fixation not explicitly mitigated |
| XSS via form fields | Field values HTML-escaped in rendered pages | WYSIWYG blocks render raw HTML — admin-only |
| SQL injection | No SQL database | N/A |
| Path traversal in uploads | Multer auto-generates filenames | Filename sanitisation not explicit |
| CSRF | SameSite cookies | No explicit CSRF token on POST routes |
| DoS on upload | 10 MB file size limit | No total disk quota enforcement |
| Data breach | Flat files on disk | No encryption at rest |
| Dependency vulnerabilities | Manual `npm audit` | No automated scanning |

> See [Enterprise Roadmap](#12-enterprise-roadmap) for planned mitigations.

---

## 11. GDPR & Data Protection

### Data collected per subscriber

| Data | Purpose | Legal basis |
|---|---|---|
| Email address | Primary identifier, communication | Consent |
| Custom field values | Personalisation | Consent |
| Consent timestamp | Proof of consent | Legal obligation |
| IP address at signup | Proof of consent | Legitimate interest |
| Unsubscribe token | Enable self-service withdrawal | Legal obligation |

### Rights fulfilment

| Right | How fulfilled |
|---|---|
| Right to access | Export CSV/JSON contains all records |
| Right to erasure | DELETE `/api/admin/forms/:slug/subscribers/:id` hard-deletes record |
| Right to withdraw consent | `/unsubscribe?token=&email=` sets `status: unsubscribed` |
| Right to object | Admin can manually unsubscribe any record |

### Privacy policy

Auto-generated at `/privacy` using form title and contact details. Covers: data collected, legal basis, retention, rights, contact.

### Data retention

No automated retention policy currently enforced. Recommended: archive or delete subscribers inactive for 24+ months. See [Enterprise Roadmap §12.4](#phase-4--gdpr--compliance-tooling) for planned consent audit trail and automated retention.

### GDPR operator responsibilities

As the platform operator you are the **data controller**. You must:
- Maintain a Record of Processing Activities (RoPA)
- Ensure a Data Processing Agreement (DPA) with your SMTP provider
- Not transfer subscriber data outside your jurisdiction without adequate safeguards
- Respond to data subject requests within 30 days

---

## 12. Enterprise Roadmap

The current architecture is production-ready for small-to-medium deployments (up to ~100k subscribers per form). The roadmap below describes the path to an enterprise-grade, multi-tenant SaaS platform.

---

### Phase 1 — Security Hardening

**Priority: High. Effort: Low–Medium.**

| Item | Description |
|---|---|
| CSRF tokens | Add `csurf` middleware; token in all POST forms and AJAX headers |
| Content Security Policy | Strict CSP header via Nginx or `helmet`; allowlist CDN domains |
| HTTP security headers | `helmet` middleware: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Rate limiting expansion | CAPTCHA (hCaptcha or Cloudflare Turnstile) on public submit route |
| File upload hardening | Validate MIME type from buffer (not just extension); sanitise filename; enforce per-user disk quota |
| Dependency scanning | Add `npm audit` to CI; integrate Dependabot or Snyk |
| Penetration testing | Annual external pentest; automated OWASP ZAP scan in CI |
| Secrets management | Migrate from `.env` to AWS Secrets Manager or HashiCorp Vault |
| Log sanitisation | Strip PII (emails, IPs) from application logs |
| Admin IP allowlist | Nginx `allow`/`deny` for `/admin` and `/api/admin/*` |

---

### Phase 2 — Database & Storage Migration

**Priority: High. Effort: High.**

Current JSON flat files will not scale past ~50k subscribers per form without noticeable latency, and offer no concurrent-write safety.

| Item | Description |
|---|---|
| PostgreSQL | Migrate all JSON files to PostgreSQL 16; managed via AWS RDS or Lightsail Managed Database |
| Schema | `forms`, `subscribers`, `design_templates`, `media`, `fonts`, `audit_log` tables |
| ORM | Knex.js (query builder) or Prisma (typed ORM); keep single-file philosophy with one db.js module |
| Migrations | `knex migrate:latest` on startup |
| Redis | Cache rendered public pages (TTL: 60s); rate-limit counters; session store |
| S3 / Object storage | Move `public/uploads/` to S3 or Cloudflare R2; serve via CDN; presigned upload URLs from client |
| Connection pooling | `pg` pool size tuned for Lightsail instance; PgBouncer for larger deployments |
| Read replicas | PostgreSQL read replica for subscriber export queries |

---

### Phase 3 — Authentication & RBAC

**Priority: Medium. Effort: Medium.**

| Item | Description |
|---|---|
| SSO / SAML 2.0 | Auth0 Enterprise SAML connections; allow corporate IdPs (Okta, Azure AD, Google Workspace) |
| SCIM provisioning | Auto-provision / deprovision admin users via corporate directory |
| MFA enforcement | Require MFA for all admin users via Auth0 policy |
| Role-based access control | Roles: `super-admin`, `admin`, `editor`, `viewer`; per-form permission scoping |
| API keys | Machine-to-machine API keys for export API and webhooks; scoped permissions; expiry |
| Audit log | Immutable log of all admin actions (who, what, when, IP) stored in DB |
| Session hardening | Absolute session expiry (8h); idle timeout (1h); session invalidation on password change |

---

### Phase 4 — GDPR & Compliance Tooling

**Priority: Medium. Effort: Medium.**

| Item | Description |
|---|---|
| Consent audit trail | Immutable consent records with IP, timestamp, form version, field snapshot |
| Double opt-in | Confirmation email flow before subscriber is activated |
| Data retention policies | Per-form retention period; automated archival/deletion job |
| Subject access request (SAR) | Admin tool: enter email → generate GDPR data package (JSON zip) |
| Right to erasure | Bulk GDPR delete by email across all forms |
| Data Processing Agreements | DPA template generator for SMTP providers |
| Cookie consent v2 | IAB TCF 2.2 compliant cookie banner |
| Privacy policy generator | Dynamic policy from form config + jurisdiction selector |
| Data residency | EU/US/APAC region selection; data stays in selected region |

---

### Phase 5 — Integrations & Export API

**Priority: Medium. Effort: Medium.**

| Item | Description |
|---|---|
| REST API (public) | OpenAPI 3.0 spec; subscriber CRUD; webhook management; API key auth |
| Webhooks | POST to configured URL on: `subscriber.created`, `subscriber.unsubscribed`, `subscriber.deleted` |
| ESP integrations | Mailchimp, Klaviyo, ConvertKit, ActiveCampaign, Brevo — two-way sync |
| CRM integrations | HubSpot, Salesforce — push new subscribers as contacts |
| Zapier / Make | Certified Zapier app; Make.com connector |
| Google Sheets | Live sync: new subscribers appended to a Google Sheet |
| n8n / self-hosted automation | Webhook-compatible; documented in integration guide |
| Import | Bulk CSV import with field mapping UI; duplicate detection |

---

### Phase 6 — Analytics & Performance

**Priority: Low–Medium. Effort: High.**

| Item | Description |
|---|---|
| Signup analytics | Time-series chart of signups per form; source tracking (UTM params) |
| Email analytics | Open rate, click rate (pixel + link tracking via own proxy) |
| A/B testing | Test two form variants (design or copy); auto-select winner by conversion rate |
| Heatmaps | Field completion funnel; drop-off analysis |
| Geo analytics | Country/city breakdown of signups (IP geolocation) |
| Edge rendering | Cloudflare Workers for public form pages; sub-50ms TTFB globally |
| CDN | Static assets (CSS, fonts, images) via Cloudflare CDN |
| Horizontal scaling | Stateless Express app + shared PostgreSQL + Redis; deploy behind load balancer |
| Docker / container | Official Docker image + docker-compose.yml for easy self-hosted deploys |

---

### Phase 7 — Multi-Tenant SaaS & Monetisation

**Priority: Low. Effort: Very High.**

| Item | Description |
|---|---|
| Multi-tenancy | Row-level tenancy in PostgreSQL; tenant isolation enforced at query layer |
| Billing | Stripe integration; per-tenant plans (subscriber count tiers) |
| Tenant onboarding | Self-serve signup; provisioning automation |
| White-label domains | Custom domain per tenant; automated Let's Encrypt via cert manager |
| Usage metering | Track signups, emails sent, storage per tenant; enforce plan limits |
| Admin super-console | Cross-tenant oversight; impersonation (with audit log) |
| Reseller programme | Reseller accounts with sub-tenant management |
| SLA & uptime | 99.9% SLA target; multi-AZ PostgreSQL; health dashboard |

---

## Appendix A — Key Functions (server.js)

| Function | Description |
|---|---|
| `defaultFormConfig()` | Returns template for a new form with all default values (includes `allowDuplicateEmail`, `uniqueKeyFields`) |
| `readFormConfig(slug)` | Reads form config from PostgreSQL `forms` table |
| `writeFormConfig(slug, cfg)` | Upserts form config in `forms` table |
| `renderPublicPage(cfg, sharedFonts, templates)` | Returns full HTML for public-facing form page |
| `renderEmbedPage(cfg, sharedFonts)` | Returns full HTML for iframe embed version |
| `renderBlockElement(el, cfg)` | Renders a single top-level section block to HTML (WYSIWYG output sanitised via `sanitize-html`) |
| `renderFormField(field, cfg)` | Renders a single form field element; supports text, select, checkbox, textarea, age, date, year, yearmonth, yearmonthday, slider, iconselect |
| `sliderPickerCSS(accent)` | Generates CSS for all custom field types (picker drums, sliders, icon tiles, grid layout) |
| `sliderPickerJS()` | Generates client JS for picker drums (year/month/day), sliders (linear/angled/arc) and icon tile selection |
| `sendWelcomeEmail(cfg, subscriber)` | Sends HTML welcome email via Nodemailer; respects `bodyFontSize` design token |
| `replaceMergeTags(text, cfg, sub, url)` | Replaces `{{tag}}` placeholders in email subject/body |
| `customFontFaceCSS(cfg, sharedFonts)` | Generates `@font-face` CSS for all custom fonts (shared + form) |
| `googleFontTag(cfg, sharedFonts, effectiveDesign)` | Generates Google Fonts `<link>` tag, skipping custom font names |
| `readSharedFonts()` | Fetches shared font records from PostgreSQL |
| `findSubscriberByToken(slug, token)` | Looks up subscriber by unsubscribe token |
| `findAllSubscriptions(email)` | Returns all active/inactive subscriptions for an email across all forms |
| `adminAuth` middleware | Verifies Auth0 session + `signflow-admin` role |
| `submitLimiter` | express-rate-limit: 10 subs/15min per IP+slug; dynamic duplicate check uses `cfg.site.uniqueKeyFields` |
| `authLimiter` | express-rate-limit: 20 attempts/15min on `/auth/login` and `/auth/callback` |

---

## Appendix B — Key Functions (admin/index.html)

| Function | Description |
|---|---|
| `switchTab(tab, el)` | Switches active top-level or form sub-tab |
| `loadForms()` | Fetches forms index; renders form list |
| `loadForm(slug)` | Loads full form config; renders all tabs |
| `saveForm()` | POSTs current `cfg` to `/api/admin/forms/:slug` |
| `schedulePreview()` | Debounced (300ms) iframe preview refresh |
| `buildPicker(id, label, key)` | Renders a BCP + hex input color picker for a design token |
| `buildFontPickers()` | Renders font family dropdowns for all font tokens |
| `_allCustomFonts()` | Returns merged array of shared + form custom fonts |
| `loadSharedFonts()` | Fetches shared font library from API |
| `handleFontUpload(input)` | Handles font file upload; supports shared/form scope |
| `removeCustomFont(source, id)` | Deletes font from shared library or form config |
| `renderCustomFontList()` | Renders font list UI in the font modal |
| `openMediaPicker(mode)` | Opens media picker modal (insert or manage mode) |
| `loadMediaLibrary()` | Fetches and renders shared media items |
| `renderBlockList()` | Re-renders the build panel block list |
| `renderSectionBlock(s)` | Renders a section card with its block items |
| `addBlock(type, sectionId)` | Adds a new block to a section |
| `deleteBlock(sectionId, blockId)` | Removes a block |
| `moveBlock(dir, sectionId, blockId)` | Moves block up/down within section |
| `openFieldModal(fieldId)` | Opens field editor modal; populates type-specific groups including `iconselect` and `yearmonthday` |
| `saveField()` | Saves field edits back to `cfg.fields`; collects all type-specific props |
| `iselRenderItems()` | Re-renders the icon selector tile list in the field modal |
| `iselAddItem()` | Appends a blank tile row to `_iselItems` |
| `iselOnLayoutChange()` | Shows/hides grid options (columns, fill direction) based on layout mode |
| `openIconPicker(rowIdx)` | Opens the Material icon picker modal for tile row `rowIdx` |
| `filterIconGrid(q)` | Filters the 180+ icon grid by search query |
| `selectPickerIcon(name)` | Inserts selected icon name into the tile row and closes picker |
| `toggleDupKeyFields()` | Shows/hides key-field checkboxes based on "allow duplicate emails" toggle |
| `renderDupKeyCheckboxes()` | Renders form field checkboxes for the unique-key selector |
| `toggleDupKeyField(cb)` | Adds/removes a field ID from `cfg.site.uniqueKeyFields` |
| `openFormatModal(type, id)` | Opens formatting modal for field/submit blocks |
| `saveFormatModal()` | Saves format overrides back to block element |
| `openEmailBodyWysiwyg()` | Opens rich text modal for email HTML body |
| `openWysiwygModal(key, title)` | Generic WYSIWYG modal bound to a cfg key |
| `openDesignTemplateModal()` | Opens save/apply/delete design template modal |
| `applyDesignTemplate(id)` | Applies saved template to current form design |
| `loadSubscribers()` | Fetches and renders subscriber table |
| `exportSubscribers(format)` | Triggers CSV or JSON download |
| `clearExportFlag(id)` | Clears exported flag on one subscriber record |
| `clearAllExportFlags()` | Clears exported flag on all records |
| `adminUnsubscribe(id)` | Admin-initiated unsubscribe for one subscriber |
| `adminReactivate(id)` | Re-activates an unsubscribed subscriber |
| `toggleHelp(head)` | Opens/closes a Help accordion group |
| `filterHelp(q)` | Filters Help sections by search query |

---

*Last updated: 2026-03-12 · SignFlow v2.1*
