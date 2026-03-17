# SignFlow — Claude Instructions

## Environment
- **No local dev server possible.** This machine has no POSIX shell (SHELL=GitHubDesktop.exe) and no node_modules installed locally.
- Do NOT attempt `preview_start`, `npm install`, or any Bash commands.
- Do NOT call preview_* tools — they will fail.
- Verify code changes **statically** (Read/Grep the edited files to confirm correctness).
- The user deploys to AWS Lightsail (wingvibes.com) by pushing to git and running `git pull` on the server.

## Project
- `server.js` — single large file (~3000+ lines), intentional, no module splitting.
- `admin/index.html` — single-file vanilla JS SPA, no build step.
- `admin/integrations/index.html` — standalone SPA at `/admin/integrations` (integration health board).
- `admin/reports/index.html` — standalone SPA at `/admin/reports` (analytics & reports).
- `routes/integrations.js` — Express router mounted at `/api/admin/integrations` (status, test, config).
- `routes/reports.js` — Express router mounted at `/api/admin/reports` (summary, subscribers, forms, email, export).
- Stack: Node.js 20, Express 4, PostgreSQL 16, Amazon S3, PM2, Nginx, Auth0 OIDC.

## Key DB Tables (PostgreSQL — `DATABASE_URL` in .env)
| Table | Purpose |
|-------|---------|
| `forms` | Form configs (slug PK, name, config JSONB, status, testing_pin) |
| `subscribers` | Subscriber records per form |
| `media` | S3 image/file references |
| `fonts` | Custom font uploads |
| `design_templates` | Saved design presets |
| `analytics` | Per-form event counters |
| `isel_presets` | Tile/icon-select named presets |
| `ip_flags` | Rate-limit / CAPTCHA trip records |
| `email_log` | Email send history |
| `audit_log` | Admin action audit trail |
| `markets` | Market/tenant groups |
| `sf_users` | Auth0-linked admin users |
| `user_markets` | User↔market role assignments |
| `form_markets` | Form↔market assignments |
| `global_settings` | Platform-wide settings (CAPTCHA keys etc.) |
| `bug_reports` | Feedback submitted via AI assistant — bugs, change requests, feature ideas. Columns: id (UUID), type (bug/change/feature), title, description, steps, context (JSONB — tab/form at time of report), reported_by (email), status (open/in-progress/resolved/wont-fix), created_at, updated_at. Admin routes: GET/PATCH/DELETE /api/admin/bug-reports. UI: Help → Feedback tab. |
| `session` | Express sessions (connect-pg-simple) |

## Internal Read-Only API (Claude Code access)
`GET https://wingvibes.com/api/internal/feedback?key=<INTERNAL_API_KEY>`
- Optional filters: `&type=bug|change|feature` `&status=open|in-progress|resolved|wont-fix` `&limit=N`
- Key stored in Lightsail `.env` as `INTERNAL_API_KEY` — never committed
- Use WebFetch to call this from Claude Code sessions when the user wants to review feedback data
- Temporary bridge until PostgreSQL MCP server is configured
