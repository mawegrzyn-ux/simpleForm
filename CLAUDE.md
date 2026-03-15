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
- Stack: Node.js 20, Express 4, PostgreSQL 16, Amazon S3, PM2, Nginx, Auth0 OIDC.
