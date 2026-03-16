"""
SignFlow — Security & Data Protection PDF generator
Run: python gen_security_pdf.py
Requires: pip install reportlab
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak, KeepTogether)
from reportlab.lib.enums import TA_CENTER
import datetime

OUTPUT = "SignFlow_Security_DataProtection.pdf"

BRAND   = colors.HexColor('#4f46e5')
BRAND_L = colors.HexColor('#ede9fe')
OK      = colors.HexColor('#166534')
WARN    = colors.HexColor('#92400e')
DARK    = colors.HexColor('#1e1b4b')
MID     = colors.HexColor('#4b5563')
LIGHT   = colors.HexColor('#f8fafc')
BRD     = colors.HexColor('#e2e5ea')

doc = SimpleDocTemplate(
    OUTPUT, pagesize=A4,
    topMargin=2*cm, bottomMargin=2.2*cm,
    leftMargin=2.2*cm, rightMargin=2.2*cm,
    title="SignFlow - Security & Data Protection",
    author="SignFlow / Obscure Kitty",
)
W = A4[0] - 4.4*cm

def S(name, **kw):
    return ParagraphStyle(name, **kw)

TITLE_S   = S('T', fontName='Helvetica-Bold', fontSize=26, textColor=DARK,  spaceAfter=4,  leading=30)
SUB_S     = S('Su',fontName='Helvetica',      fontSize=11, textColor=MID,   spaceAfter=2,  leading=14)
DATE_S    = S('D', fontName='Helvetica',      fontSize=9,  textColor=MID,   spaceAfter=0)
H2_S      = S('H2',fontName='Helvetica-Bold', fontSize=10, textColor=DARK,  spaceAfter=3,  spaceBefore=8,  leading=13)
BODY_S    = S('B', fontName='Helvetica',      fontSize=9,  textColor=MID,   spaceAfter=3,  leading=13)
BOLD_S    = S('Bo',fontName='Helvetica-Bold', fontSize=9,  textColor=DARK,  spaceAfter=2,  leading=13)
SMALL_S   = S('Sm',fontName='Helvetica',      fontSize=8,  textColor=MID,   spaceAfter=2,  leading=11)
CAP_S     = S('C', fontName='Helvetica-Oblique', fontSize=8, textColor=MID, spaceAfter=6,  leading=11)

def bullet(text):
    return Paragraph(f'<bullet>&bull;</bullet> {text}',
        ParagraphStyle('bl', parent=BODY_S, leftIndent=14, bulletIndent=6, spaceAfter=2))

def sp(h=4):
    return Spacer(1, h)

def hr(col=BRD, t=0.5):
    return HRFlowable(width='100%', thickness=t, color=col, spaceAfter=6, spaceBefore=2)

def sec(title):
    t = Table([[Paragraph(title, ParagraphStyle('sh', fontName='Helvetica-Bold',
                fontSize=11, textColor=BRAND, leading=14))]], colWidths=[W])
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0,0),(-1,-1), BRAND_L),
        ('TOPPADDING',   (0,0),(-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ('LEFTPADDING',  (0,0),(-1,-1), 10),
        ('RIGHTPADDING', (0,0),(-1,-1), 10),
    ]))
    return t

def plain_table(data, widths, header_dark=True):
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ('BACKGROUND',   (0,0),(-1,0),  DARK if header_dark else BRAND),
        ('TEXTCOLOR',    (0,0),(-1,0),  colors.white),
        ('FONTNAME',     (0,0),(-1,0),  'Helvetica-Bold'),
        ('FONTNAME',     (0,1),(-1,-1), 'Helvetica'),
        ('FONTSIZE',     (0,0),(-1,-1), 8.5),
        ('TOPPADDING',   (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ('LEFTPADDING',  (0,0),(-1,-1), 8),
        ('RIGHTPADDING', (0,0),(-1,-1), 8),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, LIGHT]),
        ('GRID',         (0,0),(-1,-1), 0.4, BRD),
    ]
    t.setStyle(TableStyle(style))
    return t

def on_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setStrokeColor(BRAND); canvas.setLineWidth(2)
    canvas.line(2.2*cm, h-1.4*cm, w-2.2*cm, h-1.4*cm)
    canvas.setFont('Helvetica-Bold', 8); canvas.setFillColor(BRAND)
    canvas.drawString(2.2*cm, h-1.15*cm, 'SignFlow')
    canvas.setFont('Helvetica', 8); canvas.setFillColor(MID)
    canvas.drawRightString(w-2.2*cm, h-1.15*cm, 'Security & Data Protection Summary')
    canvas.setStrokeColor(BRD); canvas.setLineWidth(0.5)
    canvas.line(2.2*cm, 1.6*cm, w-2.2*cm, 1.6*cm)
    canvas.setFont('Helvetica', 7.5); canvas.setFillColor(MID)
    canvas.drawString(2.2*cm, 1.1*cm, 'Confidential -- Obscure Kitty / wingvibes.com')
    canvas.drawRightString(w-2.2*cm, 1.1*cm, f'Page {doc.page}')
    canvas.restoreState()

# ─────────────────────────────────────────────────────────────────────────────
story = []

# Cover
story += [sp(24),
    Paragraph('SignFlow', TITLE_S),
    Paragraph('Security &amp; Data Protection Summary', ParagraphStyle(
        's2', fontName='Helvetica', fontSize=17, textColor=BRAND, spaceAfter=6, leading=22)),
    hr(BRAND, 2), sp(4),
    Paragraph('Platform: wingvibes.com  |  Stack: Node.js 20 / Express 4 / PostgreSQL 16 / Amazon S3 / Auth0 OIDC', SUB_S),
    Paragraph(f'Generated: {datetime.date.today().strftime("%d %B %Y")}', DATE_S),
    sp(16),
]

# Summary status table
status_rows = [
    ['Area', 'Status', 'Key Controls'],
    ['Authentication',      'Strong',   'Auth0 OIDC, PKCE, role-based access'],
    ['Session Security',    'Strong',   'DB-backed, httpOnly, secure, sameSite=lax, 8h expiry'],
    ['Rate Limiting',       'Good',     '10 subs/IP/form/15 min, 20 logins/15 min'],
    ['IP Flagging',         'Good',     'HMAC-SHA256 hash, escalating strikes (1h / 24h / 7d)'],
    ['CAPTCHA',             'Good',     'Stateless HMAC math challenge or hCaptcha'],
    ['Security Headers',    'Moderate', 'Helmet CSP; unsafe-inline required for single-file admin SPA'],
    ['HTTPS / Proxy',       'Good',     'Nginx TLS termination, trust proxy, secure cookies'],
    ['GDPR Compliance',     'Strong',   'UUID unsubscribe tokens, right to erasure, consent records'],
    ['Data Export',         'Good',     'CSV + JSON, export audit trail, quote-escaped'],
    ['SQL Injection',       'Strong',   'Parameterised queries throughout, slug whitelist'],
    ['File Uploads',        'Good',     'MIME check, size limits, UUID keys, direct to S3'],
    ['Email Security',      'Good',     'Sanitised templates, SMTP TLS, unsub footer, all attempts logged'],
    ['Secrets Management',  'Good',     '.env only, never hardcoded, sensitive values masked in UI'],
    ['Audit Logging',       'Strong',   'All admin actions logged with user, timestamp, detail JSON'],
    ['XSS Prevention',      'Strong',   'escapeHtml(), sanitize-html whitelist, CSP'],
]
st = Table(status_rows, colWidths=[W*0.26, W*0.14, W*0.60], repeatRows=1)
ts = [
    ('BACKGROUND',    (0,0),(-1,0),  BRAND),
    ('TEXTCOLOR',     (0,0),(-1,0),  colors.white),
    ('FONTNAME',      (0,0),(-1,0),  'Helvetica-Bold'),
    ('FONTNAME',      (0,1),(0,-1),  'Helvetica-Bold'),
    ('FONTNAME',      (1,1),(-1,-1), 'Helvetica'),
    ('TEXTCOLOR',     (0,1),(-1,-1), MID),
    ('FONTSIZE',      (0,0),(-1,-1), 8.5),
    ('TOPPADDING',    (0,0),(-1,-1), 5), ('BOTTOMPADDING',(0,0),(-1,-1),5),
    ('LEFTPADDING',   (0,0),(-1,-1), 8), ('RIGHTPADDING', (0,0),(-1,-1),8),
    ('ROWBACKGROUNDS',(0,1),(-1,-1), [colors.white, LIGHT]),
    ('GRID',          (0,0),(-1,-1), 0.4, BRD),
    ('LINEBELOW',     (0,0),(-1,0),  1, BRAND),
]
for i, row in enumerate(status_rows[1:], 1):
    if row[1] in ('Strong', 'Good'):
        ts.append(('TEXTCOLOR', (1,i),(1,i), OK))
    elif row[1] == 'Moderate':
        ts.append(('TEXTCOLOR', (1,i),(1,i), WARN))
st.setStyle(TableStyle(ts))
story += [st, sp(8), PageBreak()]

# ── 1. Authentication ────────────────────────────────────────────────────────
story += [sec('1. Authentication & Access Control'), sp(6),
    Paragraph('Auth0 OIDC with PKCE', H2_S),
    Paragraph('All admin access is delegated to Auth0 using OpenID Connect (OIDC). '
        'The authorisation code flow uses PKCE (Proof Key for Code Exchange, S256 method), '
        'preventing authorisation code interception. Nonce, state, and code_verifier are '
        'stored in the server-side session and validated on callback.', BODY_S),
    Paragraph('Role-Based Access Control (RBAC)', H2_S),
] + [bullet(t) for t in [
    'Users must hold the <b>signflow-admin</b> Auth0 role to access the admin panel.',
    'Session is destroyed immediately if the role check fails at callback.',
    'System roles: <b>super-admin</b> (first user) and <b>admin</b>. Super-admin controls global settings.',
    'Market-scoped roles: admin / viewer per market, enforced on all form-level operations.',
]] + [Paragraph('CSRF & Session Integrity', H2_S),
] + [bullet(t) for t in [
    'Per-session CSRF token generated at login: 32 cryptographically random bytes converted to hex.',
    'Auth flow tokens (nonce, state, code_verifier) deleted from session after successful callback.',
    'Sessions stored in PostgreSQL via connect-pg-simple -- survive server restarts without invalidation.',
]] + [Paragraph('Session Cookie Security', H2_S),
    plain_table([
        ['Flag', 'Value', 'Purpose'],
        ['httpOnly', 'true',    'JavaScript cannot read the cookie -- XSS protection'],
        ['secure',   'true',    'Cookie only sent over HTTPS'],
        ['sameSite', 'lax',     'Blocks cross-site request forgery; allows same-site form submits'],
        ['maxAge',   '8 hours', 'Automatic session expiry'],
    ], [W*0.18, W*0.18, W*0.64]),
    sp(8),
]

# ── 2. Rate Limiting ─────────────────────────────────────────────────────────
story += [sec('2. Rate Limiting & IP Flagging'), sp(6),
    Paragraph('Express Rate Limiters', H2_S),
    plain_table([
        ['Limiter', 'Window', 'Max', 'Granularity'],
        ['Form submission', '15 min', '10',  'Per IP + per form slug'],
        ['Admin API',       '15 min', '200', 'Per IP'],
        ['Auth / Login',    '15 min', '20',  'Per IP'],
    ], [W*0.30, W*0.16, W*0.14, W*0.40]),
    sp(6),
    Paragraph('Database-Backed IP Flagging', H2_S),
    Paragraph('Beyond in-memory rate limiting, a persistent IP flagging system records abuse '
        'across server restarts. IP addresses are <b>never stored in plaintext</b> -- they are '
        'hashed with HMAC-SHA256 using a salted session secret before storage in the ip_flags table.', BODY_S),
    plain_table([
        ['Strike Count', 'Flag Level', 'Block Duration'],
        ['1-2 strikes',  'Level 1',    '1 hour'],
        ['3-5 strikes',  'Level 2',    '24 hours'],
        ['6+ strikes',   'Level 3',    '7 days'],
    ], [W*0.33, W*0.33, W*0.34]),
    sp(8),
]

# ── 3. CAPTCHA ───────────────────────────────────────────────────────────────
story += [sec('3. CAPTCHA & Bot Protection'), sp(6),
    Paragraph('Two modes configurable in Global Settings:', BODY_S),
    Paragraph('Built-in Math Challenge (default)', H2_S),
] + [bullet(t) for t in [
    '<b>Stateless</b> -- no server-side storage. Token is HMAC-SHA256 of answer + 10-min time window.',
    'Verification accepts current and previous window (20-minute grace period).',
    'Works with no external dependencies or API keys.',
]] + [Paragraph('hCaptcha Integration (optional)', H2_S),
] + [bullet(t) for t in [
    'Server-side verification against api.hcaptcha.com/siteverify with the remote IP passed.',
    'Secret key stored in the database and masked with dots in all API responses.',
    'Site key exposed to client; secret key never leaves the server.',
]] + [sp(8)]

# ── 4. GDPR ──────────────────────────────────────────────────────────────────
story += [sec('4. GDPR & Data Subject Rights'), sp(6),
    Paragraph('Consent Collection', H2_S),
] + [bullet(t) for t in [
    'Explicit opt-in checkbox required at subscription (configurable per form).',
    '<b>consent_given</b> (boolean) and <b>consent_timestamp</b> (ISO timestamp) recorded per subscriber.',
    'IP address captured at subscription time as part of the consent audit record.',
]] + [Paragraph('Right to Withdraw Consent / Unsubscribe', H2_S),
] + [bullet(t) for t in [
    'Every confirmation email includes a tokenised unsubscribe link.',
    'Token: UUID v4 (128-bit random), stored and indexed for fast lookup.',
    '<b>Unsubscribe one form</b> -- sets status to unsubscribed with timestamp.',
    '<b>Unsubscribe all</b> -- updates all active subscriptions for that email address.',
    'Unsubscribe footer auto-appended to every outgoing email unless already present in the body.',
]] + [Paragraph('Right to Erasure (Article 17 GDPR)', H2_S),
] + [bullet(t) for t in [
    '<b>Delete my data</b> option on the unsubscribe page permanently removes all records for that email.',
    'Admin can delete individual subscriber records (requires admin or super-admin role).',
    'All deletion events are written to the audit log.',
]] + [Paragraph('Data Export', H2_S),
] + [bullet(t) for t in [
    'CSV and JSON export available, including consent fields, IP address, and timestamps.',
    'Export marks all records with exported=TRUE and exported_at timestamp for audit trail.',
    'CSV values are properly quote-escaped to prevent formula injection.',
]] + [Paragraph('Privacy Notice', H2_S),
] + [bullet(t) for t in [
    'Platform-hosted privacy page at /privacy documenting data collected, legal basis, and subject rights.',
    'Direct links to unsubscribe and data deletion flows from the privacy page.',
]] + [sp(8), PageBreak()]

# ── 5. Input Validation ──────────────────────────────────────────────────────
story += [sec('5. Input Validation & SQL Injection Prevention'), sp(6),
    Paragraph('Parameterised Queries', H2_S),
    Paragraph('All database interactions use PostgreSQL parameterised queries ($1, $2, ... placeholders). '
        'User-supplied values are <b>never interpolated directly into SQL strings</b>, '
        'eliminating SQL injection risk throughout the codebase.', BODY_S),
    Paragraph('Slug Validation', H2_S),
] + [bullet(t) for t in [
    'Form slugs validated with Joi: pattern /^[a-z0-9-]+$/, max 60 characters.',
    'Reserved slugs blocked: admin, auth, api, privacy, unsubscribe, embed, and others.',
    'Slug sanitised to [a-z0-9-] in the AI tool dispatcher to prevent injection via AI tool calls.',
]] + [Paragraph('Field-Level Validation (Joi)', H2_S),
] + [Paragraph(f'<b>{lbl}:</b> {desc}', ParagraphStyle('vi', parent=BODY_S, leftIndent=14, spaceAfter=2))
   for lbl, desc in [
    ('Email', 'RFC 5322 format validation, max 254 characters'),
    ('Phone', 'E.164-ish regex, country code restriction optional, strips common formatting'),
    ('Date / Year', 'Validates day exists in month (rejects Feb 31), year range 1800-2200'),
    ('Slider / Number', 'Clamped to min/max defined in field config'),
    ('Custom field IDs', 'Validated as /^[a-zA-Z][a-zA-Z0-9_]*/ before JSONB path interpolation'),
]] + [sp(8)]

# ── 6. File Uploads ──────────────────────────────────────────────────────────
story += [sec('6. File Upload Security'), sp(6),
    plain_table([
        ['Type',   'Max Size', 'Allowed',               'S3 Key Pattern'],
        ['Images', '25 MB',    'MIME type: image/*',    'uploads/{uuid}.ext'],
        ['Fonts',  '5 MB',     '.woff .woff2 .ttf .otf','fonts/{uuid}.ext'],
    ], [W*0.16, W*0.16, W*0.34, W*0.34]),
    sp(6),
] + [bullet(t) for t in [
    'Files uploaded directly to Amazon S3 via multer-s3 -- no local disk staging.',
    'UUID-based filenames prevent directory traversal and filename enumeration.',
    'S3 proxy endpoint validates the key prefix (uploads/) before fetching from S3.',
    'S3 object deletion uses the AWS SDK DeleteObjectCommand.',
]] + [sp(8)]

# ── 7. XSS / Headers ────────────────────────────────────────────────────────
story += [sec('7. XSS Prevention & Security Headers'), sp(6),
    Paragraph('HTML Escaping', H2_S),
    Paragraph('A central escapeHtml() function encodes &amp;, &lt;, &gt;, &quot;, and &#39;. '
        'Applied at all user-supplied and admin-supplied text before server-side rendering '
        '(200+ call sites throughout the codebase).', BODY_S),
    Paragraph('WYSIWYG / Rich-Text Sanitisation', H2_S),
    Paragraph('Admin-authored HTML (email bodies, form descriptions) is processed through '
        '<b>sanitize-html</b> with a strict whitelist:', BODY_S),
] + [bullet(t) for t in [
    'Allowed tags: headings, paragraphs, lists, tables, links, images, inline formatting.',
    'Allowed URL schemes: http://, https://, mailto: only.',
    'All other tags and attributes are stripped on input.',
]] + [Paragraph('Content Security Policy (via Helmet)', H2_S),
    plain_table([
        ['Directive',       'Effective Value'],
        ['default-src',     "'self'"],
        ['script-src',      "'self', 'unsafe-inline', hcaptcha.com, GTM CDN"],
        ['style-src',       "'self', 'unsafe-inline', fonts.googleapis.com"],
        ['frame-ancestors', "'self' (embed routes allow all origins -- intentional)"],
        ['object-src',      "'none'"],
        ['base-uri',        "'self'"],
    ], [W*0.30, W*0.70]),
    sp(4),
    Paragraph('Note: unsafe-inline in script-src is required by the single-file admin SPA. '
        'A future refactor to an external JS file would allow its removal. '
        'The admin panel is only accessible to Auth0-verified users.', CAP_S),
    sp(8),
]

# ── 8. Email ─────────────────────────────────────────────────────────────────
story += [sec('8. Email Security'), sp(6),
] + [bullet(t) for t in [
    'SMTP credentials stored exclusively in .env -- never hardcoded.',
    'TLS/SSL support via configurable SMTP_SECURE flag.',
    'All email template HTML sanitised with the WYSIWYG whitelist before sending.',
    'Unsubscribe footer automatically appended to every outbound email (GDPR Article 21).',
    'Every send attempt (success or failure) recorded in the email_log table with subscriber ID, subject, status, and error.',
    'Open and click tracking keyed by UUID log ID -- not predictable or guessable.',
]] + [sp(8)]

# ── 9. Secrets ───────────────────────────────────────────────────────────────
story += [sec('9. Secrets & Credentials Management'), sp(6),
    plain_table([
        ['Secret / Credential',  'Storage',               'Notes'],
        ['Auth0 client secret',  '.env',                  'Never logged or returned in any API response'],
        ['Session secret',       '.env',                  'Falls back to random UUID in dev; set explicitly for production'],
        ['SMTP password',        '.env',                  'Never returned in any API response'],
        ['hCaptcha secret key',  'PostgreSQL global_settings', 'Masked with dots in GET responses'],
        ['Anthropic API key',    '.env',                  'Server-side only; never exposed to the browser'],
        ['Internal API key',     '.env',                  'Read-only endpoint; long random string'],
        ['AWS credentials',      '.env',                  'Access key ID + secret; standard AWS SDK pattern'],
    ], [W*0.28, W*0.30, W*0.42]),
    sp(8), PageBreak(),
]

# ── 10. Audit ────────────────────────────────────────────────────────────────
story += [sec('10. Audit Logging'), sp(6),
    Paragraph('Every significant admin action is written to the audit_log PostgreSQL table with: '
        'authenticated user email, action name, target type, target ID, detail JSON, and UTC timestamp. '
        'The log is append-only and paginated for admin review (max 100 per page).', BODY_S),
    sp(4),
    Paragraph('Actions captured:', BOLD_S),
] + [bullet(t) for t in [
    'form.create / form.delete / form.config_save',
    'subscriber.delete',
    'global_settings.save (CAPTCHA mode and key changes)',
    'market.create / market.delete',
    'user.role_change',
    'media.delete / font.delete',
    'design_template.create / design_template.delete',
]] + [sp(8)]

# ── 11. Known Limitations ────────────────────────────────────────────────────
story += [sec('11. Known Limitations & Recommendations'), sp(6)]

lims = [
    ('CSP unsafe-inline (Moderate)',
     'Required by the single-file admin SPA. Mitigated by Auth0-enforced access control. '
     'Recommendation: extract admin JS to a separate file to allow removal.'),
    ('Math challenge brute-force (Low)',
     'Built-in CAPTCHA has no per-IP exponential back-off beyond the rate limiter (10/IP/15 min). '
     'For high-traffic or high-value forms, hCaptcha mode is recommended.'),
    ('Session token mid-session refresh (Low)',
     'Auth0 token expiry is not re-validated during active sessions. '
     'The 8-hour session maxAge provides a practical bound.'),
    ('SMTP SPF / DKIM (Configuration)',
     'Not enforced in application code -- depends on SMTP provider. '
     'Ensure the sending domain has valid SPF and DKIM DNS records.'),
    ('S3 bucket policy (Infrastructure)',
     'Bucket ACLs and versioning are outside application scope. '
     'Recommended: block public access at bucket level, enable versioning.'),
    ('Internal API key in query string (Low)',
     'The read-only /api/internal/feedback endpoint uses a query-string key '
     '(WebFetch cannot set custom headers). Access is strictly read-only. '
     'Long-term plan: replace with a direct PostgreSQL MCP server connection.'),
]
for title, desc in lims:
    story.append(KeepTogether([
        Paragraph(f'<b>{title}</b>', BOLD_S),
        Paragraph(desc, ParagraphStyle('lm', parent=BODY_S, leftIndent=14, spaceAfter=6)),
        sp(2),
    ]))

story += [sp(8), hr(BRAND, 1), sp(4),
    Paragraph(
        f'This document reflects the state of server.js and admin/index.html as of '
        f'{datetime.date.today().strftime("%d %B %Y")}. Review and update after each major release.',
        ParagraphStyle('fn', parent=SMALL_S, alignment=TA_CENTER, textColor=MID)),
]

doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
print(f"PDF written to: {OUTPUT}")
