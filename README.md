# ✦ SignFlow

White-label newsletter signup platform. Self-hosted, GDPR-compliant, no external CMS.

## Quick Start

```bash
npm install
npm start
```

Then open:
- **Signup page:** http://localhost:3000
- **Admin panel:** http://localhost:3000/admin (default password: `changeme123`)

> ⚠️ **Change the admin password immediately** after first login via Settings tab.

---

## Features

| Feature | Details |
|---|---|
| Visual editor | Live WYSIWYG with instant preview |
| Custom fields | Text, email, phone, dropdown, checkbox, textarea, date |
| Drag & drop | Reorder form fields |
| Fonts | 20 Google Fonts, heading + body separate |
| Colors | Full color picker with hex input |
| Images | Upload logo, hero image, background |
| Background overlay | Adjustable opacity for bg images |
| Responsive preview | Desktop / Tablet / Mobile |
| Cookie banner | GDPR-compliant, remembers consent |
| Privacy policy | Auto-generated page at /privacy |
| Unsubscribe | Per-subscriber token link at /unsubscribe |
| Data deletion | Full GDPR erasure at /delete-data |
| Export | CSV and JSON export |
| Rate limiting | 10 signups per 15min per IP |
| Subscriber management | Search, filter, paginate, delete |

---

## Deployment on AWS Lightsail

### 1. Create Lightsail instance
- Choose **Linux/Unix** → **OS Only** → **Ubuntu 22.04**
- Minimum: $5/mo (1 vCPU, 1GB RAM) — plenty for this app

### 2. Connect and set up

```bash
# Connect via SSH from Lightsail console
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install PM2 (process manager)
sudo npm install -g pm2

# Clone or upload your project
mkdir ~/signflow && cd ~/signflow
# Upload files via SFTP or git clone

npm install
```

### 3. Start with PM2

```bash
pm2 start server.js --name signflow
pm2 save
pm2 startup  # follow the printed command to auto-start on reboot
```

### 4. Set up Nginx reverse proxy (recommended)

```bash
sudo apt install -y nginx

sudo nano /etc/nginx/sites-available/signflow
```

Paste:
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    client_max_body_size 10M;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/signflow /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 5. SSL with Let's Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### 6. Open Lightsail firewall ports
In the Lightsail console → Networking → Add rules:
- HTTP (port 80)
- HTTPS (port 443)

---

## Data & GDPR

- All data stored in `data/subscribers.json` — back this up regularly
- Each subscriber record includes: consent timestamp, IP address, unsubscribe token
- Unsubscribe link: `/unsubscribe?email=EMAIL&token=TOKEN`
- Data deletion link: `/delete-data?email=EMAIL&token=TOKEN`
- Admin can delete individual records from the Subscribers tab
- Export full data as CSV or JSON anytime

### Backup (add to crontab)
```bash
crontab -e
# Add: 0 2 * * * cp /home/ubuntu/signflow/data/subscribers.json /home/ubuntu/backups/subscribers-$(date +\%Y\%m\%d).json
```

---

## Project Structure

```
signflow/
├── server.js           # Express backend + page rendering
├── package.json
├── data/
│   ├── config.json     # Site config, design, fields (editable via admin)
│   └── subscribers.json # All subscriber records
├── admin/
│   └── index.html      # Full visual editor SPA
└── public/
    └── uploads/        # User-uploaded images (auto-created)
```

---

## Customisation Notes

- **Port:** Set `PORT` environment variable to change from 3000
- **Rate limits:** Adjust in `server.js` (`submitLimiter`)  
- **File size limit:** Adjust `limits.fileSize` in multer config
- **Admin password:** Change via Settings tab in admin, or directly in `data/config.json`

---

## Security Checklist

- [ ] Change default admin password (`changeme123`)
- [ ] Enable HTTPS via Let's Encrypt
- [ ] Set up regular backups of `data/` directory
- [ ] Consider IP allowlisting for `/admin` route in Nginx if access should be restricted
- [ ] Keep Node.js and npm packages updated (`npm audit`)
