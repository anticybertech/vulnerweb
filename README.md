# LinCold™ Web Vulnerability Scanner

Web-based vulnerability scanner by Antibody Cyber Technology, LLC, using
[ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) as the scan engine. Each scan produces a
**LinCold™ AI Analysis Report** in the same format as the LinCold desktop report: overall risk rating,
severity breakdown, executive summary, findings, recommendations, and raw output.

Live platform: [vulnerweb.com](https://vulnerweb.com/). A public [sample report](https://vulnerweb.com/sample-report) is available without an account.

## Quick start (localhost)

```bash
cd vulnerweb
cp .env.example .env
set -a
. ./.env
set +a
./run.sh
# open http://127.0.0.1:5055
```

Requirements: Python 3.9 or later, and `nuclei` v3 on `PATH` with templates installed (`nuclei -update-templates`). Environment variables are loaded by the shell commands above; the app does not automatically load `.env`. Keep real credentials and runtime data out of Git.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

These tests check active and historical scan-profile compatibility and safe command construction without running scans or accessing a production database. Historical PHP-only scans remain readable through a separate legacy-profile resolver; new submissions expose only the four current choices.

## Admin accounts

Create an admin account, or promote an existing one, without using the sign-up page:

```bash
.venv/bin/python manage.py create-admin you@example.com --name "Your Name"
# prompts for a temporary password (or set LINCOLD_ADMIN_PASSWORD)
```

Admins get unlimited scans. The **Admin** page lists all users and scans, and lets admins change a user's plan
(Free/Pro) or admin role. Admins can also open any user's scan reports. A new admin must change the temporary
password at first login. Any user can change their password from **Account**.

## Deploying to AWS EC2 (vulnerweb.com)

The `deploy/` folder contains everything needed to run LinCold on EC2 behind nginx with Let's Encrypt TLS:

| File | Purpose |
|------|---------|
| `deploy/deploy_ec2.sh` | Run locally. Bundles the app and ships it to EC2 through your configured SSH jump host |
| `deploy/server_setup.sh` | Runs on EC2 as root. Installs Python, nginx, certbot and Nuclei, then sets up the app. Gets the certificate with `certbot certonly --webroot` and renews it automatically, with an nginx reload hook. Safe to re-run |
| `deploy/lincold.service` | Hardened systemd unit. Runs as the `lincold` user, data goes in `/var/lib/lincold` |
| `deploy/nginx-vulnerweb.conf` | HTTPS reverse proxy template (`__DOMAIN__` placeholder). HTTP and www redirect to `https://vulnerweb.com`. Other nginx sites are left untouched |

```bash
# one-time: authorize this machine's deploy key on your jump host
ssh-copy-id -i ~/.ssh/id_ed25519_lincold.pub ubuntu@jump.example.com

# configure your deployment; the jump host must have an SSH alias named ec2
export JUMP_HOST=jump.example.com JUMP_USER=ubuntu
export DOMAIN=scan.example.com CERT_EMAIL=admin@example.com
export ADMIN_EMAIL=admin@example.com
./deploy/deploy_ec2.sh --create-admin   # first deploy: also creates the admin (prompts for a temp password)
./deploy/deploy_ec2.sh                  # later updates
```

In production, the service sets `LINCOLD_BEHIND_PROXY=1` (secure cookies and real client IPs) and
`LINCOLD_DEMO_BILLING=0` (no free demo upgrades). Put secrets such as `STRIPE_SECRET_KEY` and `STRIPE_PRICE_ID`
in `/etc/lincold/lincold.env` on the server, then run `sudo systemctl restart lincold`.

## Plans

| Plan | Scans | Price |
|------|-------|-------|
| Free | 5 per calendar month | $0 |
| Pro  | Unlimited | `$LINCOLD_PRO_PRICE_USD`/month (default $29) |

Failed scans don't count toward the free quota. Deleted scans still count.

### Billing

- **Demo mode** (the default): "Upgrade to Pro" turns on Pro right away and charges nothing. Use it for localhost and testing.
- **Stripe mode**: set `STRIPE_SECRET_KEY` and `STRIPE_PRICE_ID` (a recurring price). Upgrading then goes through Stripe
  Checkout. Pro is turned on only after the server confirms the Checkout session with Stripe. Cancelling deletes the subscription.

## Scan profiles

| Profile | Nuclei arguments |
|---------|------------------|
| Auto Scan | `-as` (Wappalyzer tech detection, then the matching templates) |
| Quick Recon | `-tags tech,waf,ssl,panel,headers` |
| Standard & PHP Vulnerability Scan | `-s critical,high,medium`, excluding `rce`, code-injection, and the global safety tags |
| Full Scan | all default templates |

Every scan also runs with `-etags dos,fuzz,bruteforce,intrusive`, a rate limit (`-rl`), and JSONL output.

The Standard & PHP profile includes PHP-tagged findings at critical, high, and medium severities; it does not run PHP CGI argument-injection or other RCE/code-injection templates. In particular, CVE-2024-4577's Nuclei template sends PHP source configured to execute on the target; testing that finding requires a separate, explicitly approved assessment outside this hosted profile. Direct template-directory selection is not exposed in the web scanner.

## Safety controls

- The user must confirm they're authorized to test the target before each scan.
- Targets that resolve to loopback, private, link-local, or reserved addresses are blocked (SSRF protection).
- The target URL is rebuilt from its parsed parts and passed to Nuclei as an argv list, never through a shell.
- Passwords are hashed. Every POST requires a CSRF token. Login attempts are throttled.
  Reports are served with a strict CSP, and all scan data is HTML-escaped.
- Each user can have at most 3 active scans. Scans run on a global worker pool, and each scan has a time limit.

## Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `LINCOLD_HOST` / `LINCOLD_PORT` | `127.0.0.1` / `5055` | Bind address |
| `LINCOLD_SECRET_KEY` | auto-generated in `data/secret.key` | Session signing key |
| `LINCOLD_DATA_DIR` | `./data` | SQLite DB, scan JSONL, cached reports |
| `LINCOLD_NUCLEI_BIN` | `nuclei` | Nuclei binary path |
| `LINCOLD_MAX_CONCURRENT_SCANS` | `2` | Size of the worker pool |
| `LINCOLD_SCAN_TIMEOUT` | `3600` | Maximum seconds per scan |
| `LINCOLD_RATE_LIMIT` | `50` | Nuclei requests per second |
| `LINCOLD_FREE_SCANS_PER_MONTH` | `5` | Free-tier quota |
| `LINCOLD_PRO_PRICE_USD` | `29` | Price shown for Pro |
| `LINCOLD_ALLOW_PRIVATE_TARGETS` | `0` | Set to `1` to allow internal targets (lab use only) |
| `LINCOLD_BEHIND_PROXY` | `0` | Set to `1` behind nginx/TLS: secure cookies, trust `X-Forwarded-*` headers |
| `LINCOLD_DEMO_BILLING` | `1` | Set to `0` to disable demo upgrades when Stripe isn't configured |
| `LINCOLD_SITE_URL` | `https://vulnerweb.com` | Public URL used in security.txt and policies |
| `LINCOLD_CONTACT_EMAIL_DISPLAY` | `info@antibodynet.net` | Contact address shown on the site |
| `LINCOLD_CONTACT_EMAIL` | `wayne@antibodycyber.com` | Where contact `mailto:` links deliver (About, Privacy) |
| `LINCOLD_SECURITY_EMAIL` | `wayne@antibodycyber.com` | Security contact (Disclosure `mailto:` and security.txt) |
| `LINCOLD_RECAPTCHA_SITE_KEY`, `LINCOLD_RECAPTCHA_SECRET_KEY` | unset | Google reCAPTCHA v2 checkbox on login/register (off when unset; fails closed when on) |
| `LINCOLD_GOOGLE_SITE_VERIFICATION`, `LINCOLD_BING_SITE_VERIFICATION` | unset | Search Console / Bing Webmaster meta-tag tokens |
| `LINCOLD_INDEXNOW_KEY` | unset | IndexNow key served at `/<key>.txt`; submit URLs with `manage.py indexnow` |
| `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID` | unset | Turn on Stripe billing |

Secrets such as the reCAPTCHA keys go in `/etc/lincold/lincold.env` (root:lincold, mode 0640) on the server, never in the repo.
For local testing, use Google's public test keys (site `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`, secret `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe`).

## Security posture

- Strict CSP with no inline scripts or styles; report pages get a per-response CSP with SHA-256 style hashes. The login and register pages also allow Google reCAPTCHA (and drop COEP).
- HSTS (preload-eligible), COOP, CORP, COEP, Permissions-Policy, `__Host-` session cookie. Results: Mozilla Observatory A+, securityheaders.com A+, SSL Labs A+.
- nginx runs ModSecurity v3 with OWASP CRS. App-specific exclusions are in `deploy/modsecurity-lincold.conf`.
- DNS (Route53) has DKIM (`lincold._domainkey`), DMARC `p=reject`, and CAA (letsencrypt.org only).

## Layout

```
app.py        Flask routes: auth, dashboard, scans, billing, admin
manage.py     Admin CLI (create-admin)
scanner.py    Target validation, Nuclei job queue/runner, JSONL parsing
report.py     LinCold™ AI Analysis Report builder and recommendation engine
templates/    Website pages; templates/report/report.html is the report template
static/       Branding (logo, favicon), CSS, JS
data/         Runtime data (created automatically)
```
