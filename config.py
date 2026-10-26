import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("LINCOLD_DATA_DIR", BASE_DIR / "data"))
SCAN_DIR = DATA_DIR / "scans"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "lincold.db"
LOGO_PATH = BASE_DIR / "static" / "logo.png"

for _d in (DATA_DIR, SCAN_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _load_secret_key() -> str:
    env = os.environ.get("LINCOLD_SECRET_KEY")
    if env:
        return env
    key_file = DATA_DIR / "secret.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        key_file.chmod(0o600)
    return key_file.read_text().strip()


SECRET_KEY = _load_secret_key()

HOST = os.environ.get("LINCOLD_HOST", "127.0.0.1")
PORT = int(os.environ.get("LINCOLD_PORT", "5055"))

NUCLEI_BIN = os.environ.get("LINCOLD_NUCLEI_BIN", "nuclei")
MAX_CONCURRENT_SCANS = int(os.environ.get("LINCOLD_MAX_CONCURRENT_SCANS", "2"))
SCAN_TIMEOUT_SECONDS = int(os.environ.get("LINCOLD_SCAN_TIMEOUT", "3600"))
NUCLEI_RATE_LIMIT = int(os.environ.get("LINCOLD_RATE_LIMIT", "50"))

# Blocks loopback/private/link-local targets unless explicitly enabled (SSRF protection).
ALLOW_PRIVATE_TARGETS = os.environ.get("LINCOLD_ALLOW_PRIVATE_TARGETS", "0") == "1"

FREE_SCANS_PER_MONTH = int(os.environ.get("LINCOLD_FREE_SCANS_PER_MONTH", "5"))
PRO_PRICE_USD = os.environ.get("LINCOLD_PRO_PRICE_USD", "29")

# Billing: "stripe" uses Stripe Checkout; "demo" simulates checkout (localhost only);
# "disabled" turns off self-service upgrades (production without Stripe keys).
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
ALLOW_DEMO_BILLING = os.environ.get("LINCOLD_DEMO_BILLING", "1") == "1"
if STRIPE_SECRET_KEY and STRIPE_PRICE_ID:
    BILLING_MODE = "stripe"
elif ALLOW_DEMO_BILLING:
    BILLING_MODE = "demo"
else:
    BILLING_MODE = "disabled"

COMPANY = "Antibody Cyber Technology, LLC"
PRODUCT = "LinCold™"
SITE_URL = os.environ.get("LINCOLD_SITE_URL", "https://vulnerweb.com").rstrip("/")
# Address shown on the site; mailto links deliver to CONTACT_EMAIL / SECURITY_EMAIL.
CONTACT_EMAIL_DISPLAY = os.environ.get("LINCOLD_CONTACT_EMAIL_DISPLAY", "info@antibodynet.net")
CONTACT_EMAIL = os.environ.get("LINCOLD_CONTACT_EMAIL", "wayne@antibodycyber.com")
SECURITY_EMAIL = os.environ.get("LINCOLD_SECURITY_EMAIL", "wayne@antibodycyber.com")

# Google reCAPTCHA v2 ("I'm not a robot") on login/register; disabled when either key is empty.
RECAPTCHA_SITE_KEY = os.environ.get("LINCOLD_RECAPTCHA_SITE_KEY", "")
RECAPTCHA_SECRET_KEY = os.environ.get("LINCOLD_RECAPTCHA_SECRET_KEY", "")
RECAPTCHA_ENABLED = bool(RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY)
POLICY_DATE = "October 23, 2026"

# Search engine verification (values only, e.g. the content="..." part of the meta tag)
GOOGLE_SITE_VERIFICATION = os.environ.get("LINCOLD_GOOGLE_SITE_VERIFICATION", "")
BING_SITE_VERIFICATION = os.environ.get("LINCOLD_BING_SITE_VERIFICATION", "")
# IndexNow key (Bing, Yandex, Seznam...): 8-128 chars [A-Za-z0-9-]; served at /<key>.txt
INDEXNOW_KEY = os.environ.get("LINCOLD_INDEXNOW_KEY", "")

# Set to 1 when running behind a reverse proxy (nginx) that terminates TLS.
BEHIND_PROXY = os.environ.get("LINCOLD_BEHIND_PROXY", "0") == "1"
