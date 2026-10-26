"""LinCold™ Web Vulnerability Scanner — Flask application (Nuclei backend)."""
import base64
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session,
                   url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import config
import db
import report
import scanner

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.BEHIND_PROXY,
    # __Host- prefix: Secure, host-only, Path=/ (only valid over HTTPS)
    SESSION_COOKIE_NAME="__Host-lincold" if config.BEHIND_PROXY else "lincold_session",
    MAX_CONTENT_LENGTH=64 * 1024,
)
if config.BEHIND_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
           "frame-src 'self'; manifest-src 'self'; form-action 'self' https://checkout.stripe.com; "
           "frame-ancestors 'none'; base-uri 'none'; upgrade-insecure-requests")
RECAPTCHA_CSP = APP_CSP.replace(
    "script-src 'self'", "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/"
).replace(
    "frame-src 'self'", "frame-src 'self' https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/"
)
RECAPTCHA_ENDPOINTS = {"login", "register"}
PERMISSIONS_POLICY = ("accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), "
                      "fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), "
                      "midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), "
                      "screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=(), interest-cohort=()")


_failed_logins = defaultdict(deque)
LOGIN_WINDOW, LOGIN_MAX_FAILS = 900, 10


# ------------------------------------------------------------------ helpers

def current_user():
    if "user" not in g:
        uid = session.get("uid")
        g.user = db.query("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None
    return g.user


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        user = current_user()
        if not user:
            return redirect(url_for("login", next=request.path))
        if not user["is_admin"]:
            abort(404)
        return view(*a, **kw)
    return wrapped


def month_start() -> str:
    return datetime.now().strftime("%Y-%m-01 00:00:00")


def scans_this_month(uid: int) -> int:
    row = db.query("SELECT COUNT(*) AS n FROM scans WHERE user_id=? AND created_at>=? "
                   "AND status NOT IN ('failed','failed-deleted')",
                   (uid, month_start()), one=True)
    return row["n"]


def quota(user) -> dict:
    used = scans_this_month(user["id"])
    if user["plan"] == "pro" or user["is_admin"]:
        return {"used": used, "limit": None, "remaining": None, "can_scan": True}
    limit = config.FREE_SCANS_PER_MONTH
    return {"used": used, "limit": limit, "remaining": max(0, limit - used), "can_scan": used < limit}


def own_scan(scan_id):
    user = current_user()
    if user["is_admin"]:
        scan = db.query("SELECT * FROM scans WHERE id=? AND status NOT IN ('deleted','failed-deleted')",
                        (scan_id,), one=True)
    else:
        scan = db.query("SELECT * FROM scans WHERE id=? AND user_id=? AND status NOT IN ('deleted','failed-deleted')",
                        (scan_id, user["id"]), one=True)
    if not scan:
        abort(404)
    return scan


def recaptcha_ok() -> bool:
    """Verify the reCAPTCHA v2 token server-side. Fails closed on any error."""
    if not config.RECAPTCHA_ENABLED:
        return True
    token = request.form.get("g-recaptcha-response", "")
    if not token or len(token) > 4096:
        return False
    data = urllib.parse.urlencode({"secret": config.RECAPTCHA_SECRET_KEY, "response": token,
                                   "remoteip": request.remote_addr or ""}).encode()
    try:
        with urllib.request.urlopen("https://www.google.com/recaptcha/api/siteverify", data=data, timeout=10) as r:
            result = json.loads(r.read(65536))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        app.logger.warning("reCAPTCHA verification failed: %s", exc)
        return False
    if not result.get("success"):
        return False
    host = result.get("hostname", "")
    expected = urllib.parse.urlparse(config.SITE_URL).hostname
    # Enforce hostname in production only (Google's local test keys report "testkey.google.com").
    return not config.BEHIND_PROXY or host in (expected, request.host.split(":")[0])


RECAPTCHA_ERROR = "Please complete the “I'm not a robot” check and try again."


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


PASSWORD_CHANGE_EXEMPT = {"change_password", "logout", "static"}


@app.before_request
def force_password_change():
    user = current_user()
    if user and user["must_change_password"] and request.endpoint not in PASSWORD_CHANGE_EXEMPT:
        return redirect(url_for("change_password"))


@app.after_request
def security_headers(resp):
    framable = "Content-Security-Policy" in resp.headers  # reports set their own CSP and are framed by /scans/<id>
    recaptcha_page = config.RECAPTCHA_ENABLED and request.endpoint in RECAPTCHA_ENDPOINTS
    resp.headers.setdefault("Content-Security-Policy", RECAPTCHA_CSP if recaptcha_page else APP_CSP)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN" if framable else "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = PERMISSIONS_POLICY
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if not recaptcha_page:  # Google's reCAPTCHA iframes/scripts don't send CORP headers
        resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if session.get("uid") is not None or request.endpoint in ("login", "register", "change_password"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject():
    return {"user": current_user(), "csrf_token": csrf_token, "cfg": config, "profiles": scanner.PROFILES, "profile_for": scanner.get_profile}


# ------------------------------------------------------------------ public pages

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/sample-report")
def sample_report():
    html = (config.BASE_DIR / "samples" / "sample-report.html").read_text(encoding="utf-8")
    favicon = base64.b64encode((config.BASE_DIR / "static" / "favicon.ico").read_bytes()).decode("ascii")
    html = html.replace("</head>", f'<link rel="icon" type="image/x-icon" href="data:image/x-icon;base64,{favicon}" sizes="any">\n</head>', 1)
    response = Response(html, mimetype="text/html")
    response.headers["Content-Security-Policy"] = report.csp(html)
    response.headers["X-Robots-Tag"] = "noindex"
    return response


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/vulnerability-disclosure")
def disclosure():
    return render_template("disclosure.html")


@app.route("/.well-known/security.txt")
def security_txt():
    expires = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%dT00:00:00Z")
    body = (f"Contact: mailto:{config.SECURITY_EMAIL}\n"
            f"Expires: {expires}\n"
            f"Policy: {config.SITE_URL}{url_for('disclosure')}\n"
            f"Canonical: {config.SITE_URL}{url_for('security_txt')}\n"
            "Preferred-Languages: en\n")
    return Response(body, mimetype="text/plain")


SITEMAP_PAGES = [("index", "weekly", "1.0"), ("pricing", "monthly", "0.8"), ("about", "monthly", "0.7"),
                 ("register", "monthly", "0.6"), ("login", "yearly", "0.3"), ("privacy", "yearly", "0.3"),
                 ("disclosure", "yearly", "0.3")]


@app.route("/robots.txt")
def robots_txt():
    body = ("User-agent: *\n"
            "Allow: /\n"
            "Disallow: /dashboard\nDisallow: /scans\nDisallow: /billing\nDisallow: /account\nDisallow: /admin\n\n"
            f"Sitemap: {config.SITE_URL}{url_for('sitemap_xml')}\n")
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    lastmod = datetime.strptime(config.POLICY_DATE, "%B %d, %Y").strftime("%Y-%m-%d")
    urls = "".join(f"<url><loc>{config.SITE_URL}{url_for(ep)}</loc><lastmod>{lastmod}</lastmod>"
                   f"<changefreq>{freq}</changefreq><priority>{prio}</priority></url>"
                   for ep, freq, prio in SITEMAP_PAGES)
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>')
    return Response(xml, mimetype="application/xml")


@app.route("/<key>.txt")
def indexnow_key(key):
    if not config.INDEXNOW_KEY or not secrets.compare_digest(key.encode(), config.INDEXNOW_KEY.encode()):
        abort(404)
    return Response(config.INDEXNOW_KEY, mimetype="text/plain")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        email = request.form.get("email", "").strip().lower()[:200]
        pw = request.form.get("password", "")
        error = None
        if not recaptcha_ok():
            error = RECAPTCHA_ERROR
        elif not name or "@" not in email or "." not in email.split("@")[-1]:
            error = "Please enter your name and a valid email address."
        elif len(pw) < 8:
            error = "Password must be at least 8 characters."
        elif pw != request.form.get("confirm", ""):
            error = "Passwords do not match."
        elif db.query("SELECT 1 FROM users WHERE email=?", (email,), one=True):
            error = "An account with that email already exists."
        if error:
            flash(error, "error")
        else:
            with db.tx() as conn:
                cur = conn.execute("INSERT INTO users(email,name,password_hash,plan,created_at) VALUES(?,?,?,?,?)",
                                   (email, name, generate_password_hash(pw), "free", db.now_iso()))
                uid = cur.lastrowid
            session.clear()
            session["uid"] = uid
            flash(f"Welcome to LinCold™, {name}! You're on the Free plan with "
                  f"{config.FREE_SCANS_PER_MONTH} scans per month.", "success")
            return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        ip = request.remote_addr or "?"
        fails = _failed_logins[ip]
        while fails and fails[0] < time.time() - LOGIN_WINDOW:
            fails.popleft()
        if len(fails) >= LOGIN_MAX_FAILS:
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html"), 429
        if not recaptcha_ok():
            flash(RECAPTCHA_ERROR, "error")
            return render_template("login.html"), 400
        email = request.form.get("email", "").strip().lower()
        user = db.query("SELECT * FROM users WHERE email=?", (email,), one=True)
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            fails.clear()
            session.clear()
            session["uid"] = user["id"]
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        fails.append(time.time())
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    if request.method == "POST":
        new = request.form.get("new_password", "")
        error = None
        if not check_password_hash(user["password_hash"], request.form.get("current_password", "")):
            error = "Current password is incorrect."
        elif len(new) < 8:
            error = "New password must be at least 8 characters."
        elif new != request.form.get("confirm", ""):
            error = "New passwords do not match."
        elif check_password_hash(user["password_hash"], new):
            error = "New password must be different from the current password."
        if error:
            flash(error, "error")
        else:
            with db.tx() as conn:
                conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                             (generate_password_hash(new), user["id"]))
            flash("Password changed.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html")


# ------------------------------------------------------------------ dashboard & scans

@app.route("/dashboard")
@login_required
def dashboard():
    scans = db.query("SELECT * FROM scans WHERE user_id=? AND status NOT IN ('deleted','failed-deleted') "
                     "ORDER BY created_at DESC LIMIT 100", (current_user()["id"],))
    stats = db.query("SELECT COUNT(*) n, COALESCE(SUM(critical),0) c, COALESCE(SUM(high),0) h, "
                     "COALESCE(SUM(medium),0) m, COALESCE(SUM(finding_count),0) t FROM scans WHERE user_id=? "
                     "AND status NOT IN ('deleted','failed-deleted')",
                     (current_user()["id"],), one=True)
    return render_template("dashboard.html", scans=scans, q=quota(current_user()), stats=stats)


@app.route("/scans", methods=["POST"])
@login_required
def create_scan():
    user = current_user()
    q = quota(user)
    if not q["can_scan"]:
        flash(f"You've used all {q['limit']} free scans for this month. Upgrade to Pro for unlimited scans.", "error")
        return redirect(url_for("pricing"))
    if request.form.get("authorized") != "yes":
        flash("You must confirm you own or are authorized to test this target.", "error")
        return redirect(url_for("dashboard"))
    profile = request.form.get("profile", "auto")
    if profile not in scanner.PROFILES:
        flash("Unknown scan profile.", "error")
        return redirect(url_for("dashboard"))
    try:
        url, host = scanner.normalize_target(request.form.get("target", ""))
    except scanner.TargetError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))
    active = db.query("SELECT COUNT(*) n FROM scans WHERE user_id=? AND status IN ('queued','running')",
                      (user["id"],), one=True)["n"]
    if active >= 3:
        flash("You already have 3 scans in progress. Wait for one to finish.", "error")
        return redirect(url_for("dashboard"))
    scan_id = secrets.token_hex(12)
    with db.tx() as conn:
        conn.execute("INSERT INTO scans(id,user_id,target,host,profile,status,created_at) VALUES(?,?,?,?,?,?,?)",
                     (scan_id, user["id"], url, host, profile, "queued", db.now_iso()))
    scanner.manager.submit(scan_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scans/<scan_id>")
@login_required
def scan_detail(scan_id):
    scan = own_scan(scan_id)
    return render_template("scan.html", scan=scan, profile=scanner.get_profile(scan["profile"]))


@app.route("/scans/<scan_id>/status")
@login_required
def scan_status(scan_id):
    scan = own_scan(scan_id)
    live = scan["finding_count"]
    if scan["status"] in ("queued", "running"):
        live = scanner.manager.live_count(scan_id)
    return jsonify(status=scan["status"], findings=live, started_at=scan["started_at"],
                   finished_at=scan["finished_at"], error=scan["error"],
                   queue_position=scanner.manager.queue_position(scan_id) if scan["status"] == "queued" else 0)


@app.route("/scans/<scan_id>/report")
@login_required
def scan_report(scan_id):
    scan = own_scan(scan_id)
    html = report.get_or_build(scan)
    resp = Response(html, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = report.csp(html)
    return resp


@app.route("/scans/<scan_id>/download")
@login_required
def scan_download(scan_id):
    scan = own_scan(scan_id)
    html = report.get_or_build(scan)
    resp = Response(html, mimetype="text/html")
    resp.headers["Content-Disposition"] = f'attachment; filename="{report.filename(scan)}"'
    resp.headers["Content-Security-Policy"] = report.csp(html)
    return resp


@app.route("/scans/<scan_id>/json")
@login_required
def scan_json(scan_id):
    scan = own_scan(scan_id)
    findings = scanner.load_findings(scan_id)
    body = json.dumps({"scan": dict(scan), "summary": scanner.summarize(findings), "findings": findings}, indent=2)
    resp = Response(body, mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="lincold_scan_{scan_id}.json"'
    return resp


@app.route("/scans/<scan_id>/cancel", methods=["POST"])
@login_required
def scan_cancel(scan_id):
    own_scan(scan_id)
    if scanner.manager.cancel(scan_id):
        flash("Scan cancelled.", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scans/<scan_id>/delete", methods=["POST"])
@login_required
def scan_delete(scan_id):
    scan = own_scan(scan_id)
    if scan["status"] in ("queued", "running"):
        scanner.manager.cancel(scan_id)
    # Deleted scans keep counting toward the monthly quota, so only the result files are removed and the row is hidden.
    with db.tx() as conn:
        conn.execute("UPDATE scans SET status=CASE WHEN status='failed' THEN 'failed-deleted' ELSE 'deleted' END "
                     "WHERE id=?", (scan_id,))
    for ext in (".jsonl", ".log"):
        (config.SCAN_DIR / f"{scan_id}{ext}").unlink(missing_ok=True)
    (config.REPORT_DIR / f"{scan_id}.html").unlink(missing_ok=True)
    flash("Scan deleted.", "success")
    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------ billing

def _stripe(method, path, params=None):
    data = urllib.parse.urlencode(params or {}).encode() if method == "POST" else None
    req = urllib.request.Request(f"https://api.stripe.com/v1/{path}", data=data, method=method,
                                 headers={"Authorization": f"Bearer {config.STRIPE_SECRET_KEY}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def _activate_pro(uid, provider, reference, customer=None, subscription=None):
    with db.tx() as conn:
        conn.execute("UPDATE users SET plan='pro', plan_since=?, stripe_customer=COALESCE(?,stripe_customer), "
                     "stripe_subscription=COALESCE(?,stripe_subscription) WHERE id=?",
                     (db.now_iso(), customer, subscription, uid))
        conn.execute("INSERT INTO payments(user_id,provider,reference,amount,created_at) VALUES(?,?,?,?,?)",
                     (uid, provider, reference, f"${config.PRO_PRICE_USD}/mo", db.now_iso()))


@app.route("/billing")
@login_required
def billing():
    payments = db.query("SELECT * FROM payments WHERE user_id=? ORDER BY created_at DESC", (current_user()["id"],))
    return render_template("billing.html", q=quota(current_user()), payments=payments)


@app.route("/billing/checkout", methods=["POST"])
@login_required
def checkout():
    user = current_user()
    if user["plan"] == "pro":
        return redirect(url_for("billing"))
    if config.BILLING_MODE == "stripe":
        try:
            sess = _stripe("POST", "checkout/sessions", {
                "mode": "subscription",
                "line_items[0][price]": config.STRIPE_PRICE_ID,
                "line_items[0][quantity]": "1",
                "client_reference_id": str(user["id"]),
                "customer_email": user["email"],
                "success_url": url_for("checkout_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
                "cancel_url": url_for("pricing", _external=True),
            })
        except (urllib.error.URLError, ValueError) as exc:
            flash(f"Could not start checkout: {exc}", "error")
            return redirect(url_for("pricing"))
        return redirect(sess["url"], code=303)
    if config.BILLING_MODE == "disabled":
        flash(f"Online upgrades are not available yet. Email {config.CONTACT_EMAIL_DISPLAY} to upgrade to Pro.", "info")
        return redirect(url_for("pricing"))
    return redirect(url_for("demo_checkout"))


@app.route("/billing/demo-checkout", methods=["GET", "POST"])
@login_required
def demo_checkout():
    if config.BILLING_MODE != "demo":
        abort(404)
    if request.method == "POST":
        _activate_pro(current_user()["id"], "demo", "demo-" + secrets.token_hex(6))
        flash("LinCold™ Pro activated — enjoy unlimited scans!", "success")
        return redirect(url_for("billing"))
    return render_template("checkout.html")


@app.route("/billing/success")
@login_required
def checkout_success():
    if config.BILLING_MODE != "stripe":
        abort(404)
    sid = request.args.get("session_id", "")
    try:
        sess = _stripe("GET", f"checkout/sessions/{urllib.parse.quote(sid, safe='')}")
    except (urllib.error.URLError, ValueError):
        flash("Could not verify payment.", "error")
        return redirect(url_for("pricing"))
    if sess.get("client_reference_id") == str(current_user()["id"]) and sess.get("payment_status") in ("paid", "no_payment_required"):
        if current_user()["plan"] != "pro":
            _activate_pro(current_user()["id"], "stripe", sid, sess.get("customer"), sess.get("subscription"))
        flash("Payment received — LinCold™ Pro is active!", "success")
    else:
        flash("Payment was not completed.", "error")
    return redirect(url_for("billing"))


@app.route("/billing/cancel", methods=["POST"])
@login_required
def cancel_subscription():
    user = current_user()
    if user["plan"] != "pro":
        return redirect(url_for("billing"))
    if config.BILLING_MODE == "stripe" and user["stripe_subscription"]:
        try:
            _stripe("DELETE", f"subscriptions/{urllib.parse.quote(user['stripe_subscription'], safe='')}")
        except (urllib.error.URLError, ValueError) as exc:
            flash(f"Could not cancel subscription: {exc}", "error")
            return redirect(url_for("billing"))
    with db.tx() as conn:
        conn.execute("UPDATE users SET plan='free', plan_since=?, stripe_subscription=NULL WHERE id=?",
                     (db.now_iso(), user["id"]))
    flash("Your plan has been changed to Free.", "success")
    return redirect(url_for("billing"))


@app.errorhandler(400)
@app.errorhandler(404)
def http_error(err):
    return render_template("error.html", code=err.code, message=err.description), err.code


# ------------------------------------------------------------------ admin

@app.route("/admin")
@admin_required
def admin():
    users = db.query(
        "SELECT u.*, (SELECT COUNT(*) FROM scans s WHERE s.user_id=u.id AND s.created_at>=? "
        "AND s.status NOT IN ('failed','failed-deleted')) AS month_scans, "
        "(SELECT COUNT(*) FROM scans s WHERE s.user_id=u.id) AS total_scans "
        "FROM users u ORDER BY u.created_at DESC", (month_start(),))
    scans = db.query("SELECT s.*, u.email FROM scans s JOIN users u ON u.id=s.user_id "
                     "WHERE s.status NOT IN ('deleted','failed-deleted') ORDER BY s.created_at DESC LIMIT 100")
    stats = db.query("SELECT (SELECT COUNT(*) FROM users) users, (SELECT COUNT(*) FROM users WHERE plan='pro') pro, "
                     "(SELECT COUNT(*) FROM scans) scans, "
                     "(SELECT COUNT(*) FROM scans WHERE status IN ('queued','running')) active", one=True)
    return render_template("admin.html", users=users, scans=scans, stats=stats)


@app.route("/admin/users/<int:uid>", methods=["POST"])
@admin_required
def admin_update_user(uid):
    target = db.query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not target:
        abort(404)
    action = request.form.get("action")
    if uid == current_user()["id"] and action == "revoke_admin":
        flash("You can't remove your own admin access.", "error")
        return redirect(url_for("admin"))
    with db.tx() as conn:
        if action == "set_pro":
            conn.execute("UPDATE users SET plan='pro', plan_since=? WHERE id=?", (db.now_iso(), uid))
        elif action == "set_free":
            conn.execute("UPDATE users SET plan='free', plan_since=? WHERE id=?", (db.now_iso(), uid))
        elif action == "grant_admin":
            conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (uid,))
        elif action == "revoke_admin":
            conn.execute("UPDATE users SET is_admin=0 WHERE id=?", (uid,))
        else:
            abort(400, "Unknown action.")
    flash(f"Updated {target['email']}.", "success")
    return redirect(url_for("admin"))


def create_app():
    db.init_db()
    scanner.manager.start()
    return app


if __name__ == "__main__":
    create_app()
    print(f"LinCold™ Web Scanner running on http://{config.HOST}:{config.PORT}  (billing mode: {config.BILLING_MODE})")
    try:
        from waitress import serve
        serve(app, host=config.HOST, port=config.PORT, threads=8)
    except ImportError:
        app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)
