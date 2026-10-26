"""LinCold™ admin CLI.

Usage:
  python manage.py create-admin EMAIL [--name NAME]
  python manage.py indexnow        # submit public pages to Bing/Yandex via IndexNow (needs LINCOLD_INDEXNOW_KEY)

The password is read from the LINCOLD_ADMIN_PASSWORD environment variable or prompted for.
The account must change its password at first login.
"""
import argparse
import getpass
import json
import os
import sys
import urllib.request
from urllib.parse import urlparse

from werkzeug.security import generate_password_hash

import config
import db


def create_admin(email: str, name: str, password: str) -> str:
    email = email.strip().lower()
    db.init_db()
    pw_hash = generate_password_hash(password)
    with db.tx() as conn:
        row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if row:
            conn.execute("UPDATE users SET is_admin=1, plan='pro', password_hash=?, must_change_password=1 "
                         "WHERE id=?", (pw_hash, row["id"]))
            return "updated"
        conn.execute("INSERT INTO users(email,name,password_hash,plan,plan_since,created_at,is_admin,"
                     "must_change_password) VALUES(?,?,?,'pro',?,?,1,1)",
                     (email, name, pw_hash, db.now_iso(), db.now_iso()))
        return "created"


def indexnow() -> int:
    """Notify IndexNow search engines (Bing, Yandex, Seznam, Naver...) about the public pages."""
    if not config.INDEXNOW_KEY:
        sys.exit("Set LINCOLD_INDEXNOW_KEY first.")
    from app import SITEMAP_PAGES, app
    with app.test_request_context():
        from flask import url_for
        urls = [config.SITE_URL + url_for(ep) for ep, _, _ in SITEMAP_PAGES]
    body = json.dumps({"host": urlparse(config.SITE_URL).hostname, "key": config.INDEXNOW_KEY,
                       "keyLocation": f"{config.SITE_URL}/{config.INDEXNOW_KEY}.txt", "urlList": urls}).encode()
    req = urllib.request.Request("https://api.indexnow.org/indexnow", data=body, method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        print(f"IndexNow: HTTP {resp.status} for {len(urls)} URLs")
        return resp.status


def main(argv=None):
    parser = argparse.ArgumentParser(description="LinCold™ admin CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create-admin", help="Create or promote an admin account")
    p.add_argument("email")
    p.add_argument("--name", default="Administrator")
    p.add_argument("--password-stdin", action="store_true", help="Read the temporary password from stdin")
    sub.add_parser("indexnow", help="Submit public pages to IndexNow (Bing, Yandex...)")
    args = parser.parse_args(argv)
    if args.cmd == "indexnow":
        indexnow()
        return

    if args.password_stdin:
        password = sys.stdin.read().strip()
    else:
        password = os.environ.get("LINCOLD_ADMIN_PASSWORD") or getpass.getpass("Temporary password: ")
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters.")
    result = create_admin(args.email, args.name, password)
    print(f"Admin account {args.email} {result}. A password change is required at first login.")


if __name__ == "__main__":
    main()
