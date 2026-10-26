"""Builds the self-contained LinCold™ AI Analysis Report (HTML) for a scan."""
import base64
import hashlib
import re
from functools import lru_cache

from jinja2 import Environment, FileSystemLoader, select_autoescape

import config
import scanner

SEV_COLORS = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f39c12", "low": "#27ae60", "info": "#2980b9",
              "none": "#27ae60"}

REPORT_MARKER = "<!-- lincold-report v4 -->"

_env = Environment(loader=FileSystemLoader(str(config.BASE_DIR / "templates" / "report")),
                   autoescape=select_autoescape(["html"]))


@lru_cache(maxsize=1)
def logo_data_uri() -> str:
    data = config.LOGO_PATH.read_bytes()
    return "data:image/png;base64," + base64.b64encode(data).decode()


def _detail(f: dict) -> str:
    if f["extracted"]:
        value = ", ".join(f["extracted"])
    elif f["matcher"]:
        value = f["matcher"]
    else:
        value = f["name"]
    return f"{f['matched_at']}  →  {value}"


def _version_tuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def recommendations(findings: list) -> list:
    recs, seen = [], set()

    def add(key, text):
        if key not in seen:
            seen.add(key)
            recs.append(text)

    ordered = sorted(findings, key=lambda f: scanner.SEV_RANK[f["severity"]])
    for f in ordered:
        tags = set(f["tags"])
        tid = f["template_id"]
        label = f"[{f['script']}]"
        if f["severity"] in ("critical", "high", "medium"):
            ident = ", ".join(f["cve"]) or f["name"]
            fix = f["remediation"] or "Apply the vendor patch or upgrade to a fixed release, then re-scan to confirm."
            add(f"vuln:{tid}", f"{label} {f['severity'].upper()}: {ident} at {f['matched_at']} — {fix}")
            continue
        if f["severity"] == "low" and f["remediation"]:
            add(f"low:{tid}", f"{label} {f['name']} — {f['remediation']}")
            continue
        last = f["meta"].get("last_version")
        if last and f["extracted"]:
            try:
                if _version_tuple(f["extracted"][0]) < _version_tuple(last):
                    add(f"outdated:{tid}", f"{label} Installed version {f['extracted'][0]} is older than the latest "
                                           f"known release {last} — update it to receive security fixes.")
                    continue
            except ValueError:
                pass
        if "wordpress" in tags or tid.startswith("wordpress") or "wp-" in tid:
            add("wordpress", f"{label} WordPress core, plugin and theme versions are publicly discoverable — keep them "
                             "updated, remove unused plugins, block access to readme.txt files and enable automatic "
                             "security updates.")
        elif "ssl" in tags or "tls" in tags:
            add("tls", f"{label} Review TLS configuration — disable TLS 1.0/1.1 and weak ciphers, renew certificates "
                       "before expiry and enable HSTS.")
        elif "headers" in tags or "missing-security-headers" in tid:
            add("headers", f"{label} Add missing HTTP security headers (Content-Security-Policy, "
                           "Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).")
        elif "panel" in tags or "login" in tags:
            add("panel", f"{label} Administrative/login panel is exposed — restrict it by IP allow-list or VPN and "
                         "enforce MFA.")
        elif "ssh" in tid or f["port"] == "22":
            add("ssh", f"{label} SSH is reachable from the internet — restrict port 22 by firewall, disable password "
                       "and root login, use key-based auth and keep OpenSSH patched.")
        elif "waf" in tags or tid.startswith("waf-detect"):
            add("waf", f"{label} A WAF was fingerprinted — keep its rule set current and make sure the origin server "
                       "cannot be reached directly, bypassing the WAF.")
        elif "tech" in tags or "detect" in tid:
            add("banner", f"{label} Technology fingerprint exposed — suppress version banners (ServerTokens Prod in "
                          "Apache, server_tokens off in nginx) to reduce attacker reconnaissance.")
        elif f["remediation"]:
            add(f"other:{tid}", f"{label} {f['remediation']}")

    add("firewall", "Enforce a default-deny firewall policy — explicitly allow only required ports and block "
                    "everything else.")
    add("recurring", "Schedule recurring vulnerability scans (weekly/monthly) and integrate findings into your patch "
                     "management workflow.")
    return [f"{i}. {t}" for i, t in enumerate(recs[:15], 1)]


def executive_summary(host: str, s: dict, findings: list) -> str:
    c = s["counts"]
    overall = s["overall"].capitalize() if s["overall"] != "none" else "None"
    text = (f"Nuclei scan of <strong>{_esc(host)}</strong> identified <strong>{s['total']} finding(s)</strong> — "
            f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} "
            f"informational. Overall risk: <strong>{overall}</strong>. ")
    serious = [f for f in findings if f["severity"] in ("critical", "high")]
    if serious:
        names = ", ".join(sorted({_esc(f["cve"][0] if f["cve"] else f["name"]) for f in serious})[:6])
        text += f"Immediate remediation is required for: {names}."
    elif c["medium"]:
        text += "No critical services detected in this scan; medium-severity issues should be scheduled for remediation."
    else:
        text += "No critical services detected in this scan."
    return text


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def services(findings: list) -> list:
    rows = []
    for f in findings:
        if f["type"] in ("tcp", "network", "javascript", "ssl", "dns") and f["port"]:
            rows.append({"port": f["port"], "proto": f["type"], "service": f["name"],
                         "version": ", ".join(f["extracted"]) or f["matcher"] or "—"})
    return rows


def build(scan) -> str:
    findings = sorted(scanner.load_findings(scan["id"]), key=lambda f: scanner.SEV_RANK[f["severity"]])
    s = scanner.summarize(findings)
    tool = f"Nuclei {scanner.PROFILES[scan['profile']]['label'].replace('Nuclei ', '')} — {scan['target']}"
    when = scan["started_at"] or scan["created_at"]
    raw_lines = ["=" * 70, f"Tool: {tool}", f"Time: {when}", "=" * 70, ""] + [f["raw"] for f in findings]
    if not findings:
        raw_lines.append("[INF] No results found.")
    for f in findings:
        f["detail"] = _detail(f)
    return _env.get_template("report.html").render(
        title=f"LinCold™ AI Report — {tool}",
        logo=logo_data_uri(),
        company=config.COMPANY,
        generated=when,
        scanned_from=scan["scanned_from"] or "unknown",
        tool=tool,
        target=scan["host"],
        overall=s["overall"],
        overall_color=SEV_COLORS[s["overall"]],
        counts=s["counts"],
        sev_colors=SEV_COLORS,
        summary_html=executive_summary(scan["host"], s, findings),
        services=services(findings),
        findings=findings,
        recs=recommendations(findings),
        raw="\n".join(raw_lines),
        note=scan["error"],
    )


def get_or_build(scan) -> str:
    path = config.REPORT_DIR / f"{scan['id']}.html"
    if scan["status"] in ("completed", "cancelled", "failed") and path.exists():
        cached = path.read_text(encoding="utf-8")
        if REPORT_MARKER in cached:
            return cached
    html = build(scan)
    if scan["status"] in ("completed", "cancelled", "failed"):
        path.write_text(html, encoding="utf-8")
    return html


def csp(html: str) -> str:
    """Strict CSP for a rendered report: only its own inline <style> blocks (by hash) and the data: logo."""
    hashes = " ".join(
        "'sha256-" + base64.b64encode(hashlib.sha256(m.encode()).digest()).decode() + "'"
        for m in re.findall(r"<style>(.*?)</style>", html, re.S))
    return (f"default-src 'none'; img-src data:; style-src {hashes or chr(39) + 'none' + chr(39)}; "
            "frame-ancestors 'self'; base-uri 'none'; form-action 'none'")


def filename(scan) -> str:
    tool = f"Nuclei_{scanner.PROFILES[scan['profile']]['label'].replace('Nuclei ', '')}___{scan['target']}"
    stamp = re.sub(r"\D", "", scan["started_at"] or scan["created_at"])
    return f"lincold_ai_report_{re.sub(r'[^A-Za-z0-9]', '_', tool)}_{stamp[:8]}_{stamp[8:14]}.html"
