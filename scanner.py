"""Nuclei scan engine: target validation, job queue, process management, result parsing."""
import ipaddress
import json
import os
import queue
import re
import signal
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit

import config
import db

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Never run denial-of-service / brute-force style templates from the web service.
SAFE_EXCLUDE_TAGS = "dos,fuzz,bruteforce,intrusive"

PROFILES = {
    "auto": {
        "label": "Auto Scan",
        "description": "Fingerprints the site's technology stack (Wappalyzer mapping) and runs only the matching templates. Same mode as the LinCold desktop Auto Scan report.",
        "args": ["-as"],
    },
    "quick": {
        "label": "Quick Recon",
        "description": "Fast fingerprinting: technologies, WAF, TLS/SSL, security headers and exposed panels.",
        "args": ["-tags", "tech,waf,ssl,panel,headers"],
    },
    "standard": {
        "label": "Standard & PHP Vulnerability Scan",
        "description": "Checks critical, high, and medium vulnerabilities and exposures, including PHP-tagged findings. RCE and code-injection templates are excluded.",
        "args": ["-s", "critical,high,medium"],
        "exclude_tags": ["rce", "codeinjection", "code-injection", "cmd-injection"],
    },
    "full": {
        "label": "Full Scan",
        "description": "All community templates of every severity. Most thorough; can take a long time.",
        "args": [],
    },
}

LEGACY_PROFILES = {
    "php": {
        "label": "PHP Vulnerability Scan",
        "description": "PHP-tagged vulnerability and exposure checks. RCE and code-injection templates are excluded.",
        "args": ["-tags", "php"],
        "exclude_tags": ["rce", "codeinjection", "code-injection", "cmd-injection"],
    },
}


def get_profile(name: str) -> dict:
    if name in PROFILES:
        return PROFILES[name]
    return LEGACY_PROFILES[name]


_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


class TargetError(ValueError):
    pass


def _ip_is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified or not addr.is_global)


def normalize_target(raw: str):
    """Returns (url, host). Rebuilds the URL from parsed parts so nothing else reaches nuclei's argv."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 500:
        raise TargetError("Enter a target URL or domain.")
    if any(c.isspace() for c in raw) or raw.startswith("-"):
        raise TargetError("Target contains invalid characters.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise TargetError("Only http:// and https:// targets are supported.")
    if parts.username or parts.password:
        raise TargetError("Credentials in the URL are not allowed.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise TargetError("Target must include a hostname.")
    try:
        port = parts.port
    except ValueError:
        raise TargetError("Invalid port.")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise TargetError("Invalid hostname.")
        if not _HOST_RE.match(host) or "." not in host:
            raise TargetError("Enter a fully-qualified domain name (e.g. example.com).")

    try:
        infos = socket.getaddrinfo(host, port or (443 if parts.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise TargetError(f"Could not resolve '{host}'.")
    ips = {i[4][0] for i in infos}
    if not config.ALLOW_PRIVATE_TARGETS and not all(_ip_is_public(ip) for ip in ips):
        raise TargetError("Target resolves to a private, loopback or reserved address, which is not allowed.")

    netloc = f"[{host}]" if is_ip and ":" in host else host
    if port:
        netloc += f":{port}"
    path = re.sub(r"[^A-Za-z0-9\-._~/%!$&'()*+,;=:@]", "", parts.path or "")
    query = re.sub(r"[^A-Za-z0-9\-._~/%!$&'()*+,;=:@?]", "", parts.query or "")
    return f"{parts.scheme}://{netloc}{path}{'?' + query if query else ''}", host


def local_source_ip(host: str) -> str:
    """Outbound interface address used to reach host (UDP connect sends no packets)."""
    try:
        target_ip = socket.getaddrinfo(host, 80)[0][4][0]
        fam = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 80))
            return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "unknown"


def build_command(url: str, profile: str, out_file) -> list:
    selected_profile = get_profile(profile)
    excluded_tags = list(dict.fromkeys(
        [*SAFE_EXCLUDE_TAGS.split(","), *selected_profile.get("exclude_tags", [])]
    ))
    return [
        config.NUCLEI_BIN, "-u", url,
        *selected_profile["args"],
        "-etags", ",".join(excluded_tags),
        "-jsonl", "-omit-raw", "-omit-template",
        "-silent", "-no-color", "-duc",
        "-rl", str(config.NUCLEI_RATE_LIMIT),
        "-timeout", "10", "-retries", "1",
        "-o", str(out_file),
    ]


# ---------------------------------------------------------------- parsing

def _as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if x not in (None, "")]
    return [v]


def parse_event(ev: dict) -> dict:
    info = ev.get("info") or {}
    cls = info.get("classification") or {}
    sev = str(info.get("severity") or "unknown").lower()
    if sev not in SEV_RANK:
        sev = "info"
    tid = ev.get("template-id") or "unknown"
    matcher = ev.get("matcher-name") or ev.get("extractor-name") or ""
    script = f"{tid}:{matcher}" if matcher else tid
    matched = ev.get("matched-at") or ev.get("url") or ev.get("host") or ""
    extracted = [str(x) for x in _as_list(ev.get("extracted-results"))]
    meta = ev.get("meta") or {}
    raw = f"[{script}] [{ev.get('type', 'http')}] [{sev}] {matched}"
    if extracted:
        raw += " " + json.dumps(extracted, ensure_ascii=False, separators=(",", ":"))
    for k, v in meta.items():
        raw += f' [{k}="{v}"]'
    return {
        "severity": sev,
        "template_id": tid,
        "matcher": matcher,
        "script": script,
        "name": info.get("name") or tid,
        "type": ev.get("type") or "http",
        "host": ev.get("host") or "",
        "matched_at": matched,
        "port": str(ev.get("port") or ""),
        "ip": ev.get("ip") or "",
        "extracted": extracted,
        "meta": {str(k): str(v) for k, v in meta.items()},
        "tags": [str(t) for t in _as_list(info.get("tags"))],
        "description": (info.get("description") or "").strip(),
        "remediation": (info.get("remediation") or "").strip(),
        "references": [str(r) for r in _as_list(info.get("reference"))][:5],
        "cve": [str(c).upper() for c in _as_list(cls.get("cve-id"))],
        "cwe": [str(c).upper() for c in _as_list(cls.get("cwe-id"))],
        "cvss": cls.get("cvss-score"),
        "timestamp": ev.get("timestamp") or "",
        "raw": raw,
    }


def load_findings(scan_id: str) -> list:
    path = config.SCAN_DIR / f"{scan_id}.jsonl"
    findings = []
    if path.exists():
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    findings.append(parse_event(json.loads(line)))
                except (ValueError, AttributeError):
                    continue
    return findings


def summarize(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1
    overall = next((s for s in SEVERITIES if counts[s]), "none")
    return {"counts": counts, "total": len(findings), "overall": overall}


# ---------------------------------------------------------------- runner

class ScanManager:
    def __init__(self):
        self._q = queue.Queue()
        self._procs = {}
        self._cancelled = set()
        self._lock = threading.Lock()
        self._started = False

    def start(self):
        if self._started:
            return
        self._started = True
        with db.tx() as conn:
            conn.execute("UPDATE scans SET status='failed', error='Interrupted by server restart', finished_at=? "
                         "WHERE status='running'", (db.now_iso(),))
        for row in db.query("SELECT id FROM scans WHERE status='queued' ORDER BY created_at"):
            self._q.put(row["id"])
        for i in range(max(1, config.MAX_CONCURRENT_SCANS)):
            threading.Thread(target=self._worker, name=f"scan-worker-{i}", daemon=True).start()

    def submit(self, scan_id: str):
        self._q.put(scan_id)

    def queue_position(self, scan_id: str) -> int:
        rows = db.query("SELECT id FROM scans WHERE status='queued' ORDER BY created_at")
        ids = [r["id"] for r in rows]
        return ids.index(scan_id) + 1 if scan_id in ids else 0

    def live_count(self, scan_id: str) -> int:
        path = config.SCAN_DIR / f"{scan_id}.jsonl"
        if not path.exists():
            return 0
        with open(path, "rb") as fh:
            return sum(1 for line in fh if line.strip().startswith(b"{"))

    def cancel(self, scan_id: str) -> bool:
        with self._lock:
            self._cancelled.add(scan_id)
            proc = self._procs.get(scan_id)
        if proc and proc.poll() is None:
            _kill(proc)
        with db.tx() as conn:
            cur = conn.execute("UPDATE scans SET status='cancelled', finished_at=? WHERE id=? AND status IN ('queued','running')",
                               (db.now_iso(), scan_id))
            return cur.rowcount > 0

    def _worker(self):
        while True:
            scan_id = self._q.get()
            try:
                self._run(scan_id)
            except Exception as exc:  # keep the worker alive
                with db.tx() as conn:
                    conn.execute("UPDATE scans SET status='failed', error=?, finished_at=? WHERE id=?",
                                 (f"Internal error: {exc}", db.now_iso(), scan_id))
            finally:
                self._q.task_done()

    def _run(self, scan_id: str):
        row = db.query("SELECT * FROM scans WHERE id=?", (scan_id,), one=True)
        if not row or row["status"] != "queued":
            return
        with self._lock:
            if scan_id in self._cancelled:
                return
        out_file = config.SCAN_DIR / f"{scan_id}.jsonl"
        log_file = config.SCAN_DIR / f"{scan_id}.log"
        out_file.unlink(missing_ok=True)
        cmd = build_command(row["target"], row["profile"], out_file)
        with db.tx() as conn:
            conn.execute("UPDATE scans SET status='running', started_at=?, scanned_from=? WHERE id=?",
                         (db.now_iso(), local_source_ip(row["host"]), scan_id))
        try:
            with open(log_file, "wb") as log:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=log, stdin=subprocess.DEVNULL,
                                        start_new_session=True)
        except FileNotFoundError:
            self._finish(scan_id, "failed", "Nuclei binary not found on the server.")
            return
        with self._lock:
            self._procs[scan_id] = proc
        deadline = time.time() + config.SCAN_TIMEOUT_SECONDS
        timed_out = False
        while proc.poll() is None:
            if time.time() > deadline:
                timed_out = True
                _kill(proc)
                break
            time.sleep(1)
        proc.wait()
        with self._lock:
            self._procs.pop(scan_id, None)
            cancelled = scan_id in self._cancelled
        if cancelled:
            self._finish(scan_id, "cancelled", None)
        elif timed_out:
            self._finish(scan_id, "completed", f"Scan stopped after the {config.SCAN_TIMEOUT_SECONDS // 60}-minute limit; partial results shown.")
        elif proc.returncode != 0 and not out_file.exists():
            tail = log_file.read_text(errors="replace")[-400:] if log_file.exists() else ""
            self._finish(scan_id, "failed", f"Nuclei exited with code {proc.returncode}. {tail}".strip())
        else:
            self._finish(scan_id, "completed", None)

    def _finish(self, scan_id, status, error):
        s = summarize(load_findings(scan_id))
        c = s["counts"]
        with db.tx() as conn:
            conn.execute(
                "UPDATE scans SET status=CASE WHEN status IN ('deleted','failed-deleted') THEN status ELSE ? END, "
                "error=?, finished_at=COALESCE(finished_at, ?), finding_count=?, critical=?, high=?, "
                "medium=?, low=?, info=?, overall=? WHERE id=?",
                (status, error, db.now_iso(), s["total"], c["critical"], c["high"], c["medium"], c["low"], c["info"],
                 s["overall"], scan_id))
        (config.REPORT_DIR / f"{scan_id}.html").unlink(missing_ok=True)


def _kill(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired, PermissionError):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


manager = ScanManager()
