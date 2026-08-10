#!/usr/bin/env python3
"""Perimetry - JS Secret / API Key Scanner.

Crawls a page's inline + external JavaScript and hunts for leaked credentials:
cloud keys, third-party API tokens, private keys, JWTs and high-entropy blobs
assigned to secret-looking variable names. Findings are graded by severity and
the secret value is masked so the report itself never leaks the credential.
"""
import os, sys, json, re, math, concurrent.futures, requests, urllib3
from urllib.parse import urljoin, urlparse
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from perimetry.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, render_to_text
from perimetry.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

# (label, severity, compiled pattern). Ordered high→low specificity so a value
# matched by a precise rule is not also double-counted by the generic catch-all.
RULES = [
    ("AWS Access Key ID",      "HIGH", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b")),
    ("AWS Secret Access Key",  "HIGH", re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("Google API Key",         "HIGH", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth Token",     "HIGH", re.compile(r"\bya29\.[0-9A-Za-z\-_]+\b")),
    ("Firebase Cloud Msg Key", "MED",  re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b")),
    ("Slack Token",            "HIGH", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b")),
    ("Slack Webhook",          "MED",  re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+")),
    ("Stripe Live Secret",     "HIGH", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Restricted Key",  "HIGH", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    ("GitHub Token",           "HIGH", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("GitLab PAT",             "HIGH", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b")),
    ("Twilio Account SID",     "MED",  re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("Twilio API Key",         "MED",  re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("SendGrid API Key",       "HIGH", re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")),
    ("Mailgun API Key",        "HIGH", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("Mailchimp API Key",      "MED",  re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("NPM Access Token",       "HIGH", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("Square Access Token",    "HIGH", re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b")),
    ("Facebook Access Token",  "MED",  re.compile(r"\bEAACEdEose0cBA[0-9A-Za-z]+\b")),
    ("Heroku API Key",         "MED",  re.compile(r"(?i)heroku.{0,15}?['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]")),
    ("Private Key Block",      "HIGH", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token",         "LOW",  re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("Basic Auth in URL",      "MED",  re.compile(r"https?://[A-Za-z0-9._~%\-]+:[^@\s/'\"]{3,}@[A-Za-z0-9.\-]+")),
    ("Generic Secret Assign",  "LOW",  re.compile(r"(?i)(?:api[_\-]?key|secret|passwd|password|token|auth|access[_\-]?key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{12,64})['\"]")),
]

PAT_SCRIPT_SRC   = re.compile(r"<script[^>]+src=['\"]([^'\"#>]+)['\"]", re.I)
PAT_INLINE_JS    = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
# Common false positives that match the generic rule but are never secrets.
FP_TOKENS = {"application", "javascript", "text/html", "utf-8", "false", "true", "undefined", "function"}


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]        Perimetry - JS Secret / API Key Scanner")
    console.print(f"[{TEAL}]{bar}\n")


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask(value):
    v = value.strip()
    if len(v) <= 10:
        return v[0] + "*" * (len(v) - 1) if len(v) > 1 else v
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"


def fetch(url, timeout, headers):
    try:
        r = requests.get(url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
        return url, r.text if r.status_code == 200 else ""
    except requests.RequestException:
        return url, ""


def extract_sources(html, base):
    ext = [urljoin(base, m.group(1).strip()) for m in PAT_SCRIPT_SRC.finditer(html)]
    return list(dict.fromkeys(ext))


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


GENERIC_RULES = {"Generic Secret Assign", "JSON Web Token"}


def scan_text(source, text, min_entropy):
    """Yield (source, line, label, severity, masked, entropy) for each hit.

    Precise vendor rules run first; the generic catch-all rules run last and
    skip any value a precise rule already claimed, so one leaked key is not
    reported twice under two labels.
    """
    seen = set()
    claimed = set()  # values already matched by a precise (non-generic) rule
    for label, sev, pat in RULES:
        for m in pat.finditer(text):
            raw = m.group(1) if m.groups() else m.group(0)
            val = raw.strip()
            if not val or val.lower() in FP_TOKENS:
                continue
            if label in GENERIC_RULES:
                ent = shannon_entropy(val)
                # Generic rules need an entropy floor to cut noise, and must
                # not re-flag a value a precise rule already caught.
                if ent < min_entropy or val in claimed:
                    continue
            else:
                ent = shannon_entropy(val)
                claimed.add(val)
            key = (label, val)
            if key in seen:
                continue
            seen.add(key)
            yield (source, line_of(text, m.start()), label, sev, mask(val), round(ent, 2))


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    max_scripts = int(opts.get("max_scripts", 60))
    min_entropy = float(opts.get("min_entropy", 3.2))
    dom = clean_domain_input(target)
    headers = {"User-Agent": USER_AGENT}
    base = f"https://{dom}"

    _, html = fetch(base, timeout, headers)
    if not html:
        _, html = fetch(f"http://{dom}", timeout, headers)
        base = f"http://{dom}"
    if not html:
        console.print("[red]✖ Unable to retrieve the main page[/red]")
        return

    sources = extract_sources(html, base)[:max_scripts]
    console.print(f"[white]* Main page fetched, {len(sources)} external script(s) referenced[/white]")

    # Inline scripts from the landing page are scanned as a synthetic source.
    payloads = [(f"{base} (inline)", "\n".join(PAT_INLINE_JS.findall(html)))]
    if sources:
        with Progress(SpinnerColumn(), TextColumn("Downloading JS…"), BarColumn(),
                      console=console, transient=True) as pg:
            task = pg.add_task("", total=len(sources))
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                for res in pool.map(lambda u: fetch(u, timeout, headers), sources):
                    payloads.append(res)
                    pg.advance(task)

    findings = []
    for src, txt in payloads:
        if txt:
            findings.extend(scan_text(src, txt, min_entropy))

    sev_rank = {"HIGH": 0, "MED": 1, "LOW": 2}
    findings.sort(key=lambda f: (sev_rank.get(f[3], 3), f[2]))
    counts = Counter(f[3] for f in findings)

    tbl = Table(title=f"Secret Scan – {dom}", header_style="bold white")
    tbl.add_column("Severity")
    tbl.add_column("Type", style="cyan")
    tbl.add_column("Source", style="white", overflow="fold")
    tbl.add_column("Line", justify="right")
    tbl.add_column("Value (masked)", style="yellow")
    tbl.add_column("Entropy", justify="right")
    sev_style = {"HIGH": "bold red", "MED": "yellow", "LOW": "green"}
    for src, ln, label, sev, masked, ent in findings:
        short = src if len(src) <= 60 else "…" + src[-57:]
        tbl.add_row(f"[{sev_style[sev]}]{sev}[/{sev_style[sev]}]", label, short, str(ln), masked, str(ent))

    if findings:
        console.print(tbl)
    else:
        console.print("[green]No credential patterns matched.[/green]")

    summary = (
        f"Scripts scanned: {len([p for p in payloads if p[1]])}  "
        f"Findings: {len(findings)}  "
        f"HIGH: {counts.get('HIGH',0)}  MED: {counts.get('MED',0)}  LOW: {counts.get('LOW',0)}"
    )
    style = "bold red" if counts.get("HIGH") else ("yellow" if findings else "bold white")
    console.print(Panel(summary, title="Summary", style=style))
    console.print("[green][*] JS secret scan completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        body = tbl if findings else Panel("No credential patterns matched.", title="Result")
        write_to_file(os.path.join(out, "js_secret_scanner.txt"),
                      render_to_text(body, Panel(summary, title="Summary"), width=console.width))


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 12
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except json.JSONDecodeError:
            pass
    run(tgt, thr, opts)
