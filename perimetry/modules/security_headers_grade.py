#!/usr/bin/env python3
"""Perimetry - Security Headers Grade.

Fetches the target over HTTPS and scores its HTTP response headers into a single
A+…F letter grade, the way an Observatory-style scanner would. Each control is
weighted, missing or weak headers deduct points, and information-disclosure
headers (Server version, X-Powered-By) are flagged separately.
"""
import os, sys, json, time, requests, urllib3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from perimetry.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, render_to_text
from perimetry.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

# Each control: weight (max points) and an evaluator returning (points, note).
INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]        Perimetry - Security Headers Grade")
    console.print(f"[{TEAL}]{bar}\n")


def eval_hsts(v):
    if not v:
        return 0, 20, "Missing - no HTTPS enforcement"
    maxage = 0
    for part in v.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                maxage = int(part.split("=", 1)[1])
            except ValueError:
                maxage = 0
    if maxage >= 31536000:
        pts = 20
        note = "Strong (>=1y)"
        if "includesubdomains" in v.lower():
            note += ", subdomains"
        if "preload" in v.lower():
            note += ", preload"
        return pts, 20, note
    if maxage > 0:
        return 12, 20, f"Weak max-age ({maxage}s < 1y)"
    return 4, 20, "Present but no max-age"


def eval_csp(v):
    if not v:
        return 0, 25, "Missing - no injection defence"
    low = v.lower()
    pts, notes = 25, []
    if "unsafe-inline" in low:
        pts -= 8
        notes.append("unsafe-inline")
    if "unsafe-eval" in low:
        pts -= 6
        notes.append("unsafe-eval")
    if "default-src" not in low:
        pts -= 4
        notes.append("no default-src")
    if low.strip() in ("default-src *", "default-src 'none'") and "'none'" not in low:
        pts -= 4
    return max(pts, 4), 25, "Present" + (f" ({', '.join(notes)})" if notes else ", well-formed")


def eval_xfo(v):
    if not v:
        return 0, 12, "Missing - clickjacking risk"
    low = v.lower()
    if low in ("deny", "sameorigin"):
        return 12, 12, low.upper()
    return 6, 12, f"Non-standard ({v})"


def eval_xcto(v):
    if v and v.strip().lower() == "nosniff":
        return 10, 10, "nosniff"
    return (0, 10, "Missing - MIME sniffing allowed") if not v else (4, 10, f"Unexpected ({v})")


def eval_refpol(v):
    if not v:
        return 0, 8, "Missing"
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "no-referrer-when-downgrade"}
    return (8, 8, v) if v.strip().lower() in safe else (4, 8, f"Loose ({v})")


def eval_permpol(v):
    return (10, 10, "Present") if v else (0, 10, "Missing - feature policy unset")


def eval_coop(v):
    return (5, 5, v) if v else (0, 5, "Missing")


CONTROLS = [
    ("Strict-Transport-Security", "strict-transport-security", eval_hsts),
    ("Content-Security-Policy",   "content-security-policy",   eval_csp),
    ("X-Frame-Options",           "x-frame-options",           eval_xfo),
    ("X-Content-Type-Options",    "x-content-type-options",    eval_xcto),
    ("Referrer-Policy",           "referrer-policy",           eval_refpol),
    ("Permissions-Policy",        "permissions-policy",        eval_permpol),
    ("Cross-Origin-Opener-Policy","cross-origin-opener-policy",eval_coop),
]


def grade_for(pct):
    table = [(95, "A+"), (85, "A"), (75, "B"), (65, "C"), (55, "D"), (40, "E")]
    for cutoff, letter in table:
        if pct >= cutoff:
            return letter
    return "F"


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom = clean_domain_input(target)
    headers_req = {"User-Agent": USER_AGENT}
    start = time.time()

    url = f"https://{dom}"
    try:
        resp = requests.get(url, timeout=timeout, verify=False, headers=headers_req, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"[red]✖ Request failed: {e}[/red]")
        return

    hdr = {k.lower(): v for k, v in resp.headers.items()}
    console.print(f"[white]* {url} -> HTTP {resp.status_code}, {len(resp.headers)} headers[/white]\n")

    tbl = Table(title=f"Security Headers – {dom}", header_style="bold white", box=box.MINIMAL)
    tbl.add_column("Control", style="cyan")
    tbl.add_column("Score", justify="right")
    tbl.add_column("Status", overflow="fold")
    earned = total = 0
    for label, key, fn in CONTROLS:
        pts, maxpts, note = fn(hdr.get(key))
        earned += pts
        total += maxpts
        ratio = pts / maxpts if maxpts else 0
        color = "green" if ratio >= 0.85 else ("yellow" if ratio >= 0.4 else "red")
        tbl.add_row(label, f"[{color}]{pts}/{maxpts}[/{color}]", note)
    console.print(tbl)

    leaks = [(h, hdr[h]) for h in INFO_LEAK_HEADERS if h in hdr and hdr[h].strip()]
    if leaks:
        lt = Table(title="Information Disclosure", header_style="bold yellow", box=box.MINIMAL)
        lt.add_column("Header", style="yellow")
        lt.add_column("Value", overflow="fold")
        for h, v in leaks:
            lt.add_row(h, v)
        console.print(lt)
        earned = max(earned - min(len(leaks) * 2, 6), 0)

    pct = round(earned / total * 100, 1) if total else 0
    grade = grade_for(pct)
    gcolor = "bold green" if grade in ("A+", "A") else ("yellow" if grade in ("B", "C") else "bold red")
    summary = (
        f"Score: {earned}/{total} ({pct}%)   Grade: {grade}   "
        f"Info-leak headers: {len(leaks)}   Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(f"[{gcolor}]GRADE  {grade}[/{gcolor}]   {pct}%\n{summary}",
                        title="Result", style=gcolor))
    console.print("[green][*] Security headers grade completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        parts = [tbl]
        if leaks:
            parts.append(lt)
        parts.append(Panel(f"GRADE {grade}  {pct}%\n{summary}", title="Result"))
        write_to_file(os.path.join(out, "security_headers_grade.txt"),
                      render_to_text(*parts, width=console.width))


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except json.JSONDecodeError:
            pass
    run(tgt, thr, opts)
