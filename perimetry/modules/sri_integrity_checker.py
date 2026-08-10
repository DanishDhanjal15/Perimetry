#!/usr/bin/env python3
"""Perimetry - Subresource Integrity (SRI) Checker.

Every third-party script a page loads runs with the page's full privileges, so a
compromised CDN can silently take over the site. Subresource Integrity pins each
external resource to a cryptographic hash, and the browser refuses to execute
anything that does not match.

This module lists every external <script> and stylesheet, reports which ones
carry an integrity attribute, and - unlike a presence-only check - downloads the
resource and verifies the declared hash actually matches. A stale integrity
value is worse than none: the resource silently fails to load in production.
"""
import os, sys, json, re, base64, hashlib, concurrent.futures, requests, urllib3
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from perimetry.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, render_to_text
from perimetry.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

TAG_RE = re.compile(r"<(script|link)\b([^>]*)>", re.I)
ATTR_RE = re.compile(r"""([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
HASH_FUNCS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]     Perimetry - Subresource Integrity Checker")
    console.print(f"[{TEAL}]{bar}\n")


def parse_attrs(blob):
    attrs = {}
    for m in ATTR_RE.finditer(blob):
        name = m.group(1).lower()
        value = m.group(2) or m.group(3) or m.group(4) or ""
        attrs[name] = value
    return attrs


def collect_resources(html, base):
    """Return [(kind, url, integrity, crossorigin)] for external scripts/styles."""
    out = []
    for m in TAG_RE.finditer(html):
        tag = m.group(1).lower()
        attrs = parse_attrs(m.group(2))
        if tag == "script":
            src = attrs.get("src", "").strip()
            kind = "script"
        else:
            rel = attrs.get("rel", "").lower()
            if "stylesheet" not in rel:
                continue
            src = attrs.get("href", "").strip()
            kind = "stylesheet"
        if not src or src.startswith(("data:", "javascript:", "#")):
            continue
        out.append((kind, urljoin(base, src),
                    attrs.get("integrity", "").strip(), attrs.get("crossorigin", "").strip()))
    # de-duplicate by URL, keeping the first occurrence
    seen, uniq = set(), []
    for item in out:
        if item[1] in seen:
            continue
        seen.add(item[1])
        uniq.append(item)
    return uniq


def is_external(url, host):
    try:
        netloc = urlparse(url).netloc.lower()
    except ValueError:
        return False
    if not netloc:
        return False
    netloc = netloc.split(":")[0]
    return not (netloc == host or netloc.endswith("." + host))


def verify_integrity(url, integrity, timeout):
    """Download the resource and check it against the declared hash.

    Returns (status, note). SRI allows several space-separated hashes; the spec
    treats the resource as valid if ANY of them matches.
    """
    try:
        r = requests.get(url, timeout=timeout, verify=False, headers={"User-Agent": USER_AGENT})
        if r.status_code != 200:
            return "UNVERIFIED", f"HTTP {r.status_code}"
        body = r.content
    except requests.RequestException:
        return "UNVERIFIED", "fetch failed"

    tokens = [t for t in integrity.split() if "-" in t]
    if not tokens:
        return "INVALID", "malformed integrity value"
    for token in tokens:
        algo, _, digest = token.partition("-")
        fn = HASH_FUNCS.get(algo.lower())
        if not fn:
            continue
        actual = base64.b64encode(fn(body).digest()).decode()
        if actual == digest.strip():
            return "VALID", f"{algo} verified"
    return "MISMATCH", "hash does not match served content"


def check_one(item, host, timeout):
    kind, url, integrity, crossorigin = item
    external = is_external(url, host)
    if not integrity:
        if external:
            return (url, kind, "MISSING", "external resource with no integrity attribute")
        return (url, kind, "SAME-ORIGIN", "same-origin, SRI optional")
    status, note = verify_integrity(url, integrity, timeout)
    if status == "VALID" and external and not crossorigin:
        return (url, kind, "VALID", note + " (no crossorigin attribute)")
    return (url, kind, status, note)


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    max_resources = int(opts.get("max_resources", 40))
    dom = clean_domain_input(target)
    headers = {"User-Agent": USER_AGENT}

    html, base = "", f"https://{dom}"
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{dom}", timeout=timeout, verify=False,
                             headers=headers, allow_redirects=True)
            html, base = r.text or "", r.url
            break
        except requests.RequestException:
            continue
    if not html:
        console.print("[red]✖ Unable to retrieve the main page[/red]")
        return

    host = urlparse(base).netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    resources = collect_resources(html, base)[:max_resources]
    console.print(f"[white]* {len(resources)} external script/stylesheet reference(s) found[/white]")

    if not resources:
        console.print("[green]No external scripts or stylesheets to check.[/green]")
        console.print("[green][*] SRI check completed[/green]\n")
        return

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(threads, 4)) as pool:
        for res in pool.map(lambda i: check_one(i, host, timeout), resources):
            results.append(res)

    rank = {"MISMATCH": 0, "INVALID": 1, "MISSING": 2, "UNVERIFIED": 3, "VALID": 4, "SAME-ORIGIN": 5}
    results.sort(key=lambda r: rank.get(r[2], 9))

    scolor = {"MISMATCH": "bold red", "INVALID": "bold red", "MISSING": "yellow",
              "UNVERIFIED": "white", "VALID": "green", "SAME-ORIGIN": "dim"}
    tbl = Table(title=f"Subresource Integrity – {dom}", header_style="bold white", box=box.MINIMAL)
    tbl.add_column("Status")
    tbl.add_column("Type", style="cyan")
    tbl.add_column("Resource", overflow="fold")
    tbl.add_column("Note", overflow="fold")
    counts = {}
    for url, kind, status, note in results:
        counts[status] = counts.get(status, 0) + 1
        short = url if len(url) <= 70 else url[:34] + "…" + url[-33:]
        tbl.add_row(f"[{scolor.get(status,'white')}]{status}[/{scolor.get(status,'white')}]",
                    kind, short, note)
    console.print(tbl)

    external_total = sum(v for k, v in counts.items() if k != "SAME-ORIGIN")
    protected = counts.get("VALID", 0)
    coverage = round(protected / external_total * 100, 1) if external_total else 100.0
    broken = counts.get("MISMATCH", 0) + counts.get("INVALID", 0)
    summary = (
        f"External resources: {external_total}   Protected: {protected} ({coverage}%)   "
        f"Missing SRI: {counts.get('MISSING',0)}   Broken hashes: {broken}"
    )
    style = "bold red" if broken else ("yellow" if counts.get("MISSING") else "bold green")
    console.print(Panel(summary, title="Summary", style=style))
    if broken:
        console.print("[bold red]A broken integrity hash means the browser refuses to load "
                      "that resource - the site is likely already degraded.[/bold red]")
    console.print("[green][*] SRI check completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "sri_integrity_checker.txt"),
                      render_to_text(tbl, Panel(summary, title="Summary"), width=console.width))


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except json.JSONDecodeError:
            pass
    run(tgt, thr, opts)
