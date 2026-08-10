#!/usr/bin/env python3
"""Perimetry - CVE Enrichment from Tech Stack.

Fingerprints the target's server-side and client-side technologies (with
versions where they leak), then queries the public NVD 2.0 CVE feed for known
vulnerabilities that reference each product+version. Findings are ranked by
CVSS so the highest-risk components surface first. This is triage input, not a
confirmation that the host is exploitable - a keyword match means "worth a
closer look", and the module says so.

NVD works without an API key (rate-limited to ~5 requests / 30s); set
NVD_API_KEY in the environment to raise the limit and speed the scan up.
"""
import os, sys, json, re, time, requests, urllib3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from perimetry.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, render_to_text
from perimetry.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Version-bearing signatures pulled from headers, meta tags and script paths.
SERVER_RE     = re.compile(r"([A-Za-z][A-Za-z0-9_\-]+)/(\d+(?:\.\d+){1,3})")
META_GEN_RE   = re.compile(r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]([^'\"]+)['\"]", re.I)
JS_LIB_RE     = re.compile(r"/([a-zA-Z][a-zA-Z0-9_.\-]*?)[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)
POWERED_RE    = re.compile(r"([A-Za-z][A-Za-z0-9_\-]+)[/ ](\d+(?:\.\d+){1,3})")


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]     Perimetry - CVE Enrichment from Tech Stack")
    console.print(f"[{TEAL}]{bar}\n")


def detect_stack(dom, timeout):
    """Return a de-duplicated list of (product, version, source) tuples."""
    found = {}
    headers = {"User-Agent": USER_AGENT}
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{dom}", timeout=timeout, verify=False, headers=headers)
            break
        except requests.RequestException:
            r = None
    if r is None:
        return [], None

    hdr = {k.lower(): v for k, v in r.headers.items()}
    for key, label in (("server", "Server header"), ("x-powered-by", "X-Powered-By"),
                       ("x-aspnet-version", "X-AspNet-Version"), ("x-generator", "X-Generator")):
        val = hdr.get(key, "")
        if not val:
            continue
        for prod, ver in SERVER_RE.findall(val):
            found[(prod.lower(), ver)] = (prod, ver, label)
        if key == "x-aspnet-version" and re.match(r"^\d", val):
            found[("asp.net", val.strip())] = ("ASP.NET", val.strip(), label)

    html = r.text or ""
    for gen in META_GEN_RE.findall(html):
        m = POWERED_RE.search(gen)
        if m:
            found[(m.group(1).lower(), m.group(2))] = (m.group(1), m.group(2), "meta generator")
    for prod, ver in JS_LIB_RE.findall(html):
        prod_c = prod.lower().rstrip(".-")
        if prod_c and not prod_c.isdigit():
            found[(prod_c, ver)] = (prod, ver, "JS library")

    return list(found.values()), r


def query_nvd(product, version, timeout, api_key):
    """Best-effort NVD keyword lookup -> list of (cve, cvss, severity, desc)."""
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 20}
    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code == 403 or r.status_code == 429:
        return "RATELIMIT"
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None

    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "?")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        cvss, sev = extract_cvss(cve.get("metrics", {}))
        out.append((cid, cvss, sev, desc[:110]))
    out.sort(key=lambda x: x[1] if isinstance(x[1], float) else -1, reverse=True)
    return out


def extract_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            score = d.get("baseScore")
            sev = arr[0].get("baseSeverity") or d.get("baseSeverity") or "-"
            if isinstance(score, (int, float)):
                return float(score), sev
    return "-", "-"


def sev_color(sev):
    s = str(sev).upper()
    if s == "CRITICAL":
        return "bold red"
    if s == "HIGH":
        return "red"
    if s == "MEDIUM":
        return "yellow"
    if s == "LOW":
        return "green"
    return "white"


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    max_components = int(opts.get("max_components", 6))
    max_per = int(opts.get("max_cves", 5))
    dom = clean_domain_input(target)
    api_key = os.getenv("NVD_API_KEY", "").strip() or None
    start = time.time()

    console.print(f"[white]* Fingerprinting technology stack for {dom}[/white]")
    stack, resp = detect_stack(dom, timeout)
    if resp is None:
        console.print("[red]✖ Could not reach the target over HTTP/HTTPS[/red]")
        return

    stack_tbl = Table(title=f"Detected Components – {dom}", header_style="bold white", box=box.MINIMAL)
    stack_tbl.add_column("Product", style="cyan")
    stack_tbl.add_column("Version", style="green")
    stack_tbl.add_column("Source")
    for prod, ver, src in stack:
        stack_tbl.add_row(prod, ver, src)
    console.print(stack_tbl)

    if not stack:
        console.print("[yellow]No version-bearing technology signatures found "
                      "(the server may hide its versions - that's good hygiene).[/yellow]")
        console.print("[green][*] CVE enrichment completed[/green]\n")
        if EXPORT_SETTINGS.get("enable_txt_export"):
            out = os.path.join(RESULTS_DIR, dom)
            ensure_directory_exists(out)
            write_to_file(os.path.join(out, "cve_tech_enrichment.txt"),
                          render_to_text(stack_tbl, width=console.width))
        return

    console.print(f"[white]* Querying NVD for {min(len(stack), max_components)} component(s)"
                  f"{' (no API key - throttled)' if not api_key else ''}[/white]")
    cve_tbl = Table(title="Known CVEs (keyword match - verify manually)", header_style="bold white", box=box.MINIMAL)
    cve_tbl.add_column("Product", style="cyan")
    cve_tbl.add_column("CVE", style="white")
    cve_tbl.add_column("CVSS", justify="right")
    cve_tbl.add_column("Severity")
    cve_tbl.add_column("Summary", overflow="fold")

    total_cves = 0
    ratelimited = False
    for i, (prod, ver, _src) in enumerate(stack[:max_components]):
        if i and not api_key:
            time.sleep(6.5)  # respect NVD's 5-requests/30s public limit
        res = query_nvd(prod, ver, timeout, api_key)
        if res == "RATELIMIT":
            ratelimited = True
            continue
        if not res:
            continue
        for cid, cvss, sev, desc in res[:max_per]:
            total_cves += 1
            cve_tbl.add_row(f"{prod} {ver}", cid,
                            str(cvss), f"[{sev_color(sev)}]{sev}[/{sev_color(sev)}]", desc)

    if total_cves:
        console.print(cve_tbl)
    else:
        console.print("[green]No CVEs returned for the detected components.[/green]")
    if ratelimited:
        console.print("[yellow]NVD rate-limited some queries. Set NVD_API_KEY to scan fully.[/yellow]")

    summary = (
        f"Components: {len(stack)}   Queried: {min(len(stack), max_components)}   "
        f"CVEs listed: {total_cves}   Elapsed: {time.time()-start:.1f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold red" if total_cves else "bold white"))
    console.print("[green][*] CVE enrichment completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        parts = [stack_tbl]
        if total_cves:
            parts.append(cve_tbl)
        parts.append(Panel(summary, title="Summary"))
        write_to_file(os.path.join(out, "cve_tech_enrichment.txt"),
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
