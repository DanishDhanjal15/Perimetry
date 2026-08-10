#!/usr/bin/env python3
"""Perimetry - Subdomain Takeover (Deep).

Passively enumerates subdomains from Certificate Transparency logs, then checks
each one for a dangling delegation that could be claimed by an attacker: a CNAME
pointing at a de-provisioned cloud service whose take-over signature still shows
in the HTTP response. Matching is driven by a fingerprint database modelled on
the community can-i-take-over-xyz dataset (CNAME pattern + response marker +
whether the service is known to be exploitable).
"""
import os, sys, json, re, concurrent.futures, requests, urllib3
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from perimetry.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, render_to_text
from perimetry.config.settings import EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

# service, CNAME substrings, HTTP body markers, exploitable(True/"edge"/False)
FINGERPRINTS = [
    ("GitHub Pages",   ["github.io", "github.map.fastly.net"], ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"], True),
    ("AWS S3",         ["s3.amazonaws.com", "s3-website", ".s3."], ["NoSuchBucket", "The specified bucket does not exist"], True),
    ("Heroku",         ["herokuapp.com", "herokudns.com", "herokussl.com"], ["No such app", "There's nothing here, yet."], "edge"),
    ("Shopify",        ["myshopify.com"], ["Sorry, this shop is currently unavailable", "Only one step left!"], "edge"),
    ("Fastly",         ["fastly.net"], ["Fastly error: unknown domain"], "edge"),
    ("Azure",          ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azureedge.net", "blob.core.windows.net"], ["404 Web Site not found", "The specified blob does not exist"], True),
    ("Bitbucket",      ["bitbucket.io"], ["Repository not found"], True),
    ("Unbounce",       ["unbouncepages.com"], ["The requested URL was not found on this server"], "edge"),
    ("Pantheon",       ["pantheonsite.io"], ["The gods are wise", "404 error unknown site"], True),
    ("Tumblr",         ["domains.tumblr.com"], ["Whatever you were looking for doesn't currently exist at this address"], "edge"),
    ("Wordpress.com",  ["wordpress.com"], ["Do you want to register"], "edge"),
    ("Ghost",          ["ghost.io"], ["The thing you were looking for is no longer here", "Domain error"], "edge"),
    ("Surge.sh",       ["surge.sh"], ["project not found"], True),
    ("Zendesk",        ["zendesk.com"], ["Help Center Closed"], "edge"),
    ("Cargo",          ["cargocollective.com"], ["404 Not Found"], "edge"),
    ("Readthedocs",    ["readthedocs.io"], ["unknown to Read the Docs"], True),
    ("Netlify",        ["netlify.app", "netlify.com"], ["Not Found - Request ID"], "edge"),
    ("Webflow",        ["proxy-ssl.webflow.com", "webflow.io"], ["The page you are looking for doesn't exist or has been moved"], "edge"),
    ("Desk.com",       ["desk.com"], ["Please try again or try Desk.com free for 14 days"], "edge"),
    ("Help Scout",     ["helpscoutdocs.com"], ["No settings were found for this company"], True),
]


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]      Perimetry - Subdomain Takeover (Deep)")
    console.print(f"[{TEAL}]{bar}\n")


def _from_crtsh(dom, timeout, subs):
    # crt.sh is authoritative but frequently 502s; one quick retry is worth it.
    for attempt in range(2):
        try:
            r = requests.get("https://crt.sh/", params={"q": f"%.{dom}", "output": "json"},
                             timeout=timeout, headers={"User-Agent": USER_AGENT})
            if r.status_code == 200 and r.text.strip():
                for row in r.json():
                    for name in str(row.get("name_value", "")).splitlines():
                        _add_sub(name, dom, subs)
                return
        except (requests.RequestException, ValueError):
            pass


def _from_certspotter(dom, timeout, subs):
    try:
        r = requests.get("https://api.certspotter.com/v1/issuances",
                         params={"domain": dom, "include_subdomains": "true", "expand": "dns_names"},
                         timeout=timeout, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            for issuance in r.json():
                for name in issuance.get("dns_names", []):
                    _add_sub(name, dom, subs)
    except (requests.RequestException, ValueError):
        pass


def _add_sub(name, dom, subs):
    name = str(name).strip().lstrip("*.").lower()
    if name.endswith(dom) and "@" not in name and " " not in name:
        subs.add(name)


def fetch_subdomains(dom, timeout):
    """Passive subdomain set from multiple CT-log sources, merged."""
    subs = set()
    _from_crtsh(dom, timeout, subs)
    # certspotter fills in when crt.sh is down and widens coverage otherwise.
    _from_certspotter(dom, timeout, subs)
    subs.discard(dom)
    return sorted(subs)


def resolve_cname(host):
    try:
        ans = dns.resolver.resolve(host, "CNAME", lifetime=5)
        return str(ans[0].target).rstrip(".").lower()
    except Exception:
        return None


def resolves_a(host):
    try:
        dns.resolver.resolve(host, "A", lifetime=5)
        return True
    except Exception:
        return False


def match_service(cname):
    if not cname:
        return None
    for service, patterns, markers, vuln in FINGERPRINTS:
        if any(p in cname for p in patterns):
            return (service, markers, vuln)
    return None


def check_sub(host, timeout):
    """Return (host, status, service, detail). status in SAFE/POTENTIAL/VULNERABLE/DANGLING."""
    cname = resolve_cname(host)
    svc = match_service(cname)
    if not svc and cname is None:
        return None  # plain A record or no record - not takeover-relevant
    if not svc:
        return None
    service, markers, vuln = svc

    # A CNAME to a known service whose apex no longer resolves is a strong signal.
    dangling = not resolves_a(host)
    body = ""
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", timeout=timeout, verify=False,
                             headers={"User-Agent": USER_AGENT}, allow_redirects=True)
            body = r.text or ""
            break
        except requests.RequestException:
            continue

    marker_hit = any(m.lower() in body.lower() for m in markers)
    detail = f"CNAME→{cname}"
    if marker_hit and vuln is True:
        return (host, "VULNERABLE", service, detail + " | take-over marker present")
    if marker_hit:
        return (host, "POTENTIAL", service, detail + " | marker present (service needs verification)")
    if dangling:
        return (host, "POTENTIAL", service, detail + " | dangling CNAME, no A record")
    return (host, "SAFE", service, detail + " | claimed/live")


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", 10))
    max_subs = int(opts.get("max_subs", 60))
    dom = clean_domain_input(target)

    console.print(f"[white]* Enumerating subdomains for {dom} via CT logs (crt.sh + certspotter)…[/white]")
    subs = fetch_subdomains(dom, max(timeout, 20))
    if not subs:
        console.print("[yellow]No subdomains returned from CT logs (sources rate-limited or none on record).[/yellow]")
        console.print("[green][*] Subdomain takeover scan completed[/green]\n")
        return
    checked = subs[:max_subs]
    console.print(f"[white]* {len(subs)} unique subdomain(s) found, checking {len(checked)} for dangling CNAMEs[/white]")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(threads, 8)) as pool:
        futs = {pool.submit(check_sub, s, timeout): s for s in checked}
        for fut in concurrent.futures.as_completed(futs):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                results.append(res)

    rank = {"VULNERABLE": 0, "POTENTIAL": 1, "SAFE": 2, "DANGLING": 1}
    results.sort(key=lambda r: rank.get(r[1], 3))

    tbl = Table(title=f"Takeover Candidates – {dom}", header_style="bold white", box=box.MINIMAL)
    tbl.add_column("Status")
    tbl.add_column("Subdomain", style="cyan", overflow="fold")
    tbl.add_column("Service", style="green")
    tbl.add_column("Detail", overflow="fold")
    scolor = {"VULNERABLE": "bold red", "POTENTIAL": "yellow", "SAFE": "green"}
    n_vuln = n_pot = 0
    for host, status, service, detail in results:
        if status == "VULNERABLE":
            n_vuln += 1
        elif status == "POTENTIAL":
            n_pot += 1
        tbl.add_row(f"[{scolor.get(status,'white')}]{status}[/{scolor.get(status,'white')}]",
                    host, service, detail)

    if results:
        console.print(tbl)
    else:
        console.print("[green]No subdomains point at a fingerprinted takeover-prone service.[/green]")

    summary = (
        f"Subdomains: {len(subs)}   Checked: {len(checked)}   "
        f"Candidates: {len(results)}   VULNERABLE: {n_vuln}   POTENTIAL: {n_pot}"
    )
    style = "bold red" if n_vuln else ("yellow" if n_pot else "bold white")
    console.print(Panel(summary, title="Summary", style=style))
    console.print("[green][*] Subdomain takeover scan completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        body = tbl if results else Panel("No takeover-prone subdomains found.", title="Result")
        write_to_file(os.path.join(out, "subdomain_takeover_deep.txt"),
                      render_to_text(body, Panel(summary, title="Summary"), width=console.width))


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
