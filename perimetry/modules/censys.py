#!/usr/bin/env python3
import sys, os, json, asyncio, aiohttp, ipaddress, time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from perimetry.utils.util import resolve_to_ip, clean_domain_input
from perimetry.config.settings import DEFAULT_TIMEOUT, API_KEYS

console = Console()
C_ID = API_KEYS.get("CENSYS_API_ID")
C_SEC = API_KEYS.get("CENSYS_API_SECRET")
C_KEY = API_KEYS.get("CENSYS_API_KEY")
# Platform API (single bearer token) is what current Censys accounts are issued;
# search.censys.io only accepts the older API ID + secret pair.
C_PLATFORM = "https://api.platform.censys.io/v3/global/asset/host/"
C_API = "https://search.censys.io/api/v2/hosts/"

RETRY_STATUSES = {429, 500, 502, 503, 504}

async def _get_json(session, url, *, auth=None, headers=None, method="GET", data=None, timeout=DEFAULT_TIMEOUT, retries=3, backoff=0.8):
    for attempt in range(1, retries + 1):
        try:
            if method == "POST":
                async with session.post(url, json=data, timeout=timeout, auth=auth, headers=headers) as r:
                    if r.status == 200:
                        return await r.json()
                    if r.status in RETRY_STATUSES and attempt < retries:
                        await asyncio.sleep(backoff * attempt)
                        continue
                    return {"_status": r.status}
            else:
                async with session.get(url, timeout=timeout, auth=auth, headers=headers) as r:
                    if r.status == 200:
                        return await r.json()
                    if r.status in RETRY_STATUSES and attempt < retries:
                        await asyncio.sleep(backoff * attempt)
                        continue
                    return {"_status": r.status}
        except Exception:
            if attempt < retries:
                await asyncio.sleep(backoff * attempt)
                continue
            return {"_error": "request_fail"}
    return {"_error": "request_fail"}

async def fetch_ipinfo(session, ip, sem):
    async with sem:
        j = await _get_json(session, f"https://ipinfo.io/{ip}/json")
        if "_error" in j: return {"ip": ip, "error": "ipinfo_fail"}
        return {"ip": ip, "src": "ipinfo", "data": j}

async def fetch_censys(session, ip, sem):
    if C_KEY:
        async with sem:
            j = await _get_json(session, f"{C_PLATFORM}{ip}",
                                headers={"Authorization": f"Bearer {C_KEY}"})
            resource = (j or {}).get("result", {}).get("resource")
            if resource:
                return {"ip": ip, "src": "censys", "data": resource}
    elif C_ID and C_SEC:
        async with sem:
            j = await _get_json(session, f"{C_API}{ip}", auth=aiohttp.BasicAuth(C_ID, C_SEC))
            if j and j.get("result"):
                return {"ip": ip, "src": "censys", "data": j["result"]}
    return await fetch_ipinfo(session, ip, sem)

def _top_ports(services, n=8):
    try:
        ports = {}
        for s in services or []:
            p = s.get("port")
            if p is not None:
                ports[p] = ports.get(p, 0) + 1
        top = sorted(ports.items(), key=lambda x: (-x[1], x[0]))[:n]
        return ", ".join(str(p) for p, _ in top) if top else "—"
    except Exception:
        return "—"

def display(entry):
    if "error" in entry:
        console.print(f"[red]{entry['ip']} – {entry['error']}[/red]")
        return
    d = entry["data"]; ip = entry["ip"]; src = entry["src"]
    t = Table(title=f"{ip} ({src})", show_header=True, header_style="bold magenta")
    t.add_column("Field", style="cyan")
    t.add_column("Value", style="green")
    if src == "censys":
        services = d.get("services", []) or []
        t.add_row("Open Ports", str(d.get("service_count") or len(services)))
        t.add_row("Top Ports", _top_ports(services))
        protos = sorted({s.get("protocol") for s in services if s.get("protocol")})
        t.add_row("Protocols", ", ".join(protos) if protos else "—")
        meta = d.get("metadata", {}) or {}
        asn = d.get("autonomous_system", {}) or {}
        loc = d.get("location", {}) or {}
        t.add_row("OS", meta.get("os") or d.get("operating_system") or "—")
        t.add_row("ASN", f"{asn.get('asn') or '—'} ({asn.get('description') or asn.get('name') or '—'})")
        t.add_row("BGP Prefix", asn.get("bgp_prefix") or "—")
        t.add_row("Country", loc.get("country") or loc.get("country_code") or "—")
        t.add_row("City", loc.get("city") or "—")
        t.add_row("Org", meta.get("organization") or asn.get("name") or "—")
        dns = d.get("dns", {}) or {}
        # Platform returns a flat `names` list; Search v2 nested it under reverse_dns.
        names = dns.get("names") if isinstance(dns.get("names"), list) else None
        if not names and isinstance(dns.get("reverse_dns"), dict):
            names = dns["reverse_dns"].get("names")
        if names:
            shown = ", ".join(names[:5])
            t.add_row("RDNS", f"{shown} (+{len(names) - 5} more)" if len(names) > 5 else shown)
        else:
            t.add_row("RDNS", "—")
        last_up = d.get("last_updated_at") or d.get("last_updated")
        t.add_row("Last Seen", last_up or "—")
    else:
        t.add_row("Hostname", d.get("hostname") or d.get("host") or "—")
        t.add_row("City", d.get("city") or "—")
        t.add_row("Region", d.get("region") or "—")
        t.add_row("Country", d.get("country") or "—")
        t.add_row("Org", d.get("org") or "—")
        asn = d.get("asn") or {}
        if isinstance(asn, dict):
            t.add_row("ASN", f"{asn.get('asn','—')} ({asn.get('name','—')})")
    console.print(t)

async def run_async(targets, concurrency):
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as sess:
        tasks = [fetch_censys(sess, ip, sem) for ip in targets]
        with Progress(SpinnerColumn(), TextColumn("[white]Querying {task.completed}/{task.total}[/white]"), BarColumn(), transient=True, console=console) as prog:
            task = prog.add_task("Enrichment", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                entry = await coro
                display(entry)
                prog.update(task, advance=1)

def collect(target):
    ips = []
    if os.path.isfile(target):
        with open(target, "r", encoding="utf-8", errors="ignore") as fh:
            ips = [l.strip() for l in fh if l.strip()]
    else:
        dom = clean_domain_input(target)
        res = resolve_to_ip(dom) or ([target] if dom == target else [])
        ips = res if isinstance(res, list) else [res]
    out = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            out.append(ip)
        except Exception:
            continue
    return list(dict.fromkeys(out))

def main(target, opts):
    conc = int(opts.get("concurrency", 5) or 5)
    ips = collect(target)
    if not ips:
        console.print("[red]No valid IPs[/red]")
        return
    asyncio.run(run_async(ips, conc))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/] script.py <domain|ip|file> [threads] [opts_json]")
        sys.exit(1)
    tgt = sys.argv[1]
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except Exception:
        opts = {}
    main(tgt, opts)
