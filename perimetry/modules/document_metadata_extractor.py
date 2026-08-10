#!/usr/bin/env python3
"""Perimetry - Document Metadata Extractor.

Public documents are one of the most reliable OSINT sources an organisation
forgets about. A PDF carries the name of whoever exported it and the software
that produced it; an Office file additionally records the last editor and the
company. Together they leak internal usernames (useful for password spraying and
phishing), unpatched software versions, and sometimes internal file paths.

Documents linked from the target's homepage and sitemap are downloaded (size
capped) and parsed in-process: PDFs via their info dictionary, OOXML files via
their docProps parts. No third-party parser is required - PDF metadata is read
from the raw bytes and Office files are ordinary ZIP archives.
"""
import os, sys, json, re, io, zipfile, concurrent.futures, requests, urllib3
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from perimetry.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, render_to_text
from perimetry.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

DOC_EXT = (".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".odt", ".ods")
HREF_RE = re.compile(r"""(?:href|src)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""", re.I)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# PDF info-dictionary fields. Values are either literal (...) or hex <...>.
PDF_FIELDS = ("Author", "Creator", "Producer", "Title", "CreationDate", "ModDate", "Company")
OOXML_FIELDS = {
    "dc:creator": "Author",
    "cp:lastModifiedBy": "Last Modified By",
    "dc:title": "Title",
    "Application": "Creator",
    "AppVersion": "App Version",
    "Company": "Company",
    "Manager": "Manager",
}
# Windows/UNC paths that occasionally survive inside document metadata.
PATH_RE = re.compile(
    r"[A-Za-z]:\\[^\s\"'<>|)]{3,80}"          # C:\Users\someone\report.docx
    r"|\\\\[A-Za-z0-9_.\-]+\\[^\s\"'<>|)]{2,60}"  # \\fileserver\share\hr
)


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]      Perimetry - Document Metadata Extractor")
    console.print(f"[{TEAL}]{bar}\n")


def get(url, timeout, stream=False):
    try:
        return requests.get(url, timeout=timeout, verify=False, stream=stream,
                            headers={"User-Agent": USER_AGENT}, allow_redirects=True)
    except requests.RequestException:
        return None


def discover(dom, timeout, max_docs, crawl_pages, threads):
    """Collect document URLs from the homepage, the sitemap, and one crawl hop.

    Documents are rarely linked from a homepage and sitemaps normally list
    pages rather than files, so a single hop into the site's own pages is what
    actually turns this module up anything on a real target.
    """
    found, base = [], None
    home_html = ""
    for scheme in ("https", "http"):
        r = get(f"{scheme}://{dom}", timeout)
        if r is not None and r.status_code < 400:
            base, home_html = r.url, r.text or ""
            found += links_from_html(home_html, base)
            break
    if base is None:
        return [], None

    if len(found) < max_docs:
        found += from_sitemap(urljoin(base, "/sitemap.xml"), timeout, max_docs - len(found))

    if len(found) < max_docs and crawl_pages:
        pages = internal_pages(home_html, base, dom)[:crawl_pages]
        if pages:
            console.print(f"[white]* Crawling {len(pages)} internal page(s) for document links…[/white]")
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(threads, 4)) as pool:
                for page_url, html in pool.map(lambda u: (u, fetch_text(u, timeout)), pages):
                    if html:
                        found += links_from_html(html, page_url)

    seen, uniq = set(), []
    for u in found:
        clean = u.split("#")[0]
        if clean in seen:
            continue
        seen.add(clean)
        uniq.append(clean)
    return uniq, base


def fetch_text(url, timeout):
    r = get(url, timeout)
    if r is None or r.status_code != 200:
        return ""
    if "html" not in r.headers.get("Content-Type", "").lower():
        return ""
    return r.text or ""


def internal_pages(html, base, dom):
    """Same-site HTML pages worth one crawl hop."""
    out, seen = [], set()
    for m in HREF_RE.finditer(html):
        href = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if not href or href.startswith(("data:", "javascript:", "mailto:", "tel:")):
            continue
        full = urljoin(base, href).split("#")[0]
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        host = parsed.netloc.lower().split(":")[0]
        if not (host == dom or host.endswith("." + dom)):
            continue
        low = full.lower().split("?")[0]
        if low.endswith(DOC_EXT) or low.endswith((".jpg", ".png", ".svg", ".css", ".js", ".gif", ".webp", ".ico")):
            continue
        if full in seen:
            continue
        seen.add(full)
        out.append(full)
    return out


def from_sitemap(url, timeout, want, _depth=0):
    """Pull document URLs out of a sitemap.

    Large sites publish a <sitemapindex> whose entries are further sitemaps
    rather than pages, so follow one level down before giving up.
    """
    if want <= 0 or _depth > 1:
        return []
    sm = get(url, timeout)
    if sm is None or sm.status_code != 200:
        return []
    body = sm.text or ""
    locs = LOC_RE.findall(body)
    docs = [l for l in locs if l.lower().split("?")[0].endswith(DOC_EXT)]
    if docs or "<sitemapindex" not in body[:1000].lower():
        return docs[:want]
    for child in locs[:5]:
        docs += from_sitemap(child, timeout, want - len(docs), _depth + 1)
        if len(docs) >= want:
            break
    return docs[:want]


def links_from_html(html, base):
    out = []
    for m in HREF_RE.finditer(html):
        href = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if not href or href.startswith(("data:", "javascript:", "mailto:")):
            continue
        full = urljoin(base, href)
        if full.lower().split("?")[0].endswith(DOC_EXT):
            out.append(full)
    return out


# The info dictionary and the XMP packet sit near the end of a PDF, but not
# right at it - in a large export they can start ~12% before EOF, so the tail
# window has to be generous or the metadata is missed entirely.
TAIL_BYTES = 1_500_000


def download(url, timeout, max_bytes):
    """Fetch a document, capped so one huge file cannot stall the scan.

    Both formats keep the parts we need at the END of the file - a PDF's info
    dictionary lives in the trailer and a ZIP's central directory is the last
    record - so when a file exceeds the cap the tail is pulled separately with
    a Range request instead of being thrown away.
    """
    r = get(url, timeout, stream=True)
    if r is None or r.status_code != 200:
        return None
    buf = bytearray()
    truncated = False
    try:
        for chunk in r.iter_content(8192):
            buf += chunk
            if len(buf) >= max_bytes:
                truncated = True
                break
    except requests.RequestException:
        return None
    finally:
        r.close()

    if truncated:
        tail = fetch_tail(url, timeout)
        if tail:
            buf += tail
    return bytes(buf)


def fetch_tail(url, timeout):
    """Last TAIL_BYTES of the resource, or None if the server ignores Range."""
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": USER_AGENT, "Range": f"bytes=-{TAIL_BYTES}"})
    except requests.RequestException:
        return None
    # 206 means the server honoured the range; 200 would be the whole file again.
    if r.status_code != 206:
        return None
    return r.content


def decode_pdf_value(raw):
    """Decode a PDF string value, hex <...> or literal (...).

    Either form may hold UTF-16BE text behind a byte-order mark, which is what
    Office producers emit - without that step the value renders as mojibake.
    """
    if raw.startswith("<") and raw.endswith(">"):
        hexstr = re.sub(r"[^0-9A-Fa-f]", "", raw[1:-1])
        try:
            data = bytes.fromhex(hexstr if len(hexstr) % 2 == 0 else hexstr[:-1])
        except ValueError:
            return ""
    else:
        literal = raw[1:-1] if raw.startswith("(") and raw.endswith(")") else raw
        literal = literal.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
        data = literal.encode("latin-1", "replace")

    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", "replace").strip()
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace").strip()
    return data.decode("latin-1", "replace").strip()


def parse_pdf(blob):
    """Read a PDF's info dictionary and, if present, its XMP packet.

    Modern producers often write only XMP, so a checker that looks at the
    classic /Info keys alone reports "no metadata" on files that are in fact
    leaking an author name.
    """
    meta = {}
    text = blob.decode("latin-1", "replace")
    for field in PDF_FIELDS:
        # A literal string may contain escaped parentheses, so the value cannot
        # simply run to the first ')'.
        m = re.search(rf"/{field}\s*(\((?:[^()\\]|\\.)*\)|<[0-9A-Fa-f\s]*>)", text)
        if m:
            value = decode_pdf_value(m.group(1))
            if value:
                meta[field] = value[:120]
    for label, value in parse_xmp(text).items():
        meta.setdefault(label, value)
    return meta


XMP_FIELDS = {
    "dc:creator": "Author",
    "xmp:CreatorTool": "Creator",
    "pdf:Producer": "Producer",
    "dc:title": "Title",
    "xmp:CreateDate": "CreationDate",
    "xmp:ModifyDate": "ModDate",
    "xmpMM:DocumentID": "Document ID",
}


def parse_xmp(text):
    """Pull the interesting fields out of an embedded XMP packet."""
    start = text.find("<x:xmpmeta")
    if start == -1:
        return {}
    packet = text[start:start + 20000]
    out = {}
    for tag, label in XMP_FIELDS.items():
        m = re.search(rf"<{re.escape(tag)}[^>]*>(.*?)</{re.escape(tag)}>", packet, re.S)
        if not m:
            continue
        value = m.group(1)
        # dc:* fields wrap their value in an rdf:Alt/rdf:Seq list.
        li = re.search(r"<rdf:li[^>]*>(.*?)</rdf:li>", value, re.S)
        if li:
            value = li.group(1)
        value = re.sub(r"<[^>]+>", "", value).strip()
        if value:
            out[label] = value[:120]
    return out


def parse_ooxml(blob):
    meta = {}
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            names = set(z.namelist())
            for part in ("docProps/core.xml", "docProps/app.xml"):
                if part not in names:
                    continue
                xml = z.read(part).decode("utf-8", "replace")
                for tag, label in OOXML_FIELDS.items():
                    m = re.search(rf"<{re.escape(tag)}[^>]*>([^<]+)</{re.escape(tag)}>", xml)
                    if m and m.group(1).strip():
                        meta[label] = m.group(1).strip()[:120]
    except (zipfile.BadZipFile, KeyError, OSError):
        return {}
    return meta


def analyse(url, timeout, max_bytes):
    blob = download(url, timeout, max_bytes)
    if not blob:
        return None
    if blob[:4] == b"%PDF":
        meta = parse_pdf(blob)
        kind = "PDF"
    elif blob[:2] == b"PK":
        meta = parse_ooxml(blob)
        kind = "OOXML"
    else:
        return None
    if not meta:
        return None
    paths = sorted(set(PATH_RE.findall(" ".join(meta.values()))))
    return (url, kind, meta, paths)


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    max_docs = int(opts.get("max_docs", 15))
    max_bytes = int(opts.get("max_bytes", 3_000_000))
    crawl_pages = int(opts.get("crawl_pages", 15))
    dom = clean_domain_input(target)

    console.print(f"[white]* Discovering documents linked from {dom}…[/white]")
    urls, base = discover(dom, timeout, max_docs, crawl_pages, threads)
    if base is None:
        console.print("[red]✖ Unable to reach the target[/red]")
        return
    if not urls:
        console.print("[yellow]No linked documents (PDF/Office) found on the homepage or sitemap.[/yellow]")
        console.print("[green][*] Document metadata extraction completed[/green]\n")
        return

    urls = urls[:max_docs]
    console.print(f"[white]* {len(urls)} document(s) queued for metadata extraction[/white]")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(threads, 4)) as pool:
        for res in pool.map(lambda u: analyse(u, timeout, max_bytes), urls):
            if res:
                results.append(res)

    if not results:
        console.print("[green]Documents fetched but none exposed usable metadata.[/green]")
        console.print("[green][*] Document metadata extraction completed[/green]\n")
        return

    tbl = Table(title=f"Document Metadata – {dom}", header_style="bold white", box=box.MINIMAL)
    tbl.add_column("Document", style="cyan", overflow="fold")
    tbl.add_column("Type")
    tbl.add_column("Field", style="green")
    tbl.add_column("Value", overflow="fold")
    people, software, companies, all_paths = set(), set(), set(), set()
    for url, kind, meta, paths in results:
        name = url.rsplit("/", 1)[-1][:44] or url
        first = True
        for field, value in meta.items():
            tbl.add_row(name if first else "", kind if first else "", field, value)
            first = False
            if field in ("Author", "Last Modified By", "Manager"):
                people.add(value)
            elif field in ("Creator", "Producer", "Application", "App Version"):
                software.add(value)
            elif field == "Company":
                companies.add(value)
        all_paths.update(paths)
    console.print(tbl)

    if people or software or companies or all_paths:
        agg = Table(title="Aggregated Intelligence", header_style="bold yellow", box=box.MINIMAL)
        agg.add_column("Category", style="yellow")
        agg.add_column("Values", overflow="fold")
        if people:
            agg.add_row("Usernames / authors", ", ".join(sorted(people)))
        if software:
            agg.add_row("Software", ", ".join(sorted(software)))
        if companies:
            agg.add_row("Company", ", ".join(sorted(companies)))
        if all_paths:
            agg.add_row("Internal paths", ", ".join(sorted(all_paths)))
        console.print(agg)

    summary = (
        f"Documents found: {len(urls)}   With metadata: {len(results)}   "
        f"Names exposed: {len(people)}   Software: {len(software)}   Paths: {len(all_paths)}"
    )
    style = "bold red" if people or all_paths else "bold white"
    console.print(Panel(summary, title="Summary", style=style))
    if people:
        console.print("[yellow]Exposed author names are valid usernames for phishing and "
                      "password-spray target lists - consider stripping metadata before publishing.[/yellow]")
    console.print("[green][*] Document metadata extraction completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        parts = [tbl]
        if people or software or companies or all_paths:
            parts.append(agg)
        parts.append(Panel(summary, title="Summary"))
        write_to_file(os.path.join(out, "document_metadata_extractor.txt"),
                      render_to_text(*parts, width=console.width))


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except json.JSONDecodeError:
            pass
    run(tgt, thr, opts)
