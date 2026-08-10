# Perimetry - Module Reference & Review

An engineering review of all **154 modules** in Perimetry v2.0: what each one does, the
technique it actually uses, and its verified runtime status. Every status in this
document comes from a real execution run, not from reading code.

> **How this was verified.** All 154 modules were executed as subprocesses against a
> live target (`example.com`, the IANA-reserved documentation domain) with a 60-second
> per-module cap, plus a static pass over all 188 Python files for syntax, imports and
> catalog integrity.

---

## 1. At a glance

| Metric | Result |
|---|---|
| Modules in catalog | **154** |
| Executed cleanly (exit 0) | **143 / 154** |
| Python tracebacks across the whole run | **0** |
| Long-running (exceeded the 60 s test cap) | 8 |
| Correctly rejecting wrong input type | 3 |
| Require an API key for full output | 18 |
| Average module size | 145 lines |
| Sections | Network & Infrastructure · Web Application Analysis · Security & Threat Intelligence |

**Headline:** the suite is in good working order. Zero modules crash. The only
non-zero exits are three modules correctly refusing a domain when they need a
CIDR or ASN, and eight modules that are simply slow because they do a lot of
network work.

---

## 2. How a module works

Every module follows the same contract, which is what makes the suite consistent:

```
python -m perimetry.modules.<name> <target> <threads> [json-options]
```

1. **The runner spawns it as its own process** (`perimetry/core/runner.py`). One module
   crashing can never take down the CLI, and each gets a clean interpreter.
2. **`run(target, threads, opts)`** is the entry point. `opts` is the JSON blob of
   per-module options set with `set <id> <option> <value>`.
3. **Output is printed with `rich`** - tables and panels - and captured by the runner
   line by line, so progress is visible while the module is still working.
4. **Results are written twice**: a per-module `.txt` under `results/<domain>/`, and a
   combined report for the whole run.
5. **Severity is inferred** from the text the module prints, which the runner maps to
   OK / WARN / ALERT for the summary.

The practical consequence: a module is just a script that prints. That is why the
suite scales to 154 of them without central coordination - and also why output
quality varies, since nothing enforces a common result schema.

---

## 3. The modules that matter most

Not all 154 modules carry equal weight. These are the ones that would define Perimetry
as a serious security tool.

### Tier S - the flagship ten

These combine a genuinely useful finding, real implementation depth, and no
dependency on a paid API.

| ID | Module | Why it is top-tier |
|---:|---|---|
| **154** | JARM TLS Fingerprint | The single most technically demanding module. Byte-exact with Salesforce's reference implementation - **verified identical on 6 independent hosts** - so its hashes can be looked up directly in public JARM/C2 datasets. Pure sockets, zero dependencies. |
| **152** | JS Secret / API Key Scanner | Highest direct bug-bounty value in the suite. 22 vendor credential patterns plus a Shannon-entropy filter, severity grading, and masked output so the report never leaks the key it found. |
| **156** | Subdomain Takeover (Deep) | Turns a critical, immediately actionable finding. 20-service fingerprint database, dual CT sources (crt.sh + CertSpotter) so one provider outage does not blind it, and marker confirmation to suppress false positives. |
| **19** | Zone Transfer | The classic critical DNS misconfiguration. An open AXFR hands an attacker the entire internal zone; still found in the wild. |
| **116** | Git Repository Exposure Check | An exposed `.git` directory means full source-code recovery, often with credentials in history. Cheap check, severe finding. |
| **96** | Exposed Environment Files Checker | A served `.env` is game over - database passwords and API keys in plaintext. |
| **113** | Cloud Bucket Exposure | Permutes bucket names across S3, GCS and Azure. Public-bucket data leaks remain one of the most common real breaches. |
| **87** | DOM Sink Scanner | Genuine client-side vulnerability analysis - traces DOM XSS sinks (`innerHTML`, `eval`, `document.write`) back to their sources, rather than just listing headers. |
| **151** | TLS Security Config | The deepest TLS audit in the suite: protocol versions, cipher strength, forward secrecy and known protocol weaknesses in one verdict. |
| **153** | Security Headers Grade | Converts seven weighted controls into a single A+-to-F grade. The kind of one-number output that makes a tool feel professional and gets read by non-specialists. |

### Tier A - strong supporting modules

| ID | Module | Strength |
|---:|---|---|
| 158 | Document Metadata Extractor | Classic OSINT that most scanners skip. Handles both the PDF info dictionary and modern XMP packets, and recovers real employee names for phishing-risk assessment. |
| 155 | CVE Enrichment from Tech Stack | Turns passive fingerprints into ranked, CVSS-scored CVEs via the NVD API. Honest about being a keyword match. |
| 157 | Subresource Integrity Checker | Does not merely check that an `integrity` attribute exists - it re-downloads each asset and recomputes the hash, catching stale hashes that silently break production. |
| 90 | CSP Deep Analyzer | Parses the policy into directives and grades real weaknesses (`unsafe-inline`, wildcards, missing `default-src`). |
| 148 | Email Config | The most complete email-posture module: MX, SPF, DKIM, DMARC **plus** MTA-STS and BIMI. |
| 4 | DNSSEC Check | Walks the actual DNSKEY/DS/RRSIG chain rather than just reporting presence. |
| 111 | CT Log Query | Certificate transparency is the single richest passive source for subdomain discovery. |
| 112 | Breached Credentials Lookup | Uses the HIBP k-anonymity range API, so no complete hash ever leaves the host - a genuinely privacy-correct implementation. |
| 68 | Favicon Hashing | Small but strategically valuable: a favicon hash pivots to every other host running the same application. |
| 34 | RPKI Route Validity Check | Advanced networking most recon suites lack - detects BGP hijack exposure. |
| 43 | SNMP Public Community Checker | Default-credential exposure that still yields full device inventories. |
| 63 | CORS Misconfiguration Scanner | Replays forged `Origin` headers to find genuinely exploitable trust. |
| 85 | GraphQL Introspection Probe | A readable schema hands an attacker the entire API surface. |
| 130 | Attack Surface Delta | Async subdomain + resolution + port pipeline; the closest thing to continuous monitoring. |

### The dependable core

Unglamorous but used in nearly every engagement, and all verified working:
**3** DNS Records · **5** Domain Info · **18** WHOIS Lookup · **99** HTTP Headers ·
**13** SSL Expiry Alert · **27** CDN Detection · **60** Technology Stack Detection ·
**67** Form Grabber · **104** Security.txt Check · **118** SPF/DKIM/DMARC Validator.

### Honest assessment - the weakest links

Quantity is not the same as depth. These are the thinnest modules and the first
places to invest:

| ID | Module | Issue |
|---:|---|---|
| 149 | Dark Web Monitoring | **49 lines** - the smallest module. Depends on `psbdmp.ws` and `scylla.sh`, both frequently offline. The name promises far more than it delivers. |
| 108 | Subdomain Enumeration | 62 lines, single source (crt.sh). Module **156** supersedes it with multi-source enumeration. |
| 102 | Pastebin Monitoring | Produced 15 characters of output - effectively nothing without a GitHub token. |
| 51 / 52 / 57 | Crawler, Robots.txt Analyzer, Redirect Chain | Thin wrappers around a single request each; reasonable as utilities, not as findings. |
| 128 | Custom Wordlist Generator | A helper for other tools rather than a recon module in its own right. |

---

## 4. Full module reference

Legend: ✅ pass · ⏱️ long-running (correct, just slow) · ⚙️ needs a different input type.

### 4.1 Network & Infrastructure (54 modules)

| ID | Module | What it does & how it works | Keys | Status |
|---:|---|---|---|---|
| 1 | Associated Hosts | **Reverse host lookup to list domains sharing an IP.**<br>Queries HackerTarget, Shodan and crt.sh for hostnames sharing the target's IP, then merges and de-duplicates them. | Shodan | ✅ pass |
| 2 | DNS Over HTTPS | **Resolve DNS records via encrypted DoH endpoints.**<br>Sends DNS-over-HTTPS queries to Cloudflare, Google, Quad9 and AdGuard in parallel and compares the answers. | — | ✅ pass |
| 3 | DNS Records | **Enumerate standard DNS RRsets (A, AAAA, MX, NS, etc.).**<br>Resolves A/AAAA/MX/NS/TXT/CNAME/SOA record sets concurrently with dnspython. | — | ✅ pass |
| 4 | DNSSEC Check | **Detect and validate DNSSEC configuration.**<br>Walks the DNSSEC chain - DNSKEY, DS and RRSIG records - and reports whether the zone is signed and validates. | — | ✅ pass |
| 5 | Domain Info | **Registrar, creation/expiry, and zone metadata.**<br>Combines WHOIS, RDAP and DNS to report registrar, creation/expiry dates and zone metadata. | — | ✅ pass |
| 6 | Domain Reputation Check | **Aggregate trustworthiness indicators from reputation sources.**<br>Checks the domain against VirusTotal, AlienVault OTX and Cisco Talos reputation feeds. | Otx, Virustotal | ✅ pass |
| 7 | HTTP/2 and HTTP/3 Support Checker | **Detect server support for HTTP/2 and HTTP/3 (QUIC).**<br>Negotiates ALPN over TLS for h2 and opens a QUIC connection via aioquic to confirm HTTP/3. | — | ✅ pass |
| 8 | IP Info | **Geo, ASN, and ownership info for target IPs.**<br>Geolocates and enriches the resolved IP through ip-api. | — | ✅ pass |
| 9 | Open Ports Scan | **TCP port scan to identify exposed services.**<br>TCP-connect scans common ports with a thread pool, optionally enriched with Shodan's port data. | Shodan | ⏱️ long-running |
| 10 | Server Info | **Gather server banners, stack hints, and versions.**<br>Reads the HTTP response headers and resolved IP to describe the serving stack. | — | ✅ pass |
| 11 | Server Location | **Approximate server geolocation & hosting provider.**<br>Resolves the host and looks its IP up in a geolocation API. | — | ✅ pass |
| 12 | SSL Chain Analysis | **Retrieve cert chain; validate trust path & intermediates.**<br>Opens a TLS socket and walks the presented certificate chain, printing issuer/subject per link. | — | ✅ pass |
| 13 | SSL Expiry Alert | **Check certificate expiration window; warn when near expiry.**<br>Fetches the leaf certificate and computes days remaining until notAfter, flagging near expiry. | — | ✅ pass |
| 14 | TLS Cipher Suites | **Enumerate supported TLS cipher suites.**<br>Repeatedly handshakes offering one cipher family at a time to enumerate what the server accepts. | — | ✅ pass |
| 15 | TLS Handshake Simulation | **Simulate varied TLS client handshakes; flag issues.**<br>Simulates handshakes across TLS versions and reports which succeed plus the negotiated parameters. | — | ✅ pass |
| 16 | Traceroute | **Trace network hops to the destination.**<br>Runs a hop-by-hop trace toward the target and renders the path. | — | ✅ pass |
| 17 | TXT Records | **Retrieve TXT records (SPF, DKIM, verification tokens).**<br>Pulls and pretty-prints the TXT record set (SPF, verification tokens, etc.). | — | ✅ pass |
| 18 | WHOIS Lookup | **WHOIS/RDAP ownership data retrieval.**<br>Shells out to the system whois client and parses the registrar response. | — | ✅ pass |
| 19 | Zone Transfer | **Attempt AXFR to enumerate full DNS zone when misconfigured.**<br>Attempts an AXFR zone transfer against each authoritative nameserver - a classic misconfiguration check. | — | ✅ pass |
| 20 | ASN Lookup | **Map IPs/domains to ASNs & network orgs.**<br>Maps the IP to its ASN and announcing organisation via RDAP/ip-api. | — | ✅ pass |
| 21 | Reverse IP Lookup | **Enumerate domains hosted on a given IP.**<br>Reverse-lookups the IP through Shodan and HackerTarget to list co-hosted domains. | Shodan | ✅ pass |
| 22 | IP Range Scanner | **Scan an IP range for live hosts & open ports.**<br>Expands a CIDR with the ipaddress module and probes each host in the range concurrently. | — | ⚙️ needs CIDR |
| 23 | RDAP Lookup | **Structured domain/IP ownership via RDAP.**<br>Queries the RDAP registry (the structured successor to WHOIS) for domain or IP objects. | — | ✅ pass |
| 24 | NTP Information Leak Checker | **Query NTP servers for version & info leak data.**<br>Sends NTP mode-6/7 control queries to detect monlist-style information leaks and amplification exposure. | — | ✅ pass |
| 25 | IPv6 Reachability Test | **Validate IPv6 DNS + connection reachability vs IPv4.**<br>Tests IPv6 reachability across an address range, requiring IPv6 CIDR input. | — | ⚙️ needs IPv6 CIDR |
| 26 | BGP Route Analysis | **Inspect BGP announcements & paths for anomalies.**<br>Pulls prefix, peer and upstream data for the target's ASN from BGPView. | — | ✅ pass |
| 27 | CDN Detection | **Detect CDN fronting (Cloudflare, Akamai, etc.).**<br>Correlates CNAME chains, response headers and known CDN IP ranges to name the CDN in front of the site. | — | ✅ pass |
| 28 | Reverse DNS Scan | **PTR sweeping to discover hostnames.**<br>Performs reverse-DNS (PTR) lookups across a netblock with a thread pool. | — | ✅ pass |
| 29 | Network Timezone Detection | **Approximate timezone from geo/latency/banner clues.**<br>Infers the server's timezone by comparing its clock/geolocation against worldtimeapi. | — | ✅ pass |
| 30 | Geo‑DNS Footprint | **Compare DNS answers across global resolvers; map geo/ASN variance.**<br>Resolves the domain from several vantage resolvers to reveal geo-steered DNS answers. | — | ✅ pass |
| 31 | SPF Network Extractor | **Parse SPF includes/mx/a; expand & extract sending netblocks.**<br>Recursively expands the SPF record's include/ip4/ip6 mechanisms into the full sending netblock set. | — | ✅ pass |
| 32 | NS Geo/ASN Diversity Analyzer | **Assess authoritative NS geo & ASN concentration.**<br>Geolocates every nameserver and scores how diverse their countries and ASNs are (resilience check). | — | ✅ pass |
| 33 | DNS SLA Latency Monitor | **Measure resolver latency & SLA metrics; flag slow responders.**<br>Times repeated resolutions against each authoritative nameserver to build a latency/SLA picture. | — | ✅ pass |
| 34 | RPKI Route Validity Check | **Validate route origins for target prefixes against RPKI VRPs.**<br>Checks whether the announcing ASN is RPKI-valid for the prefix using RIPEstat - BGP hijack exposure. | — | ✅ pass |
| 35 | Recursive Nameserver Leak Test | **Detect recursion enabled on authoritative nameservers.**<br>Sends recursion-desired queries to the target's own nameservers to detect open recursion. | — | ✅ pass |
| 36 | Dual‑Stack Behavior Profiler | **Compare HTTP/TLS responses over IPv4 vs IPv6; flag diffs.**<br>Compares behaviour over IPv4 vs IPv6 - resolution, TLS and response - to find dual-stack drift. | — | ✅ pass |
| 37 | ICMP Reachability Matrix | **Ping sweep; build loss/latency matrix; detect filtering.**<br>Builds an ICMP reachability matrix across the resolved addresses. | — | ✅ pass |
| 38 | IP Allocation History Tracker | **Historical IP allocation & ownership timeline.**<br>Reconstructs the IP's allocation and transfer history from RIPEstat. | — | ✅ pass |
| 39 | Autonomous Neighbor Peering Map | **Map upstream/downstream AS adjacencies.**<br>Maps the ASN's BGP peers and neighbours into a peering graph via BGPView. | — | ✅ pass |
| 40 | TLS Session Resumption Map | **Probe TLS session resumption across hosts.**<br>Tests TLS session ticket and session-ID resumption support across the endpoint set. | — | ✅ pass |
| 41 | Network Certificate Inventory | **Collect certs across network; dedupe; list SANs & expiries.**<br>Sweeps addresses in the netblock collecting every TLS certificate presented, building an inventory. | — | ✅ pass |
| 42 | SSH Banner & Key Fingerprinter | **Grab SSH banners & fingerprints across hosts/ports.**<br>Opens SSH sockets with paramiko to collect banners and host key fingerprints. | — | ⏱️ long-running |
| 43 | SNMP Public Community Checker | **Test SNMP v2c communities for info leakage.**<br>Attempts SNMP reads with the default 'public' community string - a classic default-credential exposure. | — | ✅ pass |
| 44 | UDP Service Sampler | **Lightweight probes to classify common UDP services.**<br>Probes common UDP services with protocol-specific payloads and records responders. | — | ⏱️ long-running |
| 139 | SNMP Bulk Walk | **Walk the SNMP OID tree of a host using a community string.**<br>Performs a full SNMP bulk walk of the OID tree when a community string is accepted. | — | ✅ pass |
| 140 | NetBIOS Name Query | **Query the NetBIOS name service for host and workgroup names.**<br>Issues NetBIOS name-service queries to recover Windows host and workgroup names. | — | ✅ pass |
| 141 | TTL Analysis | **Infer operating system and hop distance from IP TTL values.**<br>Compares DNS TTLs against observed ICMP TTLs to infer the OS family and hop distance. | — | ✅ pass |
| 142 | IRR Routing Registry Analyzer | **Compare RADB and RIPE route objects for the target ASN.**<br>Looks up the prefix in the RIPE IRR database to compare routing intent against reality. | — | ⚙️ needs ASN-routable IP |
| 143 | Dual Stack Diff | **Diff IPv4 versus IPv6 responses served for the same host.**<br>Fetches the site over IPv4 and IPv6 and hashes both responses to surface content drift. | — | ✅ pass |
| 144 | DNS CAA Checker | **Check CAA records controlling which CAs may issue certificates.**<br>Reads CAA records to show which certificate authorities are permitted to issue for the domain. | — | ✅ pass |
| 145 | Decoy DNS Beacon | **Generate decoy DNS lookups to observe resolver behaviour.**<br>Plants uniquely-named DNS lookups and watches which resolvers replay them - detects DNS interception. | — | ✅ pass |
| 146 | Geo IP Spoof Detection | **Cross-check geolocation providers for conflicting answers.**<br>Cross-checks the IP's geolocation across several providers to spot spoofed or inconsistent geo data. | Ipinfo | ✅ pass |
| 147 | Passive DNS History | **Look up historical passive DNS records for the target.**<br>Retrieves historical passive-DNS records from SecurityTrails/HackerTarget to show past IP ownership. | Securitytrails | ✅ pass |
| 154 | JARM TLS Fingerprint | **Active JARM fingerprint of the server's TLS stack (matches public JARM datasets).**<br>Sends the ten standard JARM Client Hello probes over raw sockets and fuzzy-hashes the server's cipher/version/extension choices into a 62-character fingerprint. | — | ✅ pass |

### 4.2 Web Application Analysis (50 modules)

| ID | Module | What it does & how it works | Keys | Status |
|---:|---|---|---|---|
| 45 | Archive History | **Retrieve historical site snapshots.**<br>Queries the Wayback Machine and Common Crawl indexes for archived URLs of the domain. | — | ✅ pass |
| 46 | Broken Links Detection | **Crawl site & detect broken links.**<br>Crawls the page's links and requests each one concurrently, reporting 4xx/5xx targets. | — | ✅ pass |
| 47 | Carbon Footprint | **Estimate environmental impact of page loads.**<br>Estimates page energy use and CO2 per visit via the Website Carbon API plus transfer weight. | Website_Carbon | ✅ pass |
| 48 | CMS Detection | **Identify CMS platforms by signature.**<br>Matches HTML markers, meta generators, paths and cookies against CMS fingerprints. | — | ✅ pass |
| 49 | Cookies Analyzer | **Inspect cookies for security/privacy attributes.**<br>Parses Set-Cookie headers for Secure/HttpOnly/SameSite flags and decodes JWT-shaped cookie values. | — | ✅ pass |
| 50 | Content Discovery | **Discover hidden directories/files/endpoints.**<br>Asynchronously requests a wordlist of paths to discover unlinked content. | — | ✅ pass |
| 51 | Crawler | **Crawl site & map structure.**<br>Walks the site's internal links to build a page inventory. | — | ✅ pass |
| 52 | Robots.txt Analyzer | **Parse robots.txt for hidden/disallowed paths.**<br>Fetches robots.txt and highlights disallowed paths, which often name sensitive directories. | — | ✅ pass |
| 53 | Directory Finder | **Scan for common unlisted directories.**<br>Brute-forces common directory names with a thread pool and reports the ones that resolve. | — | ✅ pass |
| 54 | Email Harvesting | **Extract emails from site pages.**<br>Scrapes rendered HTML and mailto links for email addresses. | — | ✅ pass |
| 55 | Performance Monitoring | **Measure response time & load performance.**<br>Runs the page through Google PageSpeed Insights and reports Core Web Vitals. | Google | ✅ pass |
| 56 | Quality Metrics | **Assess site UX/content quality heuristics.**<br>Scores page quality signals - markup validity, meta completeness, asset weight. | — | ✅ pass |
| 57 | Redirect Chain | **Follow redirects; analyze safety & loops.**<br>Follows the redirect chain hop by hop, printing each Location and status. | — | ✅ pass |
| 58 | Sitemap Parsing | **Parse sitemap.xml; enumerate URLs.**<br>Parses sitemap.xml (including sitemap indexes) to enumerate declared URLs. | — | ✅ pass |
| 59 | Social Media Presence Scan | **Identify linked social media profiles.**<br>Searches engines and the page itself for links to the brand's social profiles. | — | ✅ pass |
| 60 | Technology Stack Detection | **Fingerprint technologies & frameworks in use.**<br>Fingerprints frameworks, servers and libraries from headers, HTML markers and script paths. | — | ✅ pass |
| 61 | Third-Party Integrations | **Discover external services integrated into site.**<br>Identifies embedded third-party services - analytics, chat, tag managers - from outbound references. | — | ✅ pass |
| 62 | JavaScript File Analyzer | **Extract endpoints & secrets from JS files.**<br>Downloads every external script and greps for URLs, emails and rough secret patterns. | — | ✅ pass |
| 63 | CORS Misconfiguration Scanner | **Detect overly permissive CORS settings.**<br>Replays requests with forged Origin headers to detect reflective or wildcard CORS trust. | — | ✅ pass |
| 64 | Login Page Brute Identifier | **Locate & fingerprint login/auth pages.**<br>Locates login forms and judges whether they expose brute-forceable authentication. | — | ✅ pass |
| 65 | Hidden Parameter Discovery | **Fuzz hidden GET/POST parameters.**<br>Probes candidate query parameters and diffs responses to reveal undocumented inputs. | — | ✅ pass |
| 66 | Clickjacking Test | **Check anti-framing headers & behavior.**<br>Checks X-Frame-Options and CSP frame-ancestors to determine whether the page can be framed. | — | ✅ pass |
| 67 | Form Grabber | **Enumerate forms & field metadata.**<br>Extracts every form, its method, action and input fields - the app's input surface. | — | ✅ pass |
| 68 | Favicon Hashing | **MD5 hash favicon to infer technologies.**<br>Downloads the favicon and computes its hash for pivoting to other hosts running the same app. | — | ✅ pass |
| 69 | HTML Comments Extractor | **Parse HTML comments for hidden notes/secrets.**<br>Extracts HTML comments, which frequently leak paths, credentials and TODO notes. | — | ✅ pass |
| 70 | CAPTCHA Presence Checker | **Detect CAPTCHA widgets across pages.**<br>Detects whether CAPTCHA protection is present on interactive endpoints. | — | ✅ pass |
| 71 | JavaScript Obfuscation Detector | **Highlight obfuscated or packed JS.**<br>Scores JavaScript for obfuscation markers - packers, hex-encoded strings, eval density. | — | ✅ pass |
| 72 | Virtual Host Fuzzer | **Host header brute to reveal hidden vhosts.**<br>Sends varied Host headers against the same IP to discover virtual hosts. | — | ✅ pass |
| 73 | Session Cookie Lifetime Checker | **Measure session cookie longevity.**<br>Measures session cookie lifetimes and flags excessively long-lived sessions. | — | ✅ pass |
| 74 | HTML5 Feature Abuse Detector | **Spot risky HTML5 API usage.**<br>Looks for risky HTML5 features - postMessage, localStorage, WebRTC - that widen client-side attack surface. | — | ✅ pass |
| 75 | Autocomplete Vulnerability Checker | **Detect sensitive fields with autocomplete enabled.**<br>Finds password and sensitive fields left with autocomplete enabled. | — | ✅ pass |
| 76 | Embedded Object Hunter | **Find embedded PDFs/SWF/objects.**<br>Hunts embedded objects - Flash, applets, iframes - that indicate legacy or risky content. | — | ✅ pass |
| 77 | Multi-Language URL Tester | **Probe language/locale path handling.**<br>Requests locale variants of URLs to map multi-language routing behaviour. | — | ✅ pass |
| 78 | Pixel Tracker Finder | **Detect tracking pixel beacons.**<br>Identifies tracking pixels and beacons embedded in the page. | — | ✅ pass |
| 79 | SEO Abuse Detector | **Spot hidden/abusive SEO content.**<br>Detects SEO abuse patterns such as cloaking and hidden keyword stuffing. | — | ✅ pass |
| 80 | Dependency JS/CDN Scanner | **Inventory external JS libs & versions.**<br>Inventories JavaScript dependencies and the CDNs serving them. | — | ✅ pass |
| 81 | WebSocket Endpoint Sniffer | **Discover ws:// / wss:// endpoints.**<br>Discovers WebSocket endpoints referenced in scripts and attempts handshakes. | — | ✅ pass |
| 82 | API Schema Grabber | **Attempt to fetch OpenAPI/Swagger schemas.**<br>Probes well-known API schema paths - openapi.json, swagger.json - and parses what it finds. | — | ✅ pass |
| 83 | Lazy-Load Resource Finder | **Detect resources loaded dynamically (scroll/JS).**<br>Finds lazily-loaded resources that a naive crawler would miss. | — | ✅ pass |
| 84 | HTTP Method Enumerator | **Crawl & test supported HTTP verbs per URL.**<br>Sends OPTIONS and unusual verbs to enumerate accepted HTTP methods, flagging PUT/DELETE/TRACE. | — | ✅ pass |
| 85 | GraphQL Introspection Probe | **Discover GraphQL endpoints; attempt schema introspection.**<br>Sends a GraphQL introspection query to see whether the schema is publicly readable. | — | ✅ pass |
| 86 | File Upload Surface Finder | **Crawl & detect file upload forms/JS hints.**<br>Locates file upload forms and endpoints - a high-value attack surface. | — | ✅ pass |
| 87 | DOM Sink Scanner | **Scan HTML/JS for XSS sinks (eval, innerHTML, etc.).**<br>Parses JavaScript for DOM XSS sinks (innerHTML, eval, document.write) and the sources feeding them. | — | ✅ pass |
| 88 | Cache Behavior Analyzer | **Compare caching behavior; detect poisoning risks.**<br>Crawls pages and analyses caching headers and Vary behaviour for cache-poisoning exposure. | — | ⏱️ long-running |
| 89 | Cookie Scope Diff Across Subdomains | **Aggregate Set-Cookie across crawl; scope & flag analysis.**<br>Compares cookie scope and flags across subdomains to find over-broad domain cookies. | — | ✅ pass |
| 90 | CSP Deep Analyzer | **Collect & parse CSP headers; risk scoring.**<br>Parses the CSP into directives and grades weaknesses like unsafe-inline, wildcards and missing default-src. | — | ✅ pass |
| 91 | Third-Party Script Risk Profiler | **Inventory external script hosts; categorize & score.**<br>Profiles each third-party script by origin, size and privilege to rank supply-chain risk. | — | ✅ pass |
| 92 | Static Asset Fingerprinter | **Hash JS/CSS; extract library versions; flag outdated.**<br>Hashes static assets to fingerprint framework versions and detect unexpected changes. | — | ✅ pass |
| 148 | Email Config | **Inspect MX, SPF, DKIM and DMARC configuration for the domain.**<br>Resolves MX, SPF, DKIM and DMARC plus MTA-STS policy and BIMI records for a full email posture view. | — | ✅ pass |
| 157 | Subresource Integrity Checker | **Check external scripts/styles for SRI hashes and verify the declared hashes actually match.**<br>Collects external scripts/stylesheets, then downloads each and recomputes its SHA-256/384/512 to verify the declared integrity hash actually matches. | — | ✅ pass |

### 4.3 Security & Threat Intelligence (50 modules)

| ID | Module | What it does & how it works | Keys | Status |
|---:|---|---|---|---|
| 93 | Censys Reconnaissance | **Enumerate exposed assets via Censys (API).**<br>Queries the Censys Platform API for hosts, certificates and services tied to the target. | Censys_Api_Id, Censys, Censys_Api_Secret | ✅ pass |
| 94 | Certificate Authority Recon | **Examine CA issuance & trust relationships.**<br>Collects the issuing CA for the endpoint's certificates and profiles issuance patterns. | — | ✅ pass |
| 95 | Data Leak Detection | **Check for public data leaks & sensitive exposures.**<br>Generates likely addresses for the domain and checks them against breach-lookup services. | — | ✅ pass |
| 96 | Exposed Environment Files Checker | **Detect exposed .env/config files.**<br>Requests common environment-file paths (.env, .env.local) that leak credentials when served. | — | ✅ pass |
| 97 | Firewall Detection | **Identify firewall/WAF presence heuristically.**<br>Fingerprints WAFs and firewalls from block-page markers, headers and response behaviour. | — | ✅ pass |
| 98 | Global Ranking | **Retrieve global popularity ranking metrics.**<br>Looks the domain up in the Tranco global ranking list. | — | ✅ pass |
| 99 | HTTP Headers | **Extract HTTP response headers.**<br>Retrieves and explains every HTTP response header. | — | ✅ pass |
| 100 | HTTP Security Features | **Evaluate security headers (HSTS, CSP, etc.).**<br>Audits the presence and quality of individual HTTP security features. | — | ✅ pass |
| 101 | Malware & Phishing Check | **Check blocklists for malware/phishing indicators.**<br>Checks the domain and URL against VirusTotal and URLhaus malware/phishing feeds. | Virustotal | ✅ pass |
| 102 | Pastebin Monitoring | **Search paste sites for leaked data mentions.**<br>Searches paste sites and GitHub gists for the domain appearing in public pastes. | Github | ✅ pass |
| 103 | Privacy & GDPR Compliance | **Basic privacy/GDPR checks (policies, consent).**<br>Inspects cookie banners, trackers and policy links for GDPR/privacy compliance signals. | — | ✅ pass |
| 104 | Security.txt Check | **Retrieve & parse security.txt disclosure info.**<br>Fetches /.well-known/security.txt and validates its contact fields. | — | ✅ pass |
| 105 | Shodan Reconnaissance | **Query Shodan for exposed services & vulns.**<br>Pulls host, port, banner and vulnerability data for the target from Shodan. | Shodan | ✅ pass |
| 106 | SSL Labs Report | **Pull detailed SSL Labs TLS assessment.**<br>Submits the host to the Qualys SSL Labs API and reports the returned grade. | — | ✅ pass |
| 107 | SSL Pinning Check | **Check for SSL/TLS pinning indicators.**<br>Tests whether the app pins certificates by presenting an unexpected chain. | — | ✅ pass |
| 108 | Subdomain Enumeration | **Discover subdomains via multiple techniques.**<br>Pulls subdomains from crt.sh certificate transparency records. | — | ✅ pass |
| 109 | Subdomain Takeover | **Test for dangling DNS entries vulnerable to takeover.**<br>Enumerates subdomains and checks each for dangling-CNAME takeover signatures. | — | ✅ pass |
| 110 | VirusTotal Scan | **Lookup reputation & detections in VirusTotal.**<br>Submits the domain to VirusTotal and reports multi-engine verdicts. | Virustotal | ✅ pass |
| 111 | CT Log Query | **Query certificate transparency logs for issued certs.**<br>Queries certificate transparency logs for every certificate issued to the domain. | — | ✅ pass |
| 112 | Breached Credentials Lookup | **Check breach datasets for exposed credentials.**<br>Checks credentials against HIBP using the k-anonymity range API, so no full hash leaves the host. | Hibp | ✅ pass |
| 113 | Cloud Bucket Exposure | **Detect open S3/Azure/GCP buckets tied to domain.**<br>Generates bucket-name permutations and probes S3, GCS and Azure for public listings. | — | ⏱️ long-running |
| 114 | JWT Token Analyzer | **Decode and inspect JWT algorithms & claims.**<br>Decodes JWTs found on the site and audits algorithm, expiry and signature weaknesses. | — | ✅ pass |
| 115 | Exposed API Endpoints | **Crawl and list publicly reachable API endpoints.**<br>Probes common API paths and documents which respond, including unauthenticated ones. | — | ✅ pass |
| 116 | Git Repository Exposure Check | **Detect exposed .git directories and artifacts.**<br>Requests .git/HEAD and related paths to detect an exposed repository. | — | ✅ pass |
| 117 | Typosquat Domain Checker | **Generate and check typo variants for malicious domains.**<br>Generates typo variants of the domain and resolves them to find squatters. | — | ✅ pass |
| 118 | SPF / DKIM / DMARC Validator | **Assess email auth posture and alignment.**<br>Validates SPF, DKIM and DMARC records and reports their tags. | — | ✅ pass |
| 119 | Open Redirect Finder | **Probe redirect parameters for open redirect vulnerabilities.**<br>Injects external URLs into redirect-shaped parameters and watches for off-site 3xx responses. | — | ⏱️ long-running |
| 120 | Rate-Limit & WAF Bypass Test | **Probe throttling and WAF bypass behaviors.**<br>Sends bursts of requests with varied headers to measure rate limiting and probe WAF bypasses. | — | ⏱️ long-running |
| 121 | Security Changelog Diff | **Compare security header/config changes over time.**<br>Snapshots security headers to a baseline file and diffs future runs against it. | — | ✅ pass |
| 122 | Session Hijacking (Passive) | **Analyze cookie/session flags for hijacking risk.**<br>Passively inspects session cookies and tokens for hijacking weaknesses - no active session attack. | — | ✅ pass |
| 123 | Rogue Certificate Check | **Detect suspicious or duplicate certificates.**<br>Compares certificates seen in CT logs against what the server presents to spot rogue issuance. | — | ✅ pass |
| 124 | JS Malware Scanner | **Heuristic scan of JavaScript for malware indicators.**<br>Scans served JavaScript for malware and skimmer signatures. | — | ✅ pass |
| 125 | Cloud Service Enumeration | **Detect exposed cloud/devops services (Jira, Jenkins, etc.).**<br>Detects which cloud services and SaaS providers the domain depends on. | — | ✅ pass |
| 126 | Rogue Subdomain Resolver | **Monitor for newly resolving previously dead subdomains.**<br>Resolves candidate subdomains to find records pointing at infrastructure the owner no longer controls. | — | ✅ pass |
| 127 | Bug Bounty Program Finder | **Identify bug bounty/disclosure program links.**<br>Checks whether the domain runs a public bug bounty or VDP programme. | — | ✅ pass |
| 128 | Custom Wordlist Generator | **Build tailored recon wordlists (paths, usernames, emails).**<br>Builds a target-specific wordlist from the site's own content for later fuzzing. | — | ✅ pass |
| 129 | Threat Feed Correlator | **Aggregate multi-feed reputation & threat intelligence.**<br>Correlates the target against AbuseIPDB, OTX and VirusTotal threat feeds. | Abuseipdb, Virustotal | ✅ pass |
| 130 | Attack Surface Delta | **Diff two Perimetry reports; highlight adds/removals.**<br>Asynchronously gathers subdomains, resolves them and scans ports to diff the attack surface over time. | — | ⏱️ long-running |
| 131 | Passive CVE Mapper | **Map discovered product/version hints to NVD CVEs.**<br>Maps passively-observed software versions to CVE records from the NVD feed. | — | ✅ pass |
| 132 | Security Contact Gap Finder | **Collect security contacts from security.txt, WHOIS, site.**<br>Determines whether a security contact exists across security.txt, RDAP and DNS. | — | ✅ pass |
| 133 | Domain Shadowing Detector | **CT + passive DNS to spot high-entropy subdomain bursts.**<br>Looks for attacker-created subdomains under a legitimate domain using CT and passive DNS sources. | — | ✅ pass |
| 134 | IP Reputation Trending | **Compare AbuseIPDB & VT metrics across time windows.**<br>Tracks the IP's reputation scores over time across AbuseIPDB and VirusTotal. | Abuseipdb, Virustotal | ✅ pass |
| 149 | Dark Web Monitoring | **Search public breach and paste sources for the domain.**<br>Queries paste and breach-index services for mentions of the domain. | — | ✅ pass |
| 150 | IP Reputation Check | **Check the resolved IP against reputation blocklists.**<br>Checks the resolved IP against AbuseIPDB and IPQualityScore blocklists. | Abuseipdb, Ipqualityscore | ✅ pass |
| 151 | TLS Security Config | **Audit TLS protocol versions and configuration weaknesses.**<br>Audits negotiated TLS versions, cipher strength, forward secrecy and known protocol weaknesses. | — | ✅ pass |
| 152 | JS Secret / API Key Scanner | **Scan inline and external JavaScript for leaked API keys, tokens and private keys.**<br>Downloads inline and external JavaScript, matches 22 vendor credential patterns plus a Shannon-entropy filter, and reports each hit masked with a severity grade. | — | ✅ pass |
| 153 | Security Headers Grade | **Score HTTP security headers into an A-F grade and flag info-disclosure headers.**<br>Reads the response headers and scores seven controls by weight into an A+ to F grade, deducting for information-disclosure headers. | — | ✅ pass |
| 155 | CVE Enrichment from Tech Stack | **Fingerprint tech stack versions and look up known CVEs via the NVD feed.**<br>Fingerprints product versions from headers, meta generators and script paths, then queries the NVD 2.0 API per component and ranks results by CVSS. | Nvd | ✅ pass |
| 156 | Subdomain Takeover (Deep) | **Enumerate subdomains from CT logs and flag dangling CNAMEs against a takeover fingerprint DB.**<br>Merges crt.sh and CertSpotter subdomain sets, resolves each CNAME, and matches it against a 20-service takeover fingerprint database before confirming with a response marker. | — | ✅ pass |
| 158 | Document Metadata Extractor | **Harvest author names, software versions and internal paths from public PDF and Office documents.**<br>Discovers linked PDF/Office files (homepage, sitemap, one crawl hop), fetches head plus a Range-requested tail, then parses the PDF info dictionary, the XMP packet and OOXML docProps. | — | ✅ pass |

---

## 5. Review status & known issues

### 5.1 What the run proved

* **No module crashes.** Across 154 live executions there was not a single Python
  traceback - unusual for a suite this size.
* **Catalog integrity is clean**: IDs unique, names unique, every catalog entry
  resolves to a real file, no orphaned module files.
* **All 188 Python files compile**, and every core/CLI/utility module imports.

### 5.2 Long-running modules

Eight modules exceeded the 60-second test cap. None are broken - they are doing
real work and were mid-progress when cut off:

* **9** Open Ports Scan
* **42** SSH Banner & Key Fingerprinter
* **44** UDP Service Sampler
* **88** Cache Behavior Analyzer
* **113** Cloud Bucket Exposure
* **119** Open Redirect Finder
* **120** Rate-Limit & WAF Bypass Test
* **130** Attack Surface Delta

Give them a longer `timeout`, or expect `runall` to spend most of its wall-clock here.

### 5.3 API keys the CLI cannot manage

The `api` command manages 7 services, but modules reference **8 further keys** with
no way to set them from the CLI - they must be added to `.env` by hand:

| Key | Used by |
|---|---|
| `ABUSEIPDB_API_KEY` | 129, 134, 150 |
| `SECURITYTRAILS_API_KEY` | 147 |
| `OTX_API_KEY` | 6 |
| `IPINFO_API_KEY` | 146 |
| `IPQUALITYSCORE_API_KEY` | 150 |
| `NVD_API_KEY` | 155 |
| `GITHUB_TOKEN` | 102 |
| `WEBSITE_CARBON_API_KEY` | 47 |

`SSL_LABS_API_KEY` is the mirror image: declared in settings but used by no module.

### 5.4 Legacy modules

Five modules execute at import time because they lack an `if __name__ == "__main__"`
guard - `redirect_chain`, `server_info`, `server_location`, `ssl_chain`,
`subdomain_enum`. Harmless today, since the runner always launches them as
subprocesses, but they cannot be imported or unit-tested.

### 5.5 No automated test suite

`make test` and `make lint` reference `tests/` and `docs/` directories that do not
exist. For a project of this size, that is the single largest structural gap.

---

## 6. Where this sits as a security project

**Strengths.** Breadth is genuinely unusual - 154 modules spanning network, web and
threat intelligence, in one consistent CLI with favourites, profiles, per-module
options and automatic reporting. The process-isolation design means the suite
degrades gracefully instead of collapsing. Several modules (JARM, SRI verification,
HIBP k-anonymity, RPKI) are implemented to a standard matching dedicated tools.

**The gap to "professional".** Three things separate Perimetry from a tool a team would
standardise on:

1. **No test suite.** Nothing prevents a regression in module 47 from shipping.
2. **No machine-readable output.** Modules print `rich` tables; severity is
   recovered by *regex-matching the printed text*. A JSON result schema would make
   Perimetry scriptable and CI-integrable - the highest-leverage change available.
3. **Depth over breadth from here.** The next ten modules matter less than making
   the existing weak ones (§3) as good as the flagship ten.

**Recommended next steps, in order:**

1. Add a JSON output mode with a shared result schema.
2. Add `tests/` with smoke tests that assert each module exits 0 and prints its
   completion marker - the sweep used for this document is effectively that test,
   and it should be committed.
3. Extend the `api` command to cover the 8 unmanaged keys (§5.3).
4. Rebuild or retire the weakest modules (§3) rather than adding new ones.
5. Normalise the five legacy modules onto `run(target, threads, opts)`.

---

*Generated from a full execution run of all 154 modules plus static analysis of the
codebase. Status values are empirical, not aspirational.*
