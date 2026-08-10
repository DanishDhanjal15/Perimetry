# What I contributed to Perimetry

**Perimetry is a fork of [Argus](https://github.com/jasonxtn/Argus) by Jason13
(MIT-licensed).** The original suite provided the CLI framework and the first
~147 reconnaissance modules. This document lists, honestly and specifically, the
work **I (Danish Dhanjal, [@DanishDhanjal15](https://github.com/DanishDhanjal15))**
added on top of that base — so my contribution can be judged on its own merits.

Everything below was verified by running it, not just by writing it. All new
modules were executed against a live target and produce the output described.

---

## New modules (7)

Each follows the project's module contract — `run(target, threads, opts)`, a
`rich` UI, and a `.txt` export under `results/<domain>/` — and was validated
end-to-end.

| ID | Module | Technique | Notable engineering |
|---:|---|---|---|
| 154 | **JARM TLS Fingerprint** | Sends the 10 standard JARM Client Hello probes over raw sockets and fuzzy-hashes the server's cipher/version/extension choices into a 62-char fingerprint. | **Byte-exact with Salesforce's reference implementation — verified identical on 6 independent hosts** (google, github, cloudflare, amazon, microsoft, example). Pure `socket`/`hashlib`, zero third-party deps. Hashes are directly lookupable in public JARM/C2 datasets. |
| 152 | **JS Secret / API Key Scanner** | Downloads inline + external JavaScript and matches 22 vendor credential patterns (AWS, Google, Stripe, GitHub, Slack, private keys, JWT…) behind a Shannon-entropy filter. | Severity grading (HIGH/MED/LOW) and value masking, so the report itself never leaks the credential it found. De-dupes generic matches against precise ones. |
| 156 | **Subdomain Takeover (Deep)** | Enumerates subdomains from CT logs, resolves each CNAME, and matches it against a 20-service takeover fingerprint database, then confirms with a response marker. | Dual CT sources (crt.sh + CertSpotter) so one provider outage doesn't blind the scan; marker confirmation suppresses false positives. |
| 155 | **CVE Enrichment from Tech Stack** | Fingerprints product versions from headers/meta/script paths, then queries the NVD 2.0 API per component and ranks results by CVSS. | Honest about being a keyword match ("verify manually"); handles NVD's unauthenticated rate limits gracefully. |
| 157 | **Subresource Integrity Checker** | Lists external scripts/stylesheets and, for each, re-downloads the asset and recomputes its SHA-256/384/512 to verify the declared `integrity` hash actually matches. | Goes beyond presence-checking — catches *stale* hashes that silently break production, and flags external resources missing SRI entirely. |
| 153 | **Security Headers Grade** | Scores seven HTTP security controls by weight into a single A+…F grade, deducting for information-disclosure headers. | One-number output (grade + %) that reads at a glance; per-control breakdown with weighted scoring. |
| 158 | **Document Metadata Extractor** | Discovers linked PDF/Office files (homepage, sitemap, one crawl hop) and parses the PDF info dictionary, the XMP packet, and OOXML docProps for author names, software versions and internal paths. | Handles both classic `/Info` dictionaries **and** modern XMP packets; uses a Range request to fetch the file tail where PDF metadata lives, so large files don't need a full download; decodes UTF-16 and escaped-paren strings correctly. |

---

## Bug fixes

- **API-key leak (security).** The `api <service> <key>` command wrote plaintext
  API keys into `perimetry/config/settings.py` — a **git-tracked** file — risking
  credentials being committed. Reworked it to write to `.env` (gitignored, and
  already read at startup), with in-place key replacement, no injection via
  special characters, and immediate effect in the running process.
  (`perimetry/cli/commands/info.py`)
- **Module crash on every invocation.** Module 95 (Data Leak Detection) always
  exited with an argparse error because its parser rejected the positional
  `threads` argument the runner passes. Fixed to accept the runner's
  `<target> <threads> [opts]` contract. (`perimetry/modules/data_leak.py`)
- **CLI crash when output is piped.** The banner raised `UnicodeEncodeError` under
  Windows cp1252 whenever stdout wasn't a UTF-8 terminal (e.g. piping to a file).
  Added a UTF-8 reconfigure at startup. (`perimetry/cli/main.py`)
- **Incorrect built-in help.** The command help advertised two commands that don't
  exist (`searchre`, `?<id>`) and documented `runall infra` when the real value
  is `infrastructure`; the README omitted `api`, `config` and `hm`. Corrected the
  in-app help and the README so documented commands actually work.
  (`perimetry/cli/commands/help.py`, `README.md`)

---

## Engineering review

- Authored `MODULES.md` — a full engineering review of all 154 modules: what each
  does, the technique it uses, and its **verified runtime status from a real
  execution run** (all 154 executed as subprocesses; zero tracebacks; the only
  non-zero exits are modules correctly rejecting the wrong input type). Includes
  a tiered assessment of which modules matter most and an honest list of the
  weakest ones.

## Rebrand

- Renamed the project from Argus to Perimetry across the codebase (package,
  entry point, banner, docs, Docker/Make/install tooling), preserving the
  original MIT license and Jason13's copyright.

---

*Original project: [Argus](https://github.com/jasonxtn/Argus) © 2025 Jasonxtn,
MIT. This fork retains that license; my additions above are contributed under the
same terms.*
