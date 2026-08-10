<h1 align="center">
  <a href="">
    <picture>
      <source height="220" media="(prefers-color-scheme: dark)" srcset="https://i.imgur.com/nGEReZh.png">
      <img height="200" alt="Perimetry" src="https://i.imgur.com/FL0dmHd.png">
    </picture>
  </a>
  <br>
</h1>
<p align="center">
   A Python-based toolkit for Information Gathering & Reconnaissance
</p>

<p align="center">
  <a href="https://github.com/DanishDhanjal15/Perimetry/actions/workflows/ci.yml"><img src="https://github.com/DanishDhanjal15/Perimetry/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/modules-154-orange" alt="Modules">
</p>

![screenshot](https://i.imgur.com/HIQWPPO.gif)
---

## About The Project

Perimetry is an all-in-one, Python-powered toolkit designed to streamline the process of information gathering and reconnaissance. It brings together a clean, intuitive interface and a wide range of reliable modules, allowing analysts to efficiently assess networks, web applications, and security environments with consistency and precision.

> **Perimetry is a fork of [Argus](https://github.com/jasonxtn/Argus) by Jason13** (MIT-licensed), which provides the CLI framework and most of the module suite. This fork — maintained by [Danish Dhanjal](https://github.com/DanishDhanjal15) — adds 7 new modules (JARM fingerprinting, JS secret scanning, deep subdomain-takeover detection, CVE enrichment, SRI verification, security-headers grading, document-metadata extraction), fixes several bugs including an API-key disclosure issue, and ships an engineering review of every module. See **[CONTRIBUTIONS.md](CONTRIBUTIONS.md)** for exactly what this fork changed, and **[MODULES.md](MODULES.md)** for the full module reference.

## ⚠️ WARNING: LEGAL DISCLAIMER

This tool is intended for **educational and ethical use only**. The author is not liable for any illegal use or misuse of this tool. Users are solely responsible for their actions and must ensure they have explicit permission to scan the target systems.

---

## 👀 Screenshots

Take a look at Perimetry in action:
<p float="left" align="middle">
  <img src="https://i.imgur.com/dAITama.png" width="49%">
  <img src="https://i.imgur.com/8VtXyEW.png" width="49%">
</p>
<p float="left" align="middle">
  <img src="https://i.imgur.com/rEIPl2h.png" width="49%">
  <img src="https://i.imgur.com/TVmc8gf.png" width="49%">
</p>
<p float="left" align="middle">
  <img src="https://i.imgur.com/1I6x3Gp.png" width="49%">
  <img src="https://i.imgur.com/9EZqNvK.png" width="49%">
</p>
<p float="left" align="middle">
  <img src="https://i.imgur.com/U4fdPSI.png" width="49%">
  <img src="https://i.imgur.com/LnmykFJ.png" width="49%">
</p>

---

## ⚙️ Installation

### Quick Start

#### Option 1: No Installation (Run Directly)
```bash
git clone https://github.com/DanishDhanjal15/perimetry.git
cd perimetry
pip install -r requirements.txt
python -m perimetry
```

#### Option 2: Using pip
```bash
pip install perimetry
perimetry
```

#### Option 3: Full Installation
```bash
git clone https://github.com/DanishDhanjal15/perimetry.git
cd perimetry
chmod +x install.sh && ./install.sh
python -m perimetry
```

#### Option 4: Docker
```bash
git clone https://github.com/DanishDhanjal15/perimetry.git
cd perimetry
docker build -t perimetry:latest .
docker run -it --rm -v $(pwd)/results:/app/results perimetry:latest
```

---

## 📖 Usage

### Getting Started

1. **Launch Perimetry**:
   ```bash
   perimetry

   # if running from folder: python -m perimetry
   ```

2. **Browse available modules**:
   ```
   perimetry> modules
   ```

3. **Select a module**:
   ```
   perimetry> use 1
   ```

4. **Set target and options**:
   ```
   perimetry> set target example.com
   perimetry> set threads 10
   ```

5. **Run the module**:
   ```
   perimetry> run
   ```

### Commands Cheatsheet

| Command | Category | Description | Example |
|---------|----------|-------------|---------|
| `modules` | Discovery | List all modules | `modules` |
| `modules -d` | Discovery | List with details | `modules -d` |
| `search` | Discovery | Search by keyword | `search ssl` |
| `search --regex` | Discovery | Regex search | `search '(?i)dns.*brute' --regex` |
| `use` | Selection | Select module | `use 42` |
| `helpmod` | Help | Module help | `helpmod 42` |
| `hm` | Help | Alias for `helpmod` | `hm 42` |
| `set target` | Config | Set target | `set target example.com` |
| `set` | Config | Set options | `set threads 20` |
| `unset` | Config | Unset options | `unset target` |
| `opts` | Config | Show options | `opts` |
| `scope` | Config | Show config | `scope` |
| `profile` | Config | Apply profile | `profile speed` |
| `run` | Execute | Run selected | `run` |
| `run --dry-run` | Execute | Preview without running | `run 3 17 --dry-run` |
| `runall` | Execute | Run category | `runall infrastructure` |
| `runfav` | Execute | Run favorites | `runfav` |
| `last` | Execute | Re-run last | `last` |
| `fav` | Favorites | Manage favorites | `fav add 42` |
| `show modules` | Info | Browse modules | `show modules` |
| `show api_status` | Info | Check APIs | `show api_status` |
| `show options` | Info | Show options | `show options` |
| `show options_full` | Info | Detailed options | `show options_full` |
| `info` | Info | Project info | `info` |
| `recent` | Info | Recent modules | `recent` |
| `viewout` | Output | View cached output | `viewout` |
| `grepout` | Output | Search output | `grepout "192.168"` |
| `api` | Config | Show API status / save a key to `.env` | `api shodan <key>` |
| `config` | Utility | Open settings file | `config` |
| `clear` | Utility | Clear screen | `clear` |
| `banner` | Utility | Show banner | `banner` |
| `reset` | Utility | Reset config | `reset` |
| `exit` | Utility | Exit Perimetry | `exit` |
| `quit` | Utility | Exit Perimetry | `quit` |
| `help` | Help | Show help | `help` |



### 📋 **All Modules** *(the number in each cell is the module ID you pass to `use`)* — 154 total

| Network & Infrastructure | Web Application Analysis | Security & Threat Intelligence |
|---|---|---|
| 1. Associated Hosts | 45. Archive History | 93. Censys Reconnaissance |
| 2. DNS Over HTTPS | 46. Broken Links Detection | 94. Certificate Authority Recon |
| 3. DNS Records | 47. Carbon Footprint | 95. Data Leak Detection |
| 4. DNSSEC Check | 48. CMS Detection | 96. Exposed Environment Files Checker |
| 5. Domain Info | 49. Cookies Analyzer | 97. Firewall Detection |
| 6. Domain Reputation Check | 50. Content Discovery | 98. Global Ranking |
| 7. HTTP/2 and HTTP/3 Support Checker | 51. Crawler | 99. HTTP Headers |
| 8. IP Info | 52. Robots.txt Analyzer | 100. HTTP Security Features |
| 9. Open Ports Scan | 53. Directory Finder | 101. Malware & Phishing Check |
| 10. Server Info | 54. Email Harvesting | 102. Pastebin Monitoring |
| 11. Server Location | 55. Performance Monitoring | 103. Privacy & GDPR Compliance |
| 12. SSL Chain Analysis | 56. Quality Metrics | 104. Security.txt Check |
| 13. SSL Expiry Alert | 57. Redirect Chain | 105. Shodan Reconnaissance |
| 14. TLS Cipher Suites | 58. Sitemap Parsing | 106. SSL Labs Report |
| 15. TLS Handshake Simulation | 59. Social Media Presence Scan | 107. SSL Pinning Check |
| 16. Traceroute | 60. Technology Stack Detection | 108. Subdomain Enumeration |
| 17. TXT Records | 61. Third-Party Integrations | 109. Subdomain Takeover |
| 18. WHOIS Lookup | 62. JavaScript File Analyzer | 110. VirusTotal Scan |
| 19. Zone Transfer | 63. CORS Misconfiguration Scanner | 111. CT Log Query |
| 20. ASN Lookup | 64. Login Page Brute Identifier | 112. Breached Credentials Lookup |
| 21. Reverse IP Lookup | 65. Hidden Parameter Discovery | 113. Cloud Bucket Exposure |
| 22. IP Range Scanner | 66. Clickjacking Test | 114. JWT Token Analyzer |
| 23. RDAP Lookup | 67. Form Grabber | 115. Exposed API Endpoints |
| 24. NTP Information Leak Checker | 68. Favicon Hashing | 116. Git Repository Exposure Check |
| 25. IPv6 Reachability Test | 69. HTML Comments Extractor | 117. Typosquat Domain Checker |
| 26. BGP Route Analysis | 70. CAPTCHA Presence Checker | 118. SPF / DKIM / DMARC Validator |
| 27. CDN Detection | 71. JavaScript Obfuscation Detector | 119. Open Redirect Finder |
| 28. Reverse DNS Scan | 72. Virtual Host Fuzzer | 120. Rate-Limit & WAF Bypass Test |
| 29. Network Timezone Detection | 73. Session Cookie Lifetime Checker | 121. Security Changelog Diff |
| 30. Geo‑DNS Footprint | 74. HTML5 Feature Abuse Detector | 122. Session Hijacking (Passive) |
| 31. SPF Network Extractor | 75. Autocomplete Vulnerability Checker | 123. Rogue Certificate Check |
| 32. NS Geo/ASN Diversity Analyzer | 76. Embedded Object Hunter | 124. JS Malware Scanner |
| 33. DNS SLA Latency Monitor | 77. Multi-Language URL Tester | 125. Cloud Service Enumeration |
| 34. RPKI Route Validity Check | 78. Pixel Tracker Finder | 126. Rogue Subdomain Resolver |
| 35. Recursive Nameserver Leak Test | 79. SEO Abuse Detector | 127. Bug Bounty Program Finder |
| 36. Dual‑Stack Behavior Profiler | 80. Dependency JS/CDN Scanner | 128. Custom Wordlist Generator |
| 37. ICMP Reachability Matrix | 81. WebSocket Endpoint Sniffer | 129. Threat Feed Correlator |
| 38. IP Allocation History Tracker | 82. API Schema Grabber | 130. Attack Surface Delta |
| 39. Autonomous Neighbor Peering Map | 83. Lazy-Load Resource Finder | 131. Passive CVE Mapper |
| 40. TLS Session Resumption Map | 84. HTTP Method Enumerator | 132. Security Contact Gap Finder |
| 41. Network Certificate Inventory | 85. GraphQL Introspection Probe | 133. Domain Shadowing Detector |
| 42. SSH Banner & Key Fingerprinter | 86. File Upload Surface Finder | 134. IP Reputation Trending |
| 43. SNMP Public Community Checker | 87. DOM Sink Scanner | 149. Dark Web Monitoring |
| 44. UDP Service Sampler | 88. Cache Behavior Analyzer | 150. IP Reputation Check |
| 139. SNMP Bulk Walk | 89. Cookie Scope Diff Across Subdomains | 151. TLS Security Config |
| 140. NetBIOS Name Query | 90. CSP Deep Analyzer |  |
| 141. TTL Analysis | 91. Third-Party Script Risk Profiler |  |
| 142. IRR Routing Registry Analyzer | 92. Static Asset Fingerprinter |  |
| 143. Dual Stack Diff | 148. Email Config |  |
| 144. DNS CAA Checker |  |  |
| 145. Decoy DNS Beacon |  |  |
| 146. Geo IP Spoof Detection | 152. JS Secret / API Key Scanner |  |
| 147. Passive DNS History | 153. Security Headers Grade |  |
| 154. JARM TLS Fingerprint | 155. CVE Enrichment from Tech Stack |  |
| 156. Subdomain Takeover (Deep) | 157. Subresource Integrity Checker |  |
| 158. Document Metadata Extractor |  |  |

---




## 🛠️ Configuration

### API Keys Setup

Enhance functionality by configuring API keys in `config/settings.py` or as environment variables:

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
export CENSYS_API_ID="your_id_here"
export CENSYS_API_SECRET="your_secret_here"
export GOOGLE_API_KEY="your_key_here"
export HIBP_API_KEY="your_key_here"
```

**Check API status:**
```bash
perimetry> show api_status
```

### Configuration Options

Edit `config/settings.py` to customize:
- Default request timeouts and retry logic
- Thread limits and concurrency settings
- Export settings (TXT/CSV output)
- Logging levels and destinations
- User agent strings and headers

---


## 🔄 Changelog

### Version 2.0 (Current)
**Major refactor: Complete CLI redesign and module expansion**

- **New interactive CLI** - Full command-line interface with 25+ commands
- **154 modules** - Expanded from 50 modules
- **Better UI** - Professional formatting and progress tracking
- **Multi-threading** - Improved performance with concurrent execution
- **API integrations** - Shodan, VirusTotal, Censys, SSL Labs support
- **Export capabilities** - TXT, CSV, JSON output formats
- **Configuration system** - Profiles, settings, and API key management
- **Module discovery** - Search, browse, and favorite modules
- **Batch operations** - Run multiple modules simultaneously

### Version 1.x (Legacy)
**Original simple number-based interface**

- Simple number input system (1-50)
- Basic 50 reconnaissance modules
- Console text output only
- Fixed configuration settings

---

**Note**: Version 2.0 introduces breaking changes. Users must learn new CLI commands instead of the previous number-based system.

---

## ⭐️ Show Your Support

If this tool has been helpful to you, please consider giving us a star on GitHub! Your support means a lot to us and helps others discover the project.

### Issues & Bug Reports

- Check existing issues before reporting
- Provide detailed reproduction steps
- Include system information and error logs

---
