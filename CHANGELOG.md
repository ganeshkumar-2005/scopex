# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-07

### Added
- **Asynchronous Scan Orchestration Engine** (`core/orchestrator.py`) supporting concurrent scanning, checkpoints, and per-scanner timeouts.
- **ProjectDiscovery Nuclei Integration** (`utils/nuclei_orchestrator.py`) with automatic download, execution, and deduplication of findings.
- **Glassmorphic HTML Web Dashboard** (`reports/dashboard.py`) serving visual graphs, scans logs, and PDF downloads locally.
- **Windows Command-Injection Prevention** by validating target URLs and hostnames and rejecting shell metacharacters in CLI target inputs.
- **Absolute Package Path Resolution** for configuration files and output directories, ensuring reliable execution across varying current working directories.

## [1.0.0] - 2026-06-23

### Added
- **14 Core Scanning Modules** in `scanners/`:
  - Port Scanner (fast TCP connect sweeps)
  - HTTP Header Scanner (HSTS, CSP, X-Frame-Options, server disclosures)
  - SSL/TLS Scanner (certificate validations and cipher suite audits)
  - DNS Scanner (A, AAAA, MX, TXT, CNAME, private IP leak checks)
  - Subdomain Scanner (dictionary brute-force with wildcard protection)
  - Web Vulnerability Scanner (CORS bypass, clickjacking, open redirect, sensitive file discovery)
  - SQL Injection Scanner (error-based and time-blind verify tests)
  - XSS Scanner (reflected and DOM-based detection)
  - Technology stack fingerprinter and CVE mapper
  - Cookie and JWT Scanner (weak signature cracking, none-alg check, attributes audit)
  - WAF/CDN Detector (Cloudflare, AWS WAF, etc.)
  - Information Disclosure Scraper (private keys, emails, IPs in scripts/comments)
  - Administrative Panel Finder (admin/login portal scanner)
  - API Routes Discoverer and GraphQL introspector
  - WHOIS Domain registration lookup
- **7 Advanced Nessus-style plugins** in `plugins/`:
  - SSL attacks (Heartbleed, POODLE, DROWN, FREAK, CRIME)
  - Service protocol audits (FTP anon, SSH algos, SMTP relay, DB passwordless exposures)
  - CMS vulnerability checks (WordPress user/plugins, Joomla, Drupalgeddon 2)
  - Network security controls (DNS zone transfers, SNMP community, SMB signing, LDAP binds)
  - Subdomain takeover checks (dangling CNAMES)
  - SSRF, LFI/RFI and directory traversal vectors
  - Compliance engine (maps findings to OWASP Top 10 categories & PCI-DSS v3.2.1 requirements)
- **Executive PDF Report Builder** using `fpdf2` with color-coded severity breakdowns and remediation advice.
- **Progressive CLI Interface** using `rich` and `click` displaying real-time scan progress bars and styled tables.
- **Comprehensive Unit Tests** for SQL Injection scanner (`tests/test_sqli_scanner.py`).
- **Interactive scan profiles** manager (quick, standard, full) via `config.json`.
