# Universal Recon Framework

Bug bounty recon pipeline — Web + Mobile. `.env`-driven, CLI-overridable.

## Quick Start

```bash
# Setup
cp .env.template .env
# Edit .env: set SEED_DOMAINS, SHODAN_API_KEY, dll

# Full pipeline
./recon_framework.sh

# Single phase
./recon_framework.sh --phase 1

# Phase range
./recon_framework.sh --range 2-4

# Resume from last completed phase
./recon_framework.sh --resume

# Custom target (override .env)
./recon_framework.sh --target openai.com chatgpt.com

# From file
./recon_framework.sh --targets-file targets.txt

# Verbose
./recon_framework.sh -v      # phase details
./recon_framework.sh -vv     # all tool output + debug trace

# Check tools only
./recon_framework.sh --check-tools
```

## 7 Phases

| Phase | Name | What It Does |
|-------|------|-------------|
| 1 | Passive Web Recon | subfinder, amass, crt.sh, urlscan, gau, wayback, wafw00f, wappalyzer, shodan, Google dorks, GitHub dorking |
| 2 | Active Web Recon | DNS resolution, httpx-pd probing, nmap port scan, katana/hakrawler crawl, ffuf/feroxbuster content discovery, arjun param discovery |
| 3 | Passive Mobile | APK/IPA decompile (apktool/jadx), string analysis, Firebase discovery |
| 4 | Active Mobile | Instructions for Frida SSL pinning bypass + mitmproxy |
| 5 | Web ↔ Mobile | Endpoint cross-reference, auth flow comparison, secret correlation |
| 6 | Vulnerability | nuclei (takeover, CVE, CORS, API), dalfox (XSS), sqlmap, open redirect |
| 7 | Reporting | Consolidated `recon_report.md` |

## Configuration

### `.env` (required fields)

```env
SEED_DOMAINS="openai.com"             # Space-separated targets
SHODAN_API_KEY="your_key"             # For shodan.io queries
GITHUB_TOKEN="your_token"             # For GitHub code search
```

### `.env` (optional)

```env
TARGETS_FILE="/path/targets.txt"      # Overrides SEED_DOMAINS
OUT_OF_SCOPE="staging.example.com"    # Exclude patterns
AUTH_COOKIE="session=abc123"          # Auth for crawling
AUTH_HEADER="Authorization: Bearer xyz"
RL_LIGHT=10  RL_MEDIUM=50  RL_AGGRESSIVE=100  THREADS=5
```

### Target priority

1. `--target domain.com` (CLI) — highest
2. `--targets-file list.txt` (CLI)
3. `.env` `TARGETS_FILE`
4. `.env` `SEED_DOMAINS` — fallback

All other config (API keys, rate limits, headers) always comes from `.env`.

## Output Structure

```
WORKDIR/
├── subs/          subdomain lists
├── ports/         nmap results
├── http/          httpx, waf, nuclei, dalfox results
├── urls/          gau, wayback, katana, categorized URLs
├── js/            JS analysis output
├── mobile/        APK/IPA analysis
├── api/           arjun, sqlmap results
├── correlation/   web vs mobile comparison
├── github/        GitHub leak candidates
├── dorks/         Google/GitHub dork queries
└── recon_report.md
```
