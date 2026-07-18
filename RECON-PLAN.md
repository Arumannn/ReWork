# Recon Plan — Universal (.env-Driven)

## Overview

A reusable, phase-based recon plan for **web + mobile** bug bounty hunting. Every target-specific value lives in `.env` — copy `.env.template` to `.env`, fill it in, and run each phase.

### Phases

| # | Phase | Type | Traffic |
|---|-------|------|---------|
| 1 | Passive Web Recon | OSINT | None (3rd-party APIs) |
| 2 | Active Web Recon | Probing | Direct to target |
| 3 | Passive Mobile Recon | Static Analysis | None (offline) |
| 4 | Active Mobile Recon | Dynamic Analysis | Via proxy |
| 5 | Web ↔ Mobile Correlation | Analysis | None |
| 6 | Vulnerability Discovery | Scanning | Via HexStrike |
| 7 | Reporting | Documentation | None |

---

## 0. Setup

```bash
# === Load .env ===
set -a; source ./.env; set +a

# === Validate required vars ===
: "${SEED_DOMAINS:?}"; : "${WORKDIR:?}"; : "${RL_LIGHT:=10}"
: "${RL_MEDIUM:=50}"; : "${RL_AGGRESSIVE:=100}"; : "${THREADS:=5}"

# === Create directory structure ===
mkdir -p "$WORKDIR"/{subs,ports,http,urls,js/{raw,maps,findings},mobile/{android,ios},api,auth,correlation}

# === Expand seed domains ===
echo "$SEED_DOMAINS" | tr ' ' '\n' | grep -v '^$' > seeds.txt
```

---

## Phase 1 — Passive Web Recon

> **Zero traffic to target.** All data from public archives, CT logs, search engines.

### 1.1 Subdomain Enumeration (Passive)

```bash
# subfinder — aggregates dozens of passive sources
subfinder -dL seeds.txt -all -v -o subs/subfinder.txt

# Certificate Transparency — crt.sh + certspotter
pcurl() { curl -sv --max-time 30 --retry 2 "$@"; }

: > subs/crtsh.txt
while read -r d; do
  pcurl "https://crt.sh/?q=%25.${d}&output=json" | jq -r '.[].name_value' 2>/dev/null
done < seeds.txt | sed 's/\*\.//g' | sort -u >> subs/crtsh.txt

: > subs/certspotter.txt
while read -r d; do
  pcurl "https://api.certspotter.com/v1/issuances?domain=${d}&include_subdomains=true&expand=dns_names" \
    | jq -r '.[].dns_names[]?' 2>/dev/null
done < seeds.txt | sed 's/\*\.//g' | sort -u >> subs/certspotter.txt

# urlscan.io
: > subs/urlscan.txt
while read -r d; do
  pcurl "https://urlscan.io/api/v1/search/?q=domain:${d}&size=1000" \
    | jq -r '.results[]?.page.domain' 2>/dev/null
done < seeds.txt | sort -u >> subs/urlscan.txt

# AlienVault OTX (if API key set)
if [ -n "$OTX_API_KEY" ]; then
  : > subs/otx.txt
  while read -r d; do
    pcurl -H "X-OTX-API-KEY: $OTX_API_KEY" \
      "https://otx.alienvault.com/api/v1/indicators/domain/${d}/passive_dns" \
      | jq -r '.passive_dns[]?.hostname' 2>/dev/null
  done < seeds.txt | sort -u >> subs/otx.txt
fi

# Merge all sources
cat subs/subfinder.txt subs/crtsh.txt subs/certspotter.txt subs/urlscan.txt subs/otx.txt \
    2>/dev/null | sort -u > subs/all_subs.txt
```

### 1.2 Filter Scope

```bash
# Filter by wildcard regex
grep -E "$SCOPE_WILDCARD" subs/all_subs.txt | sort -u > subs/inscope_subs.txt

# Add explicit in-scope domains
echo "$SCOPE_EXPLICIT" >> subs/inscope_subs.txt

# Remove out-of-scope
if [ -n "$OUT_OF_SCOPE" ]; then
  echo "$OUT_OF_SCOPE" | grep -vFf - subs/inscope_subs.txt > subs/inscope_subs.tmp
  mv subs/inscope_subs.tmp subs/inscope_subs.txt
fi

sort -u subs/inscope_subs.txt -o subs/inscope_subs.txt
```

### 1.3 Historical URL Gathering

```bash
# Wayback Machine CDX
: > urls/wayback_raw.txt
while read -r d; do
  curl -s --max-time 45 --retry 1 \
    "https://web.archive.org/cdx/search/cdx?url=${d}&matchType=domain&output=text&fl=original&collapse=urlkey&limit=10000" \
    >> urls/wayback_raw.txt
done < seeds.txt
sort -u urls/wayback_raw.txt -o urls/wayback_raw.txt

# GAU (alternative source, same API)
gau -subs < seeds.txt 2>/dev/null | sort -u > urls/gau.txt

sort -u urls/wayback_raw.txt urls/gau.txt > urls/all_urls.txt
grep '=' urls/all_urls.txt | sort -u > urls/params.txt
```

### 1.4 JS Discovery (Passive)

```bash
# Extract JS URLs from historical data
grep -E '\.m?js($|\?)' urls/all_urls.txt | sort -u > urls/js_urls.txt

# Categorize URLs
grep -iE 'auth|login|signin|oauth|token|session|2fa|mfa|verify|sso' urls/all_urls.txt > urls/auth_urls.txt
grep -iE 'api|v[0-9]|rest|graphql|grpc|bff|gateway' urls/all_urls.txt > urls/api_urls.txt
grep -iE 'payment|checkout|billing|invoice|refund|wallet|coupon|promo' urls/all_urls.txt > urls/payment_urls.txt
grep -iE 'admin|internal|staff|backoffice|dashboard|management' urls/all_urls.txt > urls/admin_urls.txt
grep -iE 'user|account|profile|customer' urls/all_urls.txt > urls/user_urls.txt
```

### 1.5 Technology Fingerprinting

```bash
# WAF detection (passive, single request per host)
while read -r h; do
  wafw00f "https://${h}" -a 2>/dev/null
done < subs/inscope_subs.txt | tee http/waf_results.txt
```

### 1.6 GitHub / Cloud Enumeration (Optional)

```bash
if [ -n "$GITHUB_TOKEN" ]; then
  mkdir -p github

  # Search for leaked secrets in public repos
  while read -r d; do
    # GitHub code search via API
    curl -s -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/search/code?q=${d}+extension:env+extension:json+extension:yml" \
      | jq -r '.items[]?.html_url' 2>/dev/null
  done < seeds.txt | sort -u > github/leak_candidates.txt
fi

# Cloud storage enumeration
if command -v cloud_enum &>/dev/null; then
  cloud_enum -k "$(head -1 seeds.txt)" 2>/dev/null | tee -a http/cloud_findings.txt
fi
```

---

## Phase 2 — Active Web Recon

> **Direct traffic to target.** Respect rate limits.

### 2.1 DNS Resolution

```bash
: > subs/resolved.txt
while read -r h; do
  ip=$(dig +short "$h" A | grep -E '^[0-9]' | head -1)
  [ -n "$ip" ] && echo "$h $ip" >> subs/resolved.txt
done < subs/inscope_subs.txt

awk '{print $1}' subs/resolved.txt | sort -u > subs/live_hosts.txt
```

### 2.2 HTTP Probing

```bash
AUTH_ARGS=()
[ -n "$AUTH_HEADER" ] && AUTH_ARGS+=(-H "$AUTH_HEADER")
[ -n "$AUTH_COOKIE" ] && AUTH_ARGS+=(-H "Cookie: $AUTH_COOKIE")

httpx-pd -l subs/live_hosts.txt -rl "$RL_MEDIUM" -v \
  "${AUTH_ARGS[@]}" \
  -sc -title -td -location -cl -server -probe \
  -o http/httpx_full.txt

httpx-pd -l subs/live_hosts.txt -rl "$RL_MEDIUM" -silent \
  "${AUTH_ARGS[@]}" > http/live_urls.txt
```

### 2.3 Port Scanning

```bash
awk '{print $2}' subs/resolved.txt | sort -u > ports/ips.txt
P="21,22,25,53,80,110,143,443,465,587,993,995,1080,2082,2083,3000,4443,5000,5432,6379,7001,8000,8008,8080,8081,8443,8888,9000,9200,11211,27017,30000"

nmap -iL ports/ips.txt -p "$P" -sV --open -T3 \
  --max-retries 1 --host-timeout 3m --max-rate 10 -v -oA ports/nmap_all
```

### 2.4 Web Crawling

```bash
katana -list http/live_urls.txt -rl "$RL_MEDIUM" -jc -c "$THREADS" -p 10 -d 3 -timeout 10 \
  "${AUTH_ARGS[@]}" -o urls/katana.txt

# Merge with historical URLs
cat urls/all_urls.txt urls/katana.txt 2>/dev/null | sort -u > urls/all_urls_merged.txt
grep '=' urls/all_urls_merged.txt | sort -u > urls/params_merged.txt
```

### 2.5 Content Discovery

```bash
W="api|v1|v2|v3|graphql|rest|auth|login|signin|oauth|token|session|user|admin|internal|dashboard|health|status|metrics|swagger|docs|openapi|webhook|callback|config|settings|payment|checkout|wallet|static|assets|uploads|download|.env|.git|backup|db|migrations|logs|debug|test"

for target in $(head -50 subs/live_hosts.txt); do
  ffuf -u "https://${target}/FUZZ" -w <(echo "$W" | tr '|' '\n') \
    -t "$THREADS" -rate "$RL_AGGRESSIVE" -c -fc 404 -o "http/ffuf_${target}.json" 2>/dev/null &
done
wait
```

### 2.6 Hidden Parameter Discovery

```bash
# Run arjun on high-value endpoints
for ep in $(head -30 urls/api_urls.txt); do
  arjun -u "$ep" --method GET --threads 5 --rate-limit "$RL_LIGHT" -o "api/params_$(echo "$ep" | md5sum | cut -c1-8).json" 2>/dev/null
done
```

### 2.7 JavaScript Analysis (Active Download + Static Analysis)

> Uses the dedicated `js_analis.sh` script — a `.env`-driven, universal JS pipeline.
> Reads `.env` for rate limits, auth headers, and scope. Produces a comprehensive
> report at `js/findings/REPORT.md` with endpoints, secrets, XSS, CSRF, WebSocket,
> GraphQL, auth/OAuth, payment, wallet/DeFi, and IDOR candidates.

```bash
bash js_analis.sh .   # uses .env SCOPE_WILDCARD for filtering
# or with explicit scope:
bash js_analis.sh . '\.example\.com|\.example\.io$'
```

**What it does under the hood:**

1. **Collect JS URLs** — filters `.m?js` from `urls/all_urls_merged.txt`, filtered by scope
2. **Download** — parallel `xargs` with rate limiting from `$RL_MEDIUM`, dedup by sha256
3. **Source maps** — fetches `.map` files derived from JS URLs, unpacks embedded sources
4. **Beautify** — `js-beautify` if available, otherwise analysis from raw files
5. **Endpoint extraction** — `jsluice urls` (or regex fallback), then categorized (auth, api, admin, payment, crypto, idor, ws, kyc, ...)
6. **Secret detection** — `trufflehog filesystem` + 15 regex patterns (API keys, JWT, AWS, private keys, GitHub tokens, Firebase, Stripe, ...)
7. **XSS surface** — innerHTML, postMessage handlers, eval, JSONP callbacks
8. **CSRF surface** — state-changing requests without anti-CSRF tokens
9. **WebSocket** — `wss?://` endpoints, message handlers, sensitive sends
10. **GraphQL** — schema queries, mutations, endpoint URLs
11. **Auth/OAuth** — storage patterns, JWT handling, OAuth params, hardcoded creds, SSO, MFA bypass hints
12. **Payment** — provider detection, amount handling, webhooks, refund patterns
13. **Wallet/DeFi** — web3 usage, seed phrases, wallet connect, network config
14. **IDOR** — parameterized API paths, admin impersonation patterns
15. **Report** — `js/findings/REPORT.md` with categorized findings and triage priority

---

## Phase 3 — Passive Mobile Recon

> **Offline analysis.** APK/IPA obtained from Play Store, App Store, or device backup.

### 3.1 Android APK Analysis

```bash
if [ -n "$ANDROID_PACKAGES" ]; then
  mkdir -p mobile/android/{decompiled,source,reports}

  # If APK path provided externally, use it
  # Otherwise, extract from device: adb shell pm path <package> | adb pull

  for pkg in $ANDROID_PACKAGES; do
    apk_path="mobile/android/${pkg}.apk"
    [ ! -f "$apk_path" ] && continue

    # Decompile
    apktool d -f -o "mobile/android/decompiled/${pkg}" "$apk_path" 2>/dev/null

    # Jadx decompile to Java
    jadx -d "mobile/android/source/${pkg}" "$apk_path" 2>/dev/null

    # Hardcoded URLs and secrets
    strings "$apk_path" | grep -iE 'https?://' | grep -v 'android\.com\|googleapis\|googlesyndication' \
      | sort -u > "mobile/android/urls_${pkg}.txt"

    strings "$apk_path" | grep -iE 'api[_-]?key|token|secret|password|bearer|firebase|supabase' \
      | sort -u > "mobile/android/secrets_${pkg}.txt"

    # Firebase discovery
    strings "$apk_path" | grep -iE 'firebase|firestore|realtime.*database|\.appspot\.com' \
      | sort -u > "mobile/android/firebase_${pkg}.txt"

    # Certificate pinning check
    grep -ri 'certificatePinner\|CertificatePinner\|pins\b' "mobile/android/decompiled/${pkg}" 2>/dev/null \
      > "mobile/android/cert_pinning_${pkg}.txt"

    # MobSF static scan (if available)
    if command -v mobsfscan &>/dev/null; then
      mobsfscan "mobile/android/source/${pkg}" --json -o "mobile/android/reports/mobsf_${pkg}.json" 2>/dev/null
    fi

    # apkleaks (if available)
    if command -v apkleaks &>/dev/null; then
      apkleaks -f "$apk_path" -o "mobile/android/reports/apkleaks_${pkg}.txt" 2>/dev/null
    fi
  done
fi
```

### 3.2 iOS IPA Analysis

```bash
if [ -n "$IOS_BUNDLE_IDS" ]; then
  mkdir -p mobile/ios/{decrypted,source,reports}

  for bundle in $IOS_BUNDLE_IDS; do
    ipa_path="mobile/ios/${bundle}.ipa"
    [ ! -f "$ipa_path" ] && continue

    # Extract IPA
    unzip -o "$ipa_path" -d "mobile/ios/decrypted/${bundle}" 2>/dev/null

    # Find and analyze main binary
    main_bin=$(find "mobile/ios/decrypted/${bundle}" -type f -perm +111 -name "${bundle}" 2>/dev/null | head -1)
    [ -n "$main_bin" ] && strings "$main_bin" | grep -iE 'https?://' \
      | sort -u > "mobile/ios/urls_${bundle}.txt"

    # Class-dump (if available)
    if command -v class-dump &>/dev/null && [ -n "$main_bin" ]; then
      class-dump "$main_bin" 2>/dev/null > "mobile/ios/source/${bundle}_header.txt"
    fi
  done
fi
```

### 3.3 Deep Link Extraction

```bash
# Android: extract intent filters from AndroidManifest
for pkg in $ANDROID_PACKAGES; do
  manifest="mobile/android/decompiled/${pkg}/AndroidManifest.xml"
  [ -f "$manifest" ] || continue

  # Extract deep link schemes
  grep -oE 'android:scheme="[^"]+"' "$manifest" | sort -u > "mobile/android/deeplink_schemes_${pkg}.txt"
  grep -oE 'android:host="[^"]+"' "$manifest" | sort -u > "mobile/android/deeplink_hosts_${pkg}.txt"
  grep -oE 'android:path(Pattern)?="[^"]+"' "$manifest" | sort -u > "mobile/android/deeplink_paths_${pkg}.txt"
done

# iOS: extract from Info.plist / associated domains
for bundle in $IOS_BUNDLE_IDS; do
  plist=$(find "mobile/ios/decrypted/${bundle}" -name 'Info.plist' 2>/dev/null | head -1)
  [ -f "$plist" ] || continue

  grep -oE 'CFBundleURLSchemes|CFBundleURLName|CFBundleURLTypes' "$plist" -A 2 2>/dev/null \
    > "mobile/ios/url_schemes_${bundle}.txt"
done
```

### 3.4 Mobile API Endpoint Inventory

```bash
# Consolidate all API endpoints found in mobile apps
cat mobile/android/urls_*.txt mobile/ios/urls_*.txt 2>/dev/null \
  | grep -iE '/api|/v[0-9]|/graphql|/rest|/auth|/oauth|/token|/payment|/wallet|/user|/account' \
  | sort -u > mobile/all_mobile_endpoints.txt
```

---

## Phase 4 — Active Mobile Recon

> **Runtime testing with Burp Suite / Frida / proxy.**

### 4.1 SSL Pinning Bypass (Frida)

```bash
# Android — universal SSL pinning bypass
frida -U -f "$ANDROID_PACKAGES" -l /usr/share/frida-scripts/universal.js --no-pause 2>/dev/null &
sleep 3

# Capture proxy: mitmproxy -p 8080
# Configure device proxy: adb shell settings put global http_proxy 127.0.0.1:8080
```

### 4.2 Deep Link Fuzzing (Android)

```bash
for pkg in $ANDROID_PACKAGES; do
  scheme="mobile/android/deeplink_schemes_${pkg}.txt"
  host="mobile/android/deeplink_hosts_${pkg}.txt"
  path="mobile/android/deeplink_paths_${pkg}.txt"

  [ -f "$scheme" ] || continue

  while read -r s; do
    while read -r h; do
      while read -r p; do
        uri="${s}://${h}${p}"
        echo "[*] Testing: $uri"
        adb shell am start -W -a android.intent.action.VIEW -d "$uri" 2>/dev/null || true
        sleep 0.5
      done < "$path"
    done < "$host"
  done < "$scheme"
done 2>/dev/null | tee mobile/android/deeplink_test_results.txt
```

### 4.3 Dynamic Traffic Capture

```bash
# mitmproxy — capture all mobile traffic via proxy
# mitmproxy -p 8080 -w mobile/traffic_capture.mitm
# Then replay actions in the mobile app

# Extract endpoints from captured traffic
if [ -f mobile/traffic_capture.mitm ]; then
  mitmdump -nr mobile/traffic_capture.mitm 2>/dev/null \
    | grep -oE 'https?://[^"'"'"'<> ]+' | sort -u > mobile/captured_urls.txt
fi
```

---

## Phase 5 — Web ↔ Mobile Correlation

> **Cross-reference findings from web and mobile to find undocumented APIs and mismatched auth.**

### 5.1 Endpoint Cross-Reference

```bash
mkdir -p correlation

# Endpoints found in JS (web) but NOT in mobile APK/IPA
comm -23 <(sort js/findings/endpoints/all.txt) <(sort mobile/all_mobile_endpoints.txt 2>/dev/null) \
  > correlation/web_only_endpoints.txt

# Endpoints found in mobile APK/IPA but NOT in web JS
comm -13 <(sort js/findings/endpoints/all.txt) <(sort mobile/all_mobile_endpoints.txt 2>/dev/null) \
  > correlation/mobile_only_endpoints.txt

# Endpoints found in both (undocumented / shared)
comm -12 <(sort js/findings/endpoints/all.txt) <(sort mobile/all_mobile_endpoints.txt 2>/dev/null) \
  > correlation/shared_endpoints.txt
```

### 5.2 Auth Flow Comparison

```bash
# Auth endpoints from web vs mobile
grep -iE 'auth|login|oauth|token|session' js/findings/endpoints/all.txt 2>/dev/null \
  > correlation/web_auth_endpoints.txt
grep -iE 'auth|login|oauth|token|session' mobile/all_mobile_endpoints.txt 2>/dev/null \
  > correlation/mobile_auth_endpoints.txt

# Compare auth patterns — look for OAuth flows present in mobile but not web
comm -13 correlation/web_auth_endpoints.txt correlation/mobile_auth_endpoints.txt \
  > correlation/mobile_exclusive_auth.txt
```

### 5.3 Secret Correlation

```bash
# Check if secrets found in JS match mobile infrastructure
if [ -f js/findings/secrets/regex_hits.txt ]; then
  grep -iE 'firebase|supabase|aws|amazon|gcp|azure|stripe' js/findings/secrets/regex_hits.txt \
    > correlation/web_cloud_secrets.txt
fi

# Merge all secret findings into one report
cat js/findings/secrets/regex_hits.txt mobile/android/secrets_*.txt 2>/dev/null \
  | sort -u > correlation/all_secrets.txt
```

### 5.4 Surface Summary

```bash
{
  echo "=== WEB SURFACE ==="
  echo "Live hosts: $(wc -l < subs/live_hosts.txt)"
  echo "Live URLs: $(wc -l < http/live_urls.txt)"
  echo "JS endpoints: $(wc -l < js/findings/endpoints/all.txt)"
  echo "Secrets found: $(wc -l < js/findings/secrets/regex_hits.txt)"
  echo ""
  echo "=== MOBILE SURFACE ==="
  echo "Android packages: $ANDROID_PACKAGES"
  echo "iOS bundles: $IOS_BUNDLE_IDS"
  echo "Mobile endpoints: $(wc -l < mobile/all_mobile_endpoints.txt)"
  echo ""
  echo "=== CORRELATION ==="
  echo "Endpoints in web only: $(wc -l < correlation/web_only_endpoints.txt)"
  echo "Endpoints in mobile only: $(wc -l < correlation/mobile_only_endpoints.txt)"
  echo "Shared endpoints: $(wc -l < correlation/shared_endpoints.txt)"
  echo "Combined secrets: $(wc -l < correlation/all_secrets.txt)"
} | tee correlation/summary.txt
```

---

## Phase 6 — Vulnerability Discovery (via HexStrike)

> **No raw `nuclei` calls.** All vulnerability scanning routed through HexStrike.

### 6.1 Subdomain Takeover

```bash
# Via HexStrike
hexstrike_nuclei_scan \
  target=http/live_urls.txt \
  tags=takeover \
  severity=medium,high,critical \
  rate_limit="$RL_MEDIUM" \
  output=http/takeover.txt
```

### 6.2 CVE & Misconfig Scanning

```bash
hexstrike_nuclei_scan \
  target=http/live_urls.txt \
  tags=exposure,misconfig,cve,config,backup,disclosure \
  exclude_tags=ssl,tls,dos,fuzz,intrusive,token-spray,creds-stuffing,brute-force \
  severity=medium,high,critical \
  exclude_severity=info \
  rate_limit="$RL_MEDIUM" \
  output=http/nuclei_findings.txt
```

### 6.3 CORS Misconfiguration

```bash
hexstrike_nuclei_scan \
  target=http/live_urls.txt \
  tags=cors \
  rate_limit="$RL_MEDIUM" \
  output=http/cors_findings.txt

# Manual CORS validation on high-value endpoints
for target in $(cat subs/live_hosts.txt); do
  for origin in "https://evil.com" "https://${target}.evil.com" "null"; do
    curl -sk "https://${target}/" \
      -H "Origin: $origin" \
      -I 2>/dev/null | grep -i 'access-control' | tee -a http/cors_manual.txt
  done
done
```

### 6.4 Open Redirect

```bash
grep -oE 'https?://[^"'"'"'<> ]*(redirect|return|continue|next|url|goto|dest|target)=https?://' \
  urls/all_urls_merged.txt | sort -u > urls/open_redirect_candidates.txt
```

### 6.5 XSS Scanning

```bash
# Automated XSS via HexStrike + dalfox
hexstrike_ai_generate_payload \
  attack_type=xss \
  complexity=advanced \
  technology=generic \
  url="$(head -1 urls/params.txt)" 2>/dev/null

# dalfox on parameter-rich URLs
head -100 urls/params_merged.txt | dalfox pipe --mining-dom --mining-dict \
  --rate-limit "$RL_LIGHT" -o http/xss_findings.txt 2>/dev/null
```

### 6.6 Manual Validation Checklist

Temuan dari HexStrike yang severity **medium+** wajib diverifikasi:

- [ ] Manual HTTP request (Burp Repeater / curl) — konfirmasi bukan false positive
- [ ] Root cause analysis — parameter/endpoint mana yang menyebabkan vuln
- [ ] PoC yang reproducible — langkah demi langkah
- [ ] Business impact — worst-case scenario (bisa rugi uang? data bocor? takeover?)
- [ ] CVSS score v3.1
- [ ] Remediation suggestion
- [ ] Cek duplikasi — sudah pernah dilaporkan?

---

## Phase 7 — Reporting

### 7.1 Consolidated Findings

```bash
{
  echo "# Recon Report — ${PROGRAM_NAME}"
  echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
  echo ""

  echo "## Surface Summary"
  echo "| Metric | Count |"
  echo "|--------|-------|"
  echo "| Seed domains | $(wc -l < seeds.txt) |"
  echo "| Subdomains (all) | $(wc -l < subs/all_subs.txt) |"
  echo "| Subdomains (in-scope) | $(wc -l < subs/inscope_subs.txt) |"
  echo "| Live hosts | $(wc -l < subs/live_hosts.txt) |"
  echo "| Live URLs | $(wc -l < http/live_urls.txt) |"
  echo "| URLs w/ params | $(wc -l < urls/params_merged.txt) |"
  echo "| JS endpoints found | $(wc -l < js/findings/endpoints/all.txt) |"
  echo "| Secret candidates | $(wc -l < correlation/all_secrets.txt) |"
  echo "| Takeover candidates | $(wc -l < http/takeover.txt) |"
  echo "| Nuclei findings | $(wc -l < http/nuclei_findings.txt) |"
  echo "| Mobile endpoints | $(wc -l < mobile/all_mobile_endpoints.txt) |"
  echo ""

  echo "## Web-Only Endpoints (Check for Missing Auth)"
  cat correlation/web_only_endpoints.txt
  echo ""

  echo "## Mobile-Only Endpoints (Undocumented APIs)"
  cat correlation/mobile_only_endpoints.txt
  echo ""

  echo "## Secret Candidates (Prioritize Verified)"
  cat correlation/all_secrets.txt
  echo ""

  echo "## Vulnerability Findings (Medium+)"
  [ -f http/nuclei_findings.txt ] && cat http/nuclei_findings.txt
  [ -f http/takeover.txt ] && cat http/takeover.txt
  [ -f http/cors_findings.txt ] && cat http/cors_findings.txt
  [ -f http/xss_findings.txt ] && cat http/xss_findings.txt

} | tee recon_report.md
```

### 7.2 Priority Triage

| Priority | What to Hunt | Source |
|----------|-------------|--------|
| 🔴 Critical | API key / token leaks (verified) | `correlation/all_secrets.txt` |
| 🔴 Critical | Auth bypass / IDOR on mobile-only endpoints | `correlation/mobile_only_endpoints.txt` |
| 🔴 Critical | Payment / wallet logic flaws | `urls/payment_urls.txt` |
| 🟠 High | Subdomain takeover candidates | `http/takeover.txt` |
| 🟠 High | CORS misconfig on sensitive endpoints | `http/cors_manual.txt` |
| 🟠 High | XSS on auth / payment pages | `http/xss_findings.txt` |
| 🟡 Medium | Open redirect on OAuth flows | `urls/open_redirect_candidates.txt` |
| 🟡 Medium | Missing security headers on main domains | `http/httpx_full.txt` |
| ⚪ Low | Info disclosure, version leaks | `http/nuclei_findings.txt` |

---

## Rules of Engagement

- **Test accounts only** — no access to real user data
- **Rate limits apply** — `$RL_LIGHT` for auth/payment endpoints
- **No destructive testing** — no DoS, no brute force, no data modification
- **Report via platform** — `${PROGRAM_PLATFORM}` — check live policy before each submission
- **Safe Harbor** — verify coverage before starting
- **Mobile testing** — only with accounts/devices you own
- **Cloud testing** — don't access/modify resources you don't own
