# Recon Plan — Universal (.env-Driven) — Powered by HexStrike AI 🚀

## Overview

A reusable, phase-based recon plan for **web + mobile** bug bounty hunting — **dibantu oleh HexStrike AI** untuk otomatisasi, parameter optimization, dan AI-driven tool selection. Every target-specific value lives in `.env` — copy `.env.template` to `.env`, fill it in, and run each phase.

> Semua tools di bawah ini sudah terintegrasi dengan HexStrike AI. Gunakan `hexstrike_` prefix untuk mengakses fitur AI-enhanced (parameter optimization, error recovery, smart scheduling).

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
# Via HexStrike AI — subfinder with optimized parameters
while read -r d; do
  hexstrike_subfinder_scan \
    domain="$d" \
    silent=true \
    all_sources=true
done < seeds.txt | sort -u > subs/subfinder_hexstrike.txt

# Certificate Transparency — crt.sh + certspotter (via HexStrike AI amass intel)
while read -r d; do
  hexstrike_amass_scan \
    domain="$d" \
    mode=intel
done < seeds.txt | jq -r '.[].name_value' 2>/dev/null | sort -u >> subs/crtsh_hexstrike.txt

# urlscan.io via waybackurls + gau (HexStrike AI enhanced)
hexstrike_waybackurls_discovery \
  domain="$(head -1 seeds.txt)" \
  no_subs=false | sort -u > subs/wayback_hexstrike.txt

hexstrike_gau_discovery \
  domain="$(head -1 seeds.txt)" \
  include_subs=true \
  providers="wayback,commoncrawl,otx,urlscan" | sort -u >> subs/gau_hexstrike.txt

# Merge all HexStrike sources
cat subs/subfinder_hexstrike.txt subs/crtsh_hexstrike.txt subs/wayback_hexstrike.txt subs/gau_hexstrike.txt \
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

### 1.3 Historical URL Gathering (via HexStrike)

```bash
# HexStrike AI — multi-source URL discovery
hexstrike_gau_discovery \
  domain="$(head -1 seeds.txt)" \
  include_subs=true \
  providers="wayback,commoncrawl,otx,urlscan" \
  output=urls/gau_hexstrike.txt

hexstrike_waybackurls_discovery \
  domain="$(head -1 seeds.txt)" \
  get_versions=false \
  output=urls/wayback_hexstrike.txt

# Merge + extract parameter-rich URLs
cat urls/gau_hexstrike.txt urls/wayback_hexstrike.txt 2>/dev/null | sort -u > urls/all_urls.txt
grep '=' urls/all_urls.txt | sort -u > urls/params.txt
```

### 1.4 URL Categorization (via HexStrike)

```bash
# Extract & categorize dengan HexStrike AI
hexstrike_gau_discovery \
  domain="$(head -1 seeds.txt)" \
  include_subs=true \
  output=urls/gau_hexstrike.txt

hexstrike_waybackurls_discovery \
  domain="$(head -1 seeds.txt)" \
  output=urls/wayback_hexstrike.txt

# Categorize URLs
grep -iE 'auth|login|signin|oauth|token|session|2fa|mfa|verify|sso' urls/all_urls_merged.txt > urls/auth_urls.txt
grep -iE 'api|v[0-9]|rest|graphql|grpc|bff|gateway' urls/all_urls_merged.txt > urls/api_urls.txt
grep -iE 'payment|checkout|billing|invoice|refund|wallet|coupon|promo' urls/all_urls_merged.txt > urls/payment_urls.txt
grep -iE 'admin|internal|staff|backoffice|dashboard|management' urls/all_urls_merged.txt > urls/admin_urls.txt
grep -iE 'user|account|profile|customer' urls/all_urls_merged.txt > urls/user_urls.txt
```

### 1.5 Technology Fingerprinting (via HexStrike)

```bash
# HexStrike AI — technology detection + WAF fingerprinting
hexstrike_detect_technologies_ai \
  target="$(head -1 seeds.txt)" \
  output=http/tech_detect_hexstrike.txt

hexstrike_wafw00f_scan \
  target="$(head -1 subs/inscope_subs.txt)" \
  output=http/waf_hexstrike.txt
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

### 2.1 DNS Resolution via HexStrike

```bash
# HexStrike AI — DNS enumeration + resolution
hexstrike_dnsenum_scan \
  domain="$(head -1 seeds.txt)" \
  output=subs/dns_hexstrike.txt

# Fallback manual DNS
: > subs/resolved.txt
while read -r h; do
  ip=$(dig +short "$h" A | grep -E '^[0-9]' | head -1)
  [ -n "$ip" ] && echo "$h $ip" >> subs/resolved.txt
done < subs/inscope_subs.txt

awk '{print $1}' subs/resolved.txt | sort -u > subs/live_hosts.txt
```

### 2.2 HTTP Probing (via HexStrike)

```bash
# Via HexStrike AI — httpx with technology detection
hexstrike_httpx_probe \
  target=subs/live_hosts.txt \
  probe=true \
  tech_detect=true \
  status_code=true \
  title=true \
  web_server=true \
  threads="$THREADS" \
  output=http/httpx_hexstrike.txt

# HexStrike AI technology fingerprinting
hexstrike_detect_technologies_ai \
  target="$(head -1 subs/live_hosts.txt)" \
  output=http/tech_fingerprint.txt
```

### 2.3 Port Scanning (via HexStrike)

```bash
# HexStrike AI optimized nmap scan
hexstrike_nmap_advanced_scan \
  target="$(head -1 ports/ips.txt)" \
  scan_type="-sS -sV" \
  ports="21,22,25,53,80,110,143,443,465,587,993,995,1080,2082,2083,3000,4443,5000,5432,6379,7001,8000,8008,8080,8081,8443,8888,9000,9200,11211,27017,30000" \
  os_detection=true \
  version_detection=true \
  nse_scripts="default,vuln" \
  output=ports/nmap_hexstrike.txt

# Alternatif: RustScan ultra-fast via HexStrike
hexstrike_rustscan_fast_scan \
  target="$(cat ports/ips.txt | tr '\n' ',')" \
  scripts=true \
  output=ports/rustscan_hexstrike.txt
```

### 2.4 Web Crawling (via HexStrike)

```bash
# HexStrike AI-powered crawling
hexstrike_katana_crawl \
  url="https://$(head -1 subs/live_hosts.txt)" \
  depth=3 \
  js_crawl=true \
  form_extraction=true \
  output=urls/katana_hexstrike.json

hexstrike_hakrawler_crawl \
  url="https://$(head -1 subs/live_hosts.txt)" \
  depth=3 \
  forms=true \
  robots=true \
  sitemap=true \
  output=urls/hakrawler_hexstrike.txt

# Merge all URL sources
cat urls/wayback_hexstrike.txt urls/gau_hexstrike.txt urls/katana_hexstrike.txt \
    2>/dev/null | sort -u > urls/all_urls_merged.txt
grep '=' urls/all_urls_merged.txt | sort -u > urls/params_merged.txt
```

### 2.5 Content Discovery (via HexStrike)

```bash
# Feroxbuster via HexStrike — recursive content discovery
hexstrike_feroxbuster_scan \
  url="https://$(head -1 subs/live_hosts.txt)" \
  wordlist=/usr/share/wordlists/dirb/common.txt \
  threads="$THREADS" \
  output=http/feroxbuster_hexstrike.txt

# Gobuster via HexStrike — multi-mode
hexstrike_gobuster_scan \
  url="https://$(head -1 subs/live_hosts.txt)" \
  mode=dir \
  wordlist=/usr/share/wordlists/dirb/common.txt \
  output=http/gobuster_hexstrike.txt

# FFuf via HexStrike — vhost + directory fuzzing
hexstrike_ffuf_scan \
  url="https://$(head -1 subs/live_hosts.txt)/FUZZ" \
  mode=directory \
  match_codes="200,204,301,302,307,401,403" \
  output=http/ffuf_hexstrike.txt
```

### 2.6 Hidden Parameter Discovery (via HexStrike)

```bash
# HexStrike AI — arjun parameter discovery
hexstrike_arjun_scan \
  url="https://$(head -1 subs/live_hosts.txt)" \
  method=GET \
  threads="$THREADS" \
  stable=true \
  output=api/arjun_hexstrike.json

# X8 hidden parameter discovery via HexStrike
hexstrike_x8_parameter_discovery \
  url="https://$(head -1 urls/api_urls.txt)" \
  method=GET \
  output=api/x8_params_hexstrike.txt

# ParamSpider via HexStrike
hexstrike_paramspider_mining \
  domain="$(head -1 seeds.txt)" \
  level=2 \
  output=api/paramspider_hexstrike.txt
```

### 2.7 Browser-Based Crawling (Playwright — Auth & Unauth)

> **Menggunakan Playwright (headless Chromium) untuk crawl dynamic web apps yang membutuhkan JavaScript rendering atau sesi login.**
> Bypass static crawler limitations — menangkap SPA routes, XHR/fetch calls, JS bundles, WebSocket, dan postMessage.

#### 2.7.1 Setup

```bash
# Install Playwright + Chromium
npm install playwright
npx playwright install chromium
# atau global
sudo npm install -g playwright && sudo npx playwright install chromium
```

#### 2.7.2 Unauth Crawl (Public Pages)

```javascript
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
  });

  const apiCalls = [];
  const jsUrls = [];

  page.on('request', req => {
    const url = req.url();
    const type = req.resourceType();
    // Capture XHR/fetch API calls
    if (type === 'xhr' || type === 'fetch' || url.includes('/api/')) {
      apiCalls.push(`${req.method()} ${url}`);
    }
    // Capture JS bundles
    if (type === 'script') {
      jsUrls.push(url);
    }
  });

  await page.goto('https://target.com', { waitUntil: 'networkidle', timeout: 30000 });
  await page.waitForTimeout(2000);  // biarkan async calls selesai

  // Dapatkan juga server-side props yang di-embed
  const nextData = await page.evaluate(() => {
    const el = document.getElementById('__NEXT_DATA__');
    return el ? el.textContent : null;
  });

  // Dapatkan React Router manifest (chatgpt.com dkk)
  const manifest = await page.evaluate(() => {
    // Try React Router v7
    if (window.__reactRouterManifest) return JSON.stringify(window.__reactRouterManifest);
    // Try Next.js buildId
    if (window.__NEXT_DATA__) return window.__NEXT_DATA__.buildId;
    return null;
  });

  fs.writeFileSync('api/api_calls.txt', [...new Set(apiCalls)].join('\n'));
  fs.writeFileSync('urls/js_bundles.txt', [...new Set(jsUrls)].join('\n'));
  fs.writeFileSync('http/page_html.txt', await page.content());
  fs.writeFileSync('http/next_data.json', nextData || '{}');

  await browser.close();
})();
```

#### 2.7.3 Auth Crawl (Cookie Injection)

Gunakan session cookies dari browser yang sudah login. Inject via `context.addCookies()`:

```javascript
const context = await browser.newContext({
  userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
});

await context.addCookies([
  { name: '__session', value: 's-xxx.yyy', domain: '.target.com', path: '/' },
  { name: '__cf_bm', value: '...', domain: '.target.com', path: '/' },
  { name: 'cf_clearance', value: '...', domain: '.target.com', path: '/' },
  // Stripe/Sentry/analytics cookies biasanya opsional
]);
```

**Tips:**
- `cf_clearance` + `__cf_bm` diperlukan untuk bypass Cloudflare pada sesi baru
- `_cfuvid` diperlukan untuk Cloudflare JS challenge yang sudah di-resolve
- Gunakan cookie yang masih fresh (CF challenge expired tiap ~30-60 menit)
- Untuk platform yang menggunakan JWT (Auth0, NextAuth), cari token di localStorage:
  ```javascript
  const ls = await page.evaluate(() => ({ ...localStorage }));
  ```
  Lalu inject sebagai cookie atau header Authorization

#### 2.7.4 Capture API Response Bodies

```javascript
// Capture response bodies
page.on('response', async resp => {
  const url = resp.url();
  if (!url.includes('/api/') && !url.includes('graphql')) return;
  try {
    const body = await resp.text();
    if (body.startsWith('{') || body.startsWith('[')) {
      fs.writeFileSync(`api/responses/${Date.now()}_${path.basename(url)}.json`, body);
    }
  } catch {}
});
```

#### 2.7.5 Capture JavaScript Bundles

```javascript
// Download JS bundles untuk static analysis offline
page.on('response', async resp => {
  const url = resp.url();
  if (!url.endsWith('.js') || url.includes('hot-update')) return;
  try {
    const body = await resp.body();
    const name = url.split('/').pop().split('?')[0];
    fs.writeFileSync(`js/${domain}_${name}`, body);
  } catch {}
});
```

Kemudian analisis offline:
```bash
# Extract API endpoint patterns
grep -oP '["'"'"'](/backend-api/[a-zA-Z0-9_/.-]{3,})["'"'"']' js/*.js | sort -u > api/endpoints.txt

# Extract React Router routes (chatgpt.com manifest)
python3 -c "
import re, json
with open('js/manifest.js') as f:
    data = json.loads(re.search(r'window.__reactRouterManifest=(.*)', f.read()).group(1))
for rid, rt in data['routes'].items():
    print(f'{rid}: {rt.get(\"path\",\"\")}')
"

# Extract secrets
grep -oP '(?:sk-|pk-|eyJ|ghp_|AKIA)[a-zA-Z0-9_\-]{20,}' js/*.js | sort -u > secrets/found.txt
```

#### 2.7.6 Crawl Multiple Pages

```javascript
const pages = ['/home', '/settings', '/billing', '/gpts', '/images', '/canvas'];
for (const path of pages) {
  const page = await context.newPage();
  await page.goto(`https://target.com${path}`, { waitUntil: 'networkidle', timeout: 30000 });
  // Collect per-page API calls, JS bundles, HTML
  await page.close();
}
```

#### 2.7.7 Key Findings dari Browser Crawling

Yang bisa didapatkan dari metode ini vs static crawling:
- **SPA routes** — React Router / Next.js routes yang gak keliatan di HTML statis
- **Authenticated API calls** — endpoint yang cuma muncul setelah login
- **GraphQL persisted queries** — operationName + SHA256 hash + variables
- **Realtime service keys** — Ably, Pusher, Socket.io configuration
- **Error tracking config** — Sentry DSN, Datadog RUM
- **Third-party integrations** — Stripe, Intercom, Zendesk config
- **WebSocket endpoints** — wss:// URLs untuk realtime features
- **OAuth client config** — client_id, redirect_uris, jwks_uri
- **Server-side env vars** — dari `__NEXT_DATA__` (terkadang ter-obfuscate, bisa dicoba di-decode)

#### 2.7.8 Tools Complement

| Tool | Kelebihan | Kekurangan |
|------|----------|------------|
| **Playwright** (metode ini) | JS render, auth session, capture XHR/JS | Lebih lambat, butuh resource |
| **katana** | Cepat,广度优先 | Gak render JS, gak capture API calls |
| **hakrawler** | Simple, integrasi tools lain | Sama seperti katana |
| **gau/waybackurls** | Historical URLs | Gak tau endpoint yang baru |

Gunakan kombinasi: **katana untuk cakupan luas** + **Playwright untuk deep authenticated crawling**.

---

### 2.8 JavaScript Analysis (Active Download + Static Analysis)

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

## Phase 6 — Vulnerability Discovery (via HexStrike AI)

> **Semua scanning vulnerability dirutekan melalui HexStrike AI** — gunakan AI-driven tool selection, parameter optimization, dan error recovery.

### 6.1 Smart Vulnerability Assessment (AI-Optimized)

```bash
# HexStrike AI — otomatis milih tools terbaik berdasarkan target profile
hexstrike_ai_vulnerability_assessment \
  target="$(head -1 http/live_urls.txt)" \
  focus_areas=web,api

# Atau pake intelligent smart scan — AI milihin tools + param
hexstrike_intelligent_smart_scan \
  target="$(head -1 http/live_urls.txt)" \
  objective=comprehensive \
  max_tools=10
```

### 6.2 Subdomain Takeover

```bash
# Via HexStrike AI nuclei
hexstrike_nuclei_scan \
  target=http/live_urls.txt \
  tags=takeover \
  severity=medium,high,critical \
  output=http/takeover.txt
```

### 6.3 CVE, Misconfig & API Security

```bash
# Comprehensive nuclei scan via HexStrike
hexstrike_nuclei_scan \
  target=http/live_urls.txt \
  tags=exposure,misconfig,cve,config,backup,disclosure,api,graphql,jwt \
  exclude_tags=ssl,tls,dos,fuzz,intrusive,token-spray,creds-stuffing,brute-force \
  severity=medium,high,critical \
  exclude_severity=info \
  output=http/nuclei_findings.txt

# API security audit via HexStrike
hexstrike_comprehensive_api_audit \
  base_url="https://$(head -1 subs/live_hosts.txt)" \
  output=http/api_audit.txt

# JWT analysis
hexstrike_jwt_analyzer \
  jwt_token="<token_ditemukan_di_js>" \
  output=http/jwt_analysis.txt

# IaC security (if using cloud infra)
hexstrike_checkov_iac_scan \
  directory=. \
  framework=terraform \
  output=http/checkov_results.json
```

### 6.4 CORS Misconfiguration

```bash
hexstrike_nuclei_scan \
  target=http/live_urls.txt \
  tags=cors \
  output=http/cors_findings.txt
```

### 6.5 Open Redirect

```bash
# Via HexStrike URL analysis
hexstrike_nuclei_scan \
  target=http/live_urls.txt \
  tags=redirect \
  severity=medium,high \
  output=http/open_redirect.txt

# Manual grep cadangan
grep -oE 'https?://[^"'"'"'<> ]*(redirect|return|continue|next|url|goto|dest|target)=https?://' \
  urls/all_urls_merged.txt | sort -u > urls/open_redirect_candidates.txt
```

### 6.6 XSS Scanning

```bash
# HexStrike AI — generate + test XSS payload
hexstrike_dalfox_xss_scan \
  url="$(head -1 urls/params.txt)" \
  mining_dom=true \
  mining_dict=true \
  blind=true

# Parameter fuzzing via HexStrike
hexstrike_http_intruder \
  url="$(head -1 urls/params.txt)" \
  method=GET \
  location=query \
  payloads='<script>alert(1)</script>,"><script>alert(1)</script>' \
  output=http/xss_findings.txt
```

### 6.7 SQL Injection & Command Injection

```bash
# SQL injection via HexStrike
hexstrike_sqlmap_scan \
  url="$(head -1 urls/params_merged.txt)" \
  additional_args="--batch --level=2 --risk=2 --random-agent" \
  output=http/sqli_findings.txt

# Advanced RCE payload generation
hexstrike_advanced_payload_generation \
  attack_type=rce \
  target_context="linux,webapp" \
  evasion_level=advanced
```

### 6.8 Business Logic & Authentication Testing

```bash
# HexStrike AI — workflow-based testing
hexstrike_bugbounty_authentication_bypass_testing \
  target_url="https://$(head -1 subs/live_hosts.txt)/login" \
  auth_type=form,jwt,oauth

hexstrike_bugbounty_business_logic_testing \
  domain="$(head -1 seeds.txt)" \
  program_type=web
```

### 6.9 File Upload Testing

```bash
# HexStrike AI — file upload bypass techniques
hexstrike_bugbounty_file_upload_testing \
  target_url="https://$(head -1 subs/live_hosts.txt)/upload"
```

### 6.10 Advanced Attack Chain (AI-Generated)

```bash
# HexStrike AI — bikin attack chain otomatis
hexstrike_create_attack_chain_ai \
  target="https://$(head -1 subs/live_hosts.txt)" \
  objective=comprehensive

# Discover multi-stage attack vectors
hexstrike_discover_attack_chains \
  target_software="$(head -1 http/tech_fingerprint.txt)" \
  attack_depth=3
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

### 7.1 Consolidated Findings (via HexStrike)

```bash
# Generate report via HexStrike AI
hexstrike_create_vulnerability_report \
  vulnerabilities="$(cat http/nuclei_findings.txt http/xss_findings.txt 2>/dev/null)" \
  target="$(head -1 seeds.txt)" \
  scan_type=comprehensive

# Scan summary via HexStrike
hexstrike_create_scan_summary \
  target="$(head -1 seeds.txt)" \
  tools_used="nuclei,dalfox,sqlmap,jaeles,ffuf,katana,httpx,subfinder" \
  findings="$(wc -l < http/nuclei_findings.txt 2>/dev/null || echo 0)"

# Manual consolidated report
{
  echo "# Recon Report — ${PROGRAM_NAME} (HexStrike AI Powered)"
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
