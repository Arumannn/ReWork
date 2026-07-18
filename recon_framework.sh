#!/usr/bin/env bash
# =============================================================================
#  Universal Recon Framework
#  .env-Driven | Web + Mobile Bug Bounty Recon Pipeline
# =============================================================================
#  USAGE:
#    ./recon_framework.sh [OPTIONS]
#
#  OPTIONS:
#    --check-tools       Check all required tools before running
#    --phase N           Start from phase N (1-7), skip previous phases
#    --cookie <value>    Set auth cookie (e.g. "session=abc123")
#    --header <value>    Set custom auth header (e.g. "Authorization: Bearer xyz")
#    --help              Show this help message
#
#  .env TEMPLATE:
#    Copy .env.template to .env and fill in your target's details.
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; RESET='\033[0m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'

dbg()   { [ "${VERBOSE_LEVEL:-0}" -ge 1 ] && echo -e "${MAGENTA}[DBG]${RESET} $*" || true; }
log()   { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${ORANGE}[!]${RESET} $*"; }
crit()  { echo -e "${RED}[CRIT]${RESET} ${BOLD}$*${RESET}"; }
header(){ echo -e "\n${BOLD}${MAGENTA}═══ $* ═══${RESET}"; }

# ── Range helper ───────────────────────────────────────────────────────────────
should_run_phase() {
  [ "$1" -ge "${RANGE_START:-1}" ] && [ "$1" -le "${RANGE_END:-7}" ] || return 1
  local ex; for ex in ${EXCLUDED_PHASES:-}; do [ "$1" = "$ex" ] && return 1; done
  return 0
}

# ── Phase Markers ──────────────────────────────────────────────────────────────
phase_marker()   { echo "${WORKDIR}/.phase_${1}_done"; }
phase_is_done()  { [ -f "$(phase_marker "$1")" ]; }
mark_phase_done(){
  touch "$(phase_marker "$1")"
  dbg "Phase $1 marked complete ($(phase_marker "$1"))"
}

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="${SCRIPT_DIR}"
PROGRAM="$(basename "$SCRIPT_DIR")"
PROGRAM_NAME="${PROGRAM}"
START_PHASE=1
PHASE_EXPLICIT=false
RANGE_START=1
RANGE_END=7
EXCLUDED_PHASES=""
CHECK_TOOLS_ONLY=false
RESUME=false
VERBOSE_LEVEL=0
CLI_COOKIE=""
CLI_HEADER=""
CLI_TARGET=""
CLI_TARGETS_FILE=""
CLI_OUTPUT=""
CLI_THREADS=""
CLI_RATE=""
CLI_EXCLUDE=""

# ── Help ──────────────────────────────────────────────────────────────────────
show_help() {
  cat <<EOF
${BOLD}Universal Recon Framework${RESET} — .env-Driven Bug Bounty Recon Pipeline

${BOLD}USAGE:${RESET}
  ./recon_framework.sh [OPTIONS]

${BOLD}OPTIONS:${RESET}
  --check-tools       Check all required/optional tools before running
  --phase N           Start from phase N (1-7), skip previous phases
  --resume            Auto-skip completed phases (by marker files)
  --range <N-M>       Run specific phase range (e.g. --range 2-4)
  --target <domain>   Target domain(s), space-separated (overrides .env)
  --targets-file <file>  File with targets (one/line, overrides .env SEED_DOMAINS)
  --output <dir>      Custom output directory (overrides .env WORKDIR)
  --threads <n>       Override thread count (overrides .env THREADS)
  --rate <n>          Override rate limit (sets RL_LIGHT/MEDIUM/AGGRESSIVE)
  --exclude <pattern> Exclude subdomain pattern (adds to OUT_OF_SCOPE)
  --exclude-phase <N> Skip specific phase(s), comma-separated (e.g. "3,4")
  --cookie <value>    Set auth cookie (e.g. "session=abc123")
  --header <value>    Set custom auth header (e.g. "Authorization: Bearer xyz")
  -v                  Verbose per-fase (tampilkan detail setiap fase & tool)
  -vv                 Verbose per-output (tampilkan semua raw output tool + debug)
  --verbose           Same as -v
  --help              Show this help message

${BOLD}PHASES:${RESET}
  1  Passive Web Recon       OSINT (zero traffic to target)
  2  Active Web Recon        Probing & crawling (direct traffic)
  3  Passive Mobile Recon    Static APK/IPA analysis
  4  Active Mobile Recon     Dynamic runtime analysis
  5  Web ↔ Mobile Correlation
  6  Vulnerability Discovery Scanning
  7  Reporting               Consolidated findings

${BOLD}.env FILE:${RESET}
  Copy .env.template to .env and fill in target details before running.

${BOLD}EXAMPLES:${RESET}
  ./recon_framework.sh                            Run full pipeline
  ./recon_framework.sh --phase 3                  Start from mobile recon
  ./recon_framework.sh --range 2-4                Run phases 2, 3, and 4 only
  ./recon_framework.sh --resume                   Resume from last completed phase
  ./recon_framework.sh --target example.com       Set target from CLI (no .env needed)
  ./recon_framework.sh --output /tmp/recon        Custom output directory
  ./recon_framework.sh --threads 10 --rate 20     Override concurrency
  ./recon_framework.sh --exclude 'staging\.'      Exclude subdomains matching pattern
  ./recon_framework.sh --cookie "sid=abc123"      Use auth cookie
  ./recon_framework.sh --check-tools              Only check tools
EOF
  exit 0
}

# ── CLI Parsing ───────────────────────────────────────────────────────────────
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --check-tools) CHECK_TOOLS_ONLY=true; shift ;;
      --phase)
        if [ -z "${2:-}" ] || ! [[ "$2" =~ ^[1-7]$ ]]; then
          crit "--phase requires a number between 1-7"; exit 1
        fi
        START_PHASE="$2"; PHASE_EXPLICIT=true; shift 2 ;;
      --resume) RESUME=true; shift ;;
      --range)
        if [ -z "${2:-}" ] || ! [[ "$2" =~ ^([1-7])-([1-7])$ ]]; then
          crit "--range requires format N-M (e.g. 2-4)"; exit 1
        fi
        RANGE_START="${BASH_REMATCH[1]}"
        RANGE_END="${BASH_REMATCH[2]}"
        START_PHASE=$RANGE_START
        dbg "Phase range: $RANGE_START → $RANGE_END"
        shift 2 ;;
      --target)
        if [ -z "${2:-}" ]; then crit "--target requires a value"; exit 1; fi
        CLI_TARGET="$2"; shift 2
        while [ $# -gt 0 ] && [[ "$1" != -* ]]; do
          CLI_TARGET="$CLI_TARGET $1"; shift
        done ;;
      --targets-file)
        if [ -z "${2:-}" ] || [ ! -f "$2" ]; then crit "--targets-file requires a valid file"; exit 1; fi
        CLI_TARGETS_FILE="$2"; shift 2 ;;
      --output)
        if [ -z "${2:-}" ]; then crit "--output requires a value"; exit 1; fi
        CLI_OUTPUT="$2"; shift 2 ;;
      --threads)
        if [ -z "${2:-}" ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
          crit "--threads requires a number"; exit 1
        fi
        CLI_THREADS="$2"; shift 2 ;;
      --rate)
        if [ -z "${2:-}" ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
          crit "--rate requires a number"; exit 1
        fi
        CLI_RATE="$2"; shift 2 ;;
      --exclude)
        if [ -z "${2:-}" ]; then crit "--exclude requires a value"; exit 1; fi
        CLI_EXCLUDE="$2"; shift 2 ;;
      --exclude-phase)
        if [ -z "${2:-}" ] || ! [[ "$2" =~ ^[1-7](,[1-7])*$ ]]; then
          crit "--exclude-phase requires comma-separated phase numbers (e.g. 3,4)"; exit 1
        fi
        EXCLUDED_PHASES="${2//,/ }"
        dbg "Excluded phases: $EXCLUDED_PHASES"
        shift 2 ;;
      --cookie)
        if [ -z "${2:-}" ]; then crit "--cookie requires a value"; exit 1; fi
        CLI_COOKIE="$2"; shift 2 ;;
      --header)
        if [ -z "${2:-}" ]; then crit "--header requires a value"; exit 1; fi
        CLI_HEADER="$2"; shift 2 ;;
      -v)
        VERBOSE_LEVEL=1; shift
        if [ $# -gt 0 ] && [ "$1" = "-v" ]; then
          VERBOSE_LEVEL=2; shift
        fi ;;
      --verbose) VERBOSE_LEVEL=1; shift ;;
      -vv) VERBOSE_LEVEL=2; shift ;;
      --help) show_help ;;
      *) crit "Unknown option: $1"; echo "Use --help for usage."; exit 1 ;;
    esac
  done
}

# ── Load .env ─────────────────────────────────────────────────────────────────
load_env() {
  local env_file="${WORKDIR}/.env"
  if [ -f "$env_file" ]; then
    set -a
    source "$env_file"
    set +a
  else
    warn ".env not found at ${env_file}"
    warn "Copy .env.template to .env and configure before running."
    warn "Continuing with defaults..."
  fi

  # Set defaults
  : "${RL_LIGHT:=10}" "${RL_MEDIUM:=50}" "${RL_AGGRESSIVE:=100}" "${THREADS:=5}"
  : "${SCOPE_WILDCARD:=}" "${OUT_OF_SCOPE:=}"
  : "${WORKDIR:=${SCRIPT_DIR}}"
  : "${SEED_DOMAINS:=}"
  : "${TARGETS_FILE:=}"
  : "${GITHUB_TOKEN:=}"
  : "${SHODAN_API_KEY:=}"

  # Build auth args from env + CLI
  AUTH_ARGS=()
  if [ -n "${CLI_COOKIE}" ]; then
    AUTH_ARGS+=(-H "Cookie: ${CLI_COOKIE}")
  elif [ -n "${AUTH_COOKIE:-}" ]; then
    AUTH_ARGS+=(-H "Cookie: ${AUTH_COOKIE}")
  fi
  if [ -n "${CLI_HEADER}" ]; then
    AUTH_ARGS+=(-H "${CLI_HEADER}")
  elif [ -n "${AUTH_HEADER:-}" ]; then
    AUTH_ARGS+=(-H "${AUTH_HEADER}")
  fi

  WORKDIR="$(cd "$WORKDIR" 2>$NULL && pwd || echo "$PWD")"

  # ── Apply CLI overrides ──
  # Target priority: --target > --targets-file > .env TARGETS_FILE > .env SEED_DOMAINS
  if [ -n "$CLI_TARGET" ]; then
    SEED_DOMAINS="$CLI_TARGET"
    SCOPE_WILDCARD="\\.($(echo "$CLI_TARGET" | tr ' ' '|' | sed 's/\./\\./g'))$"
    dbg "CLI --target: $CLI_TARGET (scope: $SCOPE_WILDCARD)"
  elif [ -n "$CLI_TARGETS_FILE" ]; then
    SEED_DOMAINS="$(tr '\n' ' ' < "$CLI_TARGETS_FILE" | sed 's/  */ /g; s/^ *//; s/ *$//')"
    SCOPE_WILDCARD=""
    dbg "CLI --targets-file: $CLI_TARGETS_FILE ($(echo "$SEED_DOMAINS" | wc -w) targets)"
  elif [ -n "${TARGETS_FILE:-}" ] && [ -f "$TARGETS_FILE" ]; then
    SEED_DOMAINS="$(tr '\n' ' ' < "$TARGETS_FILE" | sed 's/  */ /g; s/^ *//; s/ *$//')"
    SCOPE_WILDCARD=""
    dbg ".env TARGETS_FILE: $TARGETS_FILE ($(echo "$SEED_DOMAINS" | wc -w) targets)"
  fi
  if [ -n "$CLI_OUTPUT" ]; then
    WORKDIR="$CLI_OUTPUT"
    mkdir -p "$WORKDIR"
    dbg "CLI output: $WORKDIR"
  fi
  if [ -n "$CLI_THREADS" ]; then
    THREADS="$CLI_THREADS"
    dbg "CLI threads: $THREADS"
  fi
  if [ -n "$CLI_RATE" ]; then
    RL_LIGHT="$CLI_RATE"
    RL_MEDIUM=$((CLI_RATE * 3))
    RL_AGGRESSIVE=$((CLI_RATE * 5))
    dbg "CLI rate: $CLI_RATE (L=$RL_LIGHT M=$RL_MEDIUM A=$RL_AGGRESSIVE)"
  fi
  if [ -n "$CLI_EXCLUDE" ]; then
    OUT_OF_SCOPE="${OUT_OF_SCOPE:+$OUT_OF_SCOPE\n}${CLI_EXCLUDE}"
    dbg "CLI exclude: $CLI_EXCLUDE"
  fi

  ok "Program : ${PROGRAM}"
  ok "Workdir : ${WORKDIR}"
  ok "Rate    : L=${RL_LIGHT} M=${RL_MEDIUM} A=${RL_AGGRESSIVE}/s"
  ok "Threads : ${THREADS}"
  [ ${#AUTH_ARGS[@]} -gt 0 ] && ok "Auth    : ${AUTH_ARGS[*]}" || true
}

# ── Tool Check ────────────────────────────────────────────────────────────────
check_tools() {
  header "Tool Check"

  local required=(
    curl jq sort uniq tr dig xargs sha256sum python3 grep awk sed flock
  )
  local optional_standard=(
    subfinder gau httpx-pd katana ffuf amass nuclei nmap dalfox sqlmap
    wafw00f gobuster feroxbuster hakrawler arjun jsluice trufflehog
    js-beautify
  )
  local optional_new=(
    wappalyzer-cli shodan
  )

  local missing_req=() missing_opt=()

  log "Checking required tools..."
  for t in "${required[@]}"; do
    if command -v "$t" &>/dev/null; then
      ok "  ${t}"
    else
      missing_req+=("$t")
    fi
  done

  log "Checking standard recon tools..."
  for t in "${optional_standard[@]}"; do
    if command -v "$t" &>/dev/null; then
      ok "  ${t}"
    else
      missing_opt+=("$t")
    fi
  done

  log "Checking new integrated tools..."
  for t in "${optional_new[@]}"; do
    if command -v "$t" &>/dev/null; then
      ok "  ${t}"
    else
      missing_opt+=("$t")
    fi
  done

  if [ ${#missing_req[@]} -gt 0 ]; then
    crit "MISSING REQUIRED: ${missing_req[*]}"; exit 1
  fi

  if [ ${#missing_opt[@]} -gt 0 ]; then
    warn "Optional tools not found: ${missing_opt[*]}"
    warn "Some features will be skipped."
  fi

  # Check SHODAN_API_KEY
  if command -v shodan &>/dev/null; then
    if shodan info 2>$NULL; then
      ok "  shodan: API key valid"
    else
      warn "  shodan: no API key or quota exhausted"
    fi
  fi

  ok "All required tools present."
}

# ── Directory Setup ───────────────────────────────────────────────────────────
setup_dirs() {
  mkdir -p "$WORKDIR"/{subs,ports,http,urls,js/{raw,maps,beautified,unpacked,findings/{endpoints,secrets,xss,csrf,websocket,graphql,auth,payment,wallet,idor}},mobile/{android,ios},api,auth,correlation,github,dorks}
}

# ── Phase 1: Passive Web Recon ────────────────────────────────────────────────
phase1_passive_web() {
  header "Phase 1 — Passive Web Recon"

  if [ -z "$SEED_DOMAINS" ]; then
    crit "SEED_DOMAINS is empty! Set in .env"; return 1
  fi

  echo "$SEED_DOMAINS" | tr ' ' '\n' | grep -v '^$' > seeds.txt
  ok "Seed domains: $(tr '\n' ' ' < seeds.txt)"

  # ── 1.1 Subdomain Enumeration (Passive) ──
  log "1.1 — Passive Subdomain Enumeration"

  if command -v subfinder &>/dev/null; then
    log "  Running subfinder..."
    subfinder -dL seeds.txt -all -v 2>$NULL >> subs/subfinder.txt || true
    sort -u subs/subfinder.txt -o subs/subfinder.txt 2>$NULL || true
    ok "  subfinder done: $(wc -l < subs/subfinder.txt 2>$NULL || echo 0)"
  fi

  if command -v amass &>/dev/null; then
    log "  Running amass intel..."
    while read -r d; do
      amass intel -whois -d "$d" 2>$NULL >> subs/amass_intel.txt || true
    done < seeds.txt
    sort -u subs/amass_intel.txt -o subs/amass_intel.txt 2>$NULL || true
  fi

  log "  Certificate Transparency (crt.sh)..."
  while read -r d; do
    curl -s --max-time 30 --retry 2 \
      "https://crt.sh/?q=%25.${d}&output=json" 2>$NULL \
      | jq -r '.[].name_value' 2>$NULL || true
  done < seeds.txt | sed 's/\*\.//g' >> subs/crtsh.txt || true
  sort -u subs/crtsh.txt -o subs/crtsh.txt 2>$NULL || true

  log "  urlscan.io..."
  while read -r d; do
    curl -s --max-time 30 \
      "https://urlscan.io/api/v1/search/?q=domain:${d}&size=1000" 2>$NULL \
      | jq -r '.results[]?.page.domain' 2>$NULL || true
  done < seeds.txt >> subs/urlscan.txt || true
  sort -u subs/urlscan.txt -o subs/urlscan.txt 2>$NULL || true

  # Merge all subdomains
  cat subs/subfinder.txt subs/crtsh.txt subs/amass_intel.txt subs/urlscan.txt \
    2>$NULL | sort -u >> subs/all_subs_raw.txt || true
  sort -u subs/all_subs_raw.txt -o subs/all_subs_raw.txt 2>$NULL || true
  ok "Total subdomains collected: $(wc -l < subs/all_subs_raw.txt 2>$NULL || echo 0)"

  # ── 1.2 Filter Scope ──
  log "1.2 — Filtering Scope"
  if [ -n "$SCOPE_WILDCARD" ]; then
    grep -E "$SCOPE_WILDCARD" subs/all_subs_raw.txt >> subs/inscope_subs.txt 2>$NULL || true
  else
    cp subs/all_subs_raw.txt subs/inscope_subs.txt 2>$NULL || true
  fi

  if [ -n "${SCOPE_EXPLICIT:-}" ]; then
    echo "$SCOPE_EXPLICIT" >> subs/inscope_subs.txt
  fi

  if [ -n "$OUT_OF_SCOPE" ]; then
    echo "$OUT_OF_SCOPE" | grep -vFf - subs/inscope_subs.txt \
      > subs/inscope_subs.tmp 2>$NULL || true
    mv subs/inscope_subs.tmp subs/inscope_subs.txt 2>$NULL || true
  fi

  sort -u subs/inscope_subs.txt -o subs/inscope_subs.txt 2>$NULL || true
  ok "In-scope subdomains: $(wc -l < subs/inscope_subs.txt 2>$NULL || echo 0)"

  # ── 1.3 Historical URLs ──
  log "1.3 — Historical URL Gathering"

  if command -v gau &>/dev/null; then
    log "  Running gau..."
    gau -subs < seeds.txt 2>$NULL >> urls/gau.txt || true
    sort -u urls/gau.txt -o urls/gau.txt 2>$NULL || true
  fi

  log "  Wayback Machine CDX..."
  while read -r d; do
    curl -s --max-time 45 --retry 1 \
      "https://web.archive.org/cdx/search/cdx?url=${d}&matchType=domain&output=text&fl=original&collapse=urlkey&limit=10000" \
      2>$NULL >> urls/wayback_raw.txt || true
  done < seeds.txt

  cat urls/gau.txt urls/wayback_raw.txt 2>$NULL | sort -u >> urls/all_urls.txt || true
  sort -u urls/all_urls.txt -o urls/all_urls.txt 2>$NULL || true
  grep '=' urls/all_urls.txt >> urls/params.txt 2>$NULL || true
  grep -iE '\.m?js($|\?)' urls/all_urls.txt >> urls/js_urls.txt 2>$NULL || true
  ok "Historical URLs: $(wc -l < urls/all_urls.txt 2>$NULL || echo 0)"

  # ── 1.4 URL Categorization ──
  log "1.4 — URL Categorization"
  grep -iE 'auth|login|signin|oauth|token|session|2fa|mfa|verify|sso' urls/all_urls.txt \
    >> urls/auth_urls.txt 2>$NULL || true
  grep -iE 'api|v[0-9]|rest|graphql|grpc|bff|gateway' urls/all_urls.txt \
    >> urls/api_urls.txt 2>$NULL || true
  grep -iE 'payment|checkout|billing|invoice|refund|wallet|coupon|promo' urls/all_urls.txt \
    >> urls/payment_urls.txt 2>$NULL || true
  grep -iE 'admin|internal|staff|backoffice|dashboard|management' urls/all_urls.txt \
    >> urls/admin_urls.txt 2>$NULL || true
  grep -iE 'user|account|profile|customer' urls/all_urls.txt \
    >> urls/user_urls.txt 2>$NULL || true

  ok "  Auth: $(wc -l < urls/auth_urls.txt 2>$NULL || echo 0)"
  ok "  API:  $(wc -l < urls/api_urls.txt 2>$NULL || echo 0)"
  ok "  Payment: $(wc -l < urls/payment_urls.txt 2>$NULL || echo 0)"

  # ── 1.5 Technology Fingerprinting (Passive) ──
  log "1.5 — Technology Fingerprinting"

  if command -v wafw00f &>/dev/null; then
    log "  WAF detection via wafw00f..."
    while read -r h; do
      wafw00f "https://${h}" -a 2>$NULL || true
    done < <(head -20 subs/inscope_subs.txt 2>$NULL) \
      >> http/waf_results.txt || true
  fi

  if command -v wappalyzer-cli &>/dev/null; then
    log "  Tech detection via wappalyzer-cli..."
    while read -r h; do
      wappalyzer-cli -target "https://${h}" -silent 2>$NULL || true
    done < <(head -20 subs/inscope_subs.txt 2>$NULL) \
      >> http/wappalyzer_results.txt || true
  fi

  # ── 1.6 Shodan Recon ──
  log "1.6 — Shodan Reconnaissance"
  if command -v shodan &>/dev/null; then
    while read -r d; do
      shodan search "hostname:${d}" 2>$NULL >> subs/shodan_hosts.txt || true
      shodan domain "$d" 2>$NULL >> subs/shodan_domain.txt || true
    done < seeds.txt
    sort -u subs/shodan_hosts.txt -o subs/shodan_hosts.txt 2>$NULL || true
    ok "  Shodan: $(wc -l < subs/shodan_hosts.txt 2>$NULL || echo 0) findings"
  else
    warn "  shodan CLI not available — skipping"
  fi

  # ── 1.7 Google Dorking ──
  log "1.7 — Google Dork Generation"
  while read -r d; do
    cat >> dorks/google_dorks.txt <<EOF
site:${d} intitle:login
site:${d} filetype:env
site:${d} filetype:sql
site:${d} filetype:log
site:${d} inurl:admin
site:${d} inurl:api
site:${d} inurl:wp-admin
site:${d} inurl:backup
site:${d} intitle:"index of"
site:${d} ext:json
site:${d} ext:xml
site:${d} ext:pdf confidential
site:${d} "bucket" "s3"
site:${d} "password" filetype:txt
site:${d} "token" filetype:json
site:${d} "api_key"
site:${d} "secret"
site:${d} "-----BEGIN"
site:${d} "db_password"
site:${d} "AWS_ACCESS_KEY"
EOF
  done < seeds.txt
  ok "  Google dorks saved to dorks/google_dorks.txt ($(wc -l < dorks/google_dorks.txt) queries)"

  # ── 1.8 GitHub Dorking ──
  log "1.8 — GitHub Dorking"
  if [ -n "$GITHUB_TOKEN" ]; then
    mkdir -p github
    while read -r d; do
      local queries=("${d}+api+key" "${d}+secret" "${d}+token" "${d}+password" "${d}+.env")
      for q in "${queries[@]}"; do
        curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
          "https://api.github.com/search/code?q=${q}&per_page=50" 2>$NULL \
          | jq -r '.items[]?.html_url' 2>$NULL >> github/leak_candidates.txt || true
      done
    done < seeds.txt
    sort -u github/leak_candidates.txt -o github/leak_candidates.txt 2>$NULL || true
    ok "  GitHub leak candidates: $(wc -l < github/leak_candidates.txt 2>$NULL || echo 0)"
  else
    log "  GITHUB_TOKEN not set — generating dork queries only"
    while read -r d; do
      cat >> dorks/github_dorks.txt <<EOF
"${d}" "api_key"
"${d}" "secret"
"${d}" "token"
"${d}" "password"
"${d}" ".env"
"${d}" "AWS_ACCESS_KEY"
"${d}" "-----BEGIN RSA PRIVATE KEY"
"${d}" "mongodb://"
org:"${d}" password
org:"${d}" secret
EOF
    done < seeds.txt
    ok "  GitHub dorks saved to dorks/github_dorks.txt"
  fi

  ok "Phase 1 — Passive Web Recon complete!"
  mark_phase_done 1
}

# ── Phase 2: Active Web Recon ─────────────────────────────────────────────────
phase2_active_web() {
  header "Phase 2 — Active Web Recon"

  if [ ! -f subs/inscope_subs.txt ] || [ ! -s subs/inscope_subs.txt ]; then
    crit "No in-scope subdomains found. Run Phase 1 first."; return 1
  fi

  # ── 2.1 DNS Resolution ──
  log "2.1 — DNS Resolution"
  while read -r h; do
    ip=$(dig +short "$h" A 2>$NULL | grep -E '^[0-9]' | head -1)
    [ -n "$ip" ] && echo "$h $ip" >> subs/resolved.txt
  done < subs/inscope_subs.txt
  sort -u subs/resolved.txt -o subs/resolved.txt 2>$NULL || true
  awk '{print $1}' subs/resolved.txt 2>$NULL | sort -u >> subs/live_hosts.txt || true
  sort -u subs/live_hosts.txt -o subs/live_hosts.txt 2>$NULL || true
  ok "Resolved IPs: $(wc -l < subs/resolved.txt 2>$NULL || echo 0)"

  # ── 2.2 HTTP Probing ──
  log "2.2 — HTTP Probing"
  if command -v httpx-pd &>/dev/null; then
    log "  httpx-pd with tech detection..."
    httpx-pd -l subs/live_hosts.txt -rl "$RL_MEDIUM" -v \
      "${AUTH_ARGS[@]}" \
      -sc -title -td -location -cl -server -probe \
      2>$NULL >> http/httpx_full.txt || true

    log "  httpx-pd -tech (active subdomain check)..."
    httpx-pd -l subs/live_hosts.txt -rl "$RL_MEDIUM" -silent \
      "${AUTH_ARGS[@]}" -tech-detect \
      2>$NULL >> http/httpx_tech.txt || true

    httpx-pd -l subs/live_hosts.txt -rl "$RL_MEDIUM" -silent \
      "${AUTH_ARGS[@]}" \
      2>$NULL >> http/live_urls.txt || true

    sort -u http/live_urls.txt -o http/live_urls.txt 2>$NULL || true
    sort -u http/httpx_full.txt -o http/httpx_full.txt 2>$NULL || true
    ok "  Live URLs: $(wc -l < http/live_urls.txt 2>$NULL || echo 0)"
  else
    warn "  httpx-pd not available — using curl probe"
    while read -r h; do
      for scheme in https http; do
        code=$(curl -skL -o /dev/null -w '%{http_code}' --max-time 5 \
          "${AUTH_ARGS[@]}" "${scheme}://${h}/" 2>$NULL || true)
        [ "$code" != "000" ] && echo "${scheme}://${h}" >> http/live_urls.txt
      done
    done < subs/live_hosts.txt
    sort -u http/live_urls.txt -o http/live_urls.txt 2>$NULL || true
  fi

  # ── 2.3 Port Scanning ──
  log "2.3 — Port Scanning"
  awk '{print $2}' subs/resolved.txt | sort -u > ports/ips.txt
  local PORTS="21,22,25,53,80,110,143,443,465,587,993,995,1080,2082,2083,3000,4443,5000,5432,6379,7001,8000,8008,8080,8081,8443,8888,9000,9200,11211,27017,30000"

  if command -v nmap &>/dev/null; then
    log "  Running nmap on resolved IPs..."
    nmap -iL ports/ips.txt -p "$PORTS" -sV --open -T3 \
      --max-retries 1 --host-timeout 3m --max-rate 10 -v \
      -oA ports/nmap_all 2>$NULL || true
    ok "  nmap scan complete"
  else
    warn "  nmap not available — skipping port scan"
  fi

  # ── 2.4 Web Crawling ──
  log "2.4 — Web Crawling"
  if command -v katana &>/dev/null; then
    log "  Running katana..."
    katana -list http/live_urls.txt -rl "$RL_MEDIUM" -jc -c "$THREADS" \
      -p 10 -d 3 -timeout 10 "${AUTH_ARGS[@]}" \
      2>$NULL >> urls/katana.txt || true
    sort -u urls/katana.txt -o urls/katana.txt 2>$NULL || true
  fi

  if command -v hakrawler &>/dev/null; then
    log "  Running hakrawler..."
    while read -r u; do
      echo "$u"
    done < http/live_urls.txt | hakrawler -d 3 -subs -u \
      2>$NULL >> urls/hakrawler.txt || true
    sort -u urls/hakrawler.txt -o urls/hakrawler.txt 2>$NULL || true
  fi

  # Merge URLs
  cat urls/katana.txt urls/hakrawler.txt 2>$NULL | sort -u \
    >> urls/all_urls_merged.txt || true
  sort -u urls/all_urls_merged.txt -o urls/all_urls_merged.txt 2>$NULL || true
  grep '=' urls/all_urls_merged.txt | sort -u >> urls/params_merged.txt || true
  ok "Merged URLs: $(wc -l < urls/all_urls_merged.txt 2>$NULL || echo 0)"

  # ── 2.5 Content Discovery ──
  log "2.5 — Content Discovery"
  local WORDS="api|v1|v2|v3|graphql|rest|auth|login|signin|oauth|token|session|user|admin|internal|dashboard|health|status|metrics|swagger|docs|openapi|webhook|callback|config|settings|payment|checkout|wallet|static|assets|uploads|download|.env|.git|backup|db|migrations|logs|debug|test"

  if command -v ffuf &>/dev/null; then
    log "  Running ffuf content discovery..."
    while read -r h; do
      ffuf -u "https://${h}/FUZZ" -w <(echo "$WORDS" | tr '|' '\n') \
        -t "$THREADS" -rate "$RL_AGGRESSIVE" -c -fc 404 \
        2>$NULL >> http/ffuf_results.txt || true
    done < <(head -20 subs/live_hosts.txt 2>$NULL)
    sort -u http/ffuf_results.txt -o http/ffuf_results.txt 2>$NULL || true
    ok "  FFuf results: $(wc -l < http/ffuf_results.txt 2>$NULL || echo 0)"
  fi

  if command -v feroxbuster &>/dev/null; then
    log "  Running feroxbuster..."
    while read -r h; do
      feroxbuster -u "https://${h}" -w <(echo "$WORDS" | tr '|' '\n') \
        -t "$THREADS" --rate-limit "$RL_MEDIUM" --silent \
        2>$NULL >> http/feroxbuster_results.txt || true
    done < <(head -10 subs/live_hosts.txt 2>$NULL)
    sort -u http/feroxbuster_results.txt -o http/feroxbuster_results.txt 2>$NULL || true
  fi

  # ── 2.6 Hidden Parameter Discovery ──
  log "2.6 — Hidden Parameter Discovery"
  if command -v arjun &>/dev/null; then
    log "  Running arjun..."
    while read -r ep; do
      arjun -u "$ep" --method GET --threads 5 --rate-limit "$RL_LIGHT" \
        2>$NULL >> api/arjun_params.txt || true
    done < <(head -30 urls/api_urls.txt 2>$NULL)
    sort -u api/arjun_params.txt -o api/arjun_params.txt 2>$NULL || true
  fi

  ok "Phase 2 — Active Web Recon complete!"
  mark_phase_done 2
}

# ── Phase 3: Passive Mobile Recon ─────────────────────────────────────────────
phase3_mobile_passive() {
  header "Phase 3 — Passive Mobile Recon"

  # ── 3.1 Android APK Analysis ──
  if [ -n "${ANDROID_PACKAGES:-}" ]; then
    log "3.1 — Android APK Analysis"
    mkdir -p mobile/android/{decompiled,source,reports}

    for pkg in $ANDROID_PACKAGES; do
      local apk_path="mobile/android/${pkg}.apk"
      [ ! -f "$apk_path" ] && warn "  APK not found: ${apk_path}" && continue

      if command -v apktool &>/dev/null; then
        log "  Decompiling ${pkg} with apktool..."
        apktool d -f -o "mobile/android/decompiled/${pkg}" "$apk_path" \
          2>$NULL || true
      fi

      if command -v jadx &>/dev/null; then
        log "  Decompiling ${pkg} with jadx..."
        jadx -d "mobile/android/source/${pkg}" "$apk_path" 2>$NULL || true
      fi

      log "  Extracting URLs from ${pkg}..."
      strings "$apk_path" | grep -iE 'https?://' \
        | grep -v 'android\.com\|googleapis\|googlesyndication' \
        >> "mobile/android/urls_${pkg}.txt" || true
      sort -u "mobile/android/urls_${pkg}.txt" -o "mobile/android/urls_${pkg}.txt" 2>$NULL || true

      log "  Extracting secrets from ${pkg}..."
      strings "$apk_path" | grep -iE 'api[_-]?key|token|secret|password|bearer|firebase|supabase' \
        >> "mobile/android/secrets_${pkg}.txt" || true
      sort -u "mobile/android/secrets_${pkg}.txt" -o "mobile/android/secrets_${pkg}.txt" 2>$NULL || true

      log "  Firebase discovery..."
      strings "$apk_path" | grep -iE 'firebase|firestore|realtime.*database|\.appspot\.com' \
        >> "mobile/android/firebase_${pkg}.txt" || true
      sort -u "mobile/android/firebase_${pkg}.txt" -o "mobile/android/firebase_${pkg}.txt" 2>$NULL || true
    done
  else
    log "3.1 — ANDROID_PACKAGES not set, skipping"
  fi

  # ── 3.2 iOS IPA Analysis ──
  if [ -n "${IOS_BUNDLE_IDS:-}" ]; then
    log "3.2 — iOS IPA Analysis"
    mkdir -p mobile/ios/{decrypted,source,reports}

    for bundle in $IOS_BUNDLE_IDS; do
      local ipa_path="mobile/ios/${bundle}.ipa"
      [ ! -f "$ipa_path" ] && warn "  IPA not found: ${ipa_path}" && continue

      unzip -o "$ipa_path" -d "mobile/ios/decrypted/${bundle}" 2>$NULL || true
      local main_bin
      main_bin=$(find "mobile/ios/decrypted/${bundle}" -type f -perm +111 \
        -name "${bundle}" 2>$NULL | head -1)

      if [ -n "$main_bin" ]; then
        strings "$main_bin" | grep -iE 'https?://' \
          >> "mobile/ios/urls_${bundle}.txt" || true
        sort -u "mobile/ios/urls_${bundle}.txt" -o "mobile/ios/urls_${bundle}.txt" 2>$NULL || true
      fi
    done
  else
    log "3.2 — IOS_BUNDLE_IDS not set, skipping"
  fi

  # ── 3.3 Mobile API Endpoint Inventory ──
  log "3.3 — Mobile API Endpoint Inventory"
  cat mobile/android/urls_*.txt mobile/ios/urls_*.txt 2>$NULL \
    | grep -iE '/api|/v[0-9]|/graphql|/rest|/auth|/oauth|/token|/payment|/wallet|/user|/account' \
    >> mobile/all_mobile_endpoints.txt || true
  sort -u mobile/all_mobile_endpoints.txt -o mobile/all_mobile_endpoints.txt 2>$NULL || true
  ok "Mobile endpoints: $(wc -l < mobile/all_mobile_endpoints.txt 2>$NULL || echo 0)"

  ok "Phase 3 — Passive Mobile Recon complete!"
  mark_phase_done 3
}

# ── Phase 4: Active Mobile Recon ──────────────────────────────────────────────
phase4_mobile_active() {
  header "Phase 4 — Active Mobile Recon"
  log "Phase 4 requires device (adb) and Frida setup."
  log "Run the following manually if needed:"
  echo "  # SSL Pinning Bypass:"
  echo "  frida -U -f \"\$ANDROID_PACKAGES\" -l /usr/share/frida-scripts/universal.js --no-pause"
  echo "  # Proxy: mitmproxy -p 8080"
  echo "  # Device proxy: adb shell settings put global http_proxy 127.0.0.1:8080"
  ok "Phase 4 — Active Mobile Recon instructions generated"
  mark_phase_done 4
}

# ── Phase 5: Web ↔ Mobile Correlation ───────────────────────────────────────
phase5_correlation() {
  header "Phase 5 — Web ↔ Mobile Correlation"
  mkdir -p correlation

  # ── 5.1 Endpoint Cross-Reference ──
  log "5.1 — Endpoint Cross-Reference"
  if [ -f js/findings/endpoints/all.txt ] && [ -f mobile/all_mobile_endpoints.txt ]; then
    comm -23 <(sort js/findings/endpoints/all.txt) <(sort mobile/all_mobile_endpoints.txt) \
      >> correlation/web_only_endpoints.txt || true
    comm -13 <(sort js/findings/endpoints/all.txt) <(sort mobile/all_mobile_endpoints.txt) \
      >> correlation/mobile_only_endpoints.txt || true
    comm -12 <(sort js/findings/endpoints/all.txt) <(sort mobile/all_mobile_endpoints.txt) \
      >> correlation/shared_endpoints.txt || true
    ok "  Web-only: $(wc -l < correlation/web_only_endpoints.txt 2>$NULL || echo 0)"
    ok "  Mobile-only: $(wc -l < correlation/mobile_only_endpoints.txt 2>$NULL || echo 0)"
    ok "  Shared: $(wc -l < correlation/shared_endpoints.txt 2>$NULL || echo 0)"
  else
    warn "  Missing endpoint files — run JS analysis and Phase 3 first"
  fi

  # ── 5.2 Auth Flow Comparison ──
  log "5.2 — Auth Flow Comparison"
  grep -iE 'auth|login|oauth|token|session' js/findings/endpoints/all.txt \
    >> correlation/web_auth_endpoints.txt 2>$NULL || true
  grep -iE 'auth|login|oauth|token|session' mobile/all_mobile_endpoints.txt \
    >> correlation/mobile_auth_endpoints.txt 2>$NULL || true

  if [ -f correlation/web_auth_endpoints.txt ] && [ -f correlation/mobile_auth_endpoints.txt ]; then
    comm -13 correlation/web_auth_endpoints.txt correlation/mobile_auth_endpoints.txt \
      >> correlation/mobile_exclusive_auth.txt || true
  fi

  # ── 5.3 Secret Correlation ──
  log "5.3 — Secret Correlation"
  cat js/findings/secrets/regex_hits.txt mobile/android/secrets_*.txt \
    2>$NULL | sort -u >> correlation/all_secrets.txt || true
  sort -u correlation/all_secrets.txt -o correlation/all_secrets.txt 2>$NULL || true
  ok "Combined secrets: $(wc -l < correlation/all_secrets.txt 2>$NULL || echo 0)"

  ok "Phase 5 — Correlation complete!"
}

# ── Phase 6: Vulnerability Discovery ──────────────────────────────────────────
phase6_vulnerability() {
  header "Phase 6 — Vulnerability Discovery"

  if [ ! -f http/live_urls.txt ] || [ ! -s http/live_urls.txt ]; then
    crit "No live URLs found. Run Phase 2 first."; return 1
  fi

  # ── 6.1 Subdomain Takeover ──
  log "6.1 — Subdomain Takeover Check"
  if command -v nuclei &>/dev/null; then
    nuclei -l http/live_urls.txt -tags takeover -rl "$RL_MEDIUM" \
      -severity medium,high,critical "${AUTH_ARGS[@]}" \
      2>$NULL >> http/takeover.txt || true
    sort -u http/takeover.txt -o http/takeover.txt 2>$NULL || true
    ok "  Takeover findings: $(wc -l < http/takeover.txt 2>$NULL || echo 0)"
  fi

  # ── 6.2 CVE & Misconfig ──
  log "6.2 — CVE & Misconfig Scanning"
  if command -v nuclei &>/dev/null; then
    nuclei -l http/live_urls.txt \
      -tags exposure,misconfig,cve,config,backup,disclosure \
      -exclude-tags ssl,tls,dos,fuzz,intrusive,token-spray,creds-stuffing,brute-force \
      -severity medium,high,critical -exclude-severity info \
      -rl "$RL_MEDIUM" "${AUTH_ARGS[@]}" \
      2>$NULL >> http/nuclei_findings.txt || true
    sort -u http/nuclei_findings.txt -o http/nuclei_findings.txt 2>$NULL || true
    ok "  Nuclei findings: $(wc -l < http/nuclei_findings.txt 2>$NULL || echo 0)"
  fi

  # ── 6.3 CORS Misconfiguration ──
  log "6.3 — CORS Misconfiguration"
  if command -v nuclei &>/dev/null; then
    nuclei -l http/live_urls.txt -tags cors -rl "$RL_MEDIUM" \
      2>$NULL >> http/cors_findings.txt || true
  fi

  for target in $(head -10 subs/live_hosts.txt 2>$NULL); do
    for origin in "https://evil.com" "https://${target}.evil.com" "null"; do
      curl -sk "https://${target}/" -H "Origin: $origin" -I \
        2>$NULL | grep -i 'access-control' >> http/cors_manual.txt || true
    done
  done
  sort -u http/cors_findings.txt -o http/cors_findings.txt 2>$NULL || true
  ok "  CORS checks done"

  # ── 6.4 Open Redirect ──
  log "6.4 — Open Redirect"
  grep -oE 'https?://[^"'"'"'<> ]*(redirect|return|continue|next|url|goto|dest|target)=https?://' \
    urls/all_urls_merged.txt >> urls/open_redirect_candidates.txt 2>$NULL || true
  sort -u urls/open_redirect_candidates.txt -o urls/open_redirect_candidates.txt 2>$NULL || true
  ok "  Open redirect candidates: $(wc -l < urls/open_redirect_candidates.txt 2>$NULL || echo 0)"

  # ── 6.5 XSS Scanning ──
  log "6.5 — XSS Scanning"
  if command -v dalfox &>/dev/null; then
    head -100 urls/params_merged.txt 2>$NULL \
      | dalfox pipe --mining-dom --mining-dict --rate-limit "$RL_LIGHT" \
        2>$NULL >> http/xss_findings.txt || true
    sort -u http/xss_findings.txt -o http/xss_findings.txt 2>$NULL || true
    ok "  XSS findings: $(wc -l < http/xss_findings.txt 2>$NULL || echo 0)"
  fi

  # ── 6.6 SQL Injection ──
  log "6.6 — SQL Injection"
  if command -v sqlmap &>/dev/null; then
    head -10 urls/params_merged.txt 2>$NULL \
      | xargs -I{} sqlmap -u "{}" --batch --level=1 --risk=1 \
        --random-agent --output-dir=api/sqlmap 2>$NULL || true
    ok "  SQLMap scan complete"
  fi

  # ── 6.7 API Security Audit ──
  log "6.7 — API Security Audit"
  if [ -f urls/api_urls.txt ] && [ -s urls/api_urls.txt ]; then
    if command -v nuclei &>/dev/null; then
      nuclei -l urls/api_urls.txt -tags api,graphql,jwt \
        -rl "$RL_LIGHT" "${AUTH_ARGS[@]}" \
        2>$NULL >> http/api_vulns.txt || true
      sort -u http/api_vulns.txt -o http/api_vulns.txt 2>$NULL || true
    fi
    ok "  API security checks done"
  fi

  ok "Phase 6 — Vulnerability Discovery complete!"
}

# ── Phase 7: Reporting ────────────────────────────────────────────────────────
phase7_reporting() {
  header "Phase 7 — Reporting"

  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')

  cat >> recon_report.md <<EOF
# Recon Report — ${PROGRAM_NAME:-$PROGRAM}
**Generated:** ${ts}

## Surface Summary

| Metric | Count |
|--------|-------|
| Seed domains | $(wc -l < seeds.txt 2>$NULL || echo 0) |
| Subdomains (all) | $(wc -l < subs/all_subs_raw.txt 2>$NULL || echo 0) |
| Subdomains (in-scope) | $(wc -l < subs/inscope_subs.txt 2>$NULL || echo 0) |
| Live hosts | $(wc -l < subs/live_hosts.txt 2>$NULL || echo 0) |
| Live URLs | $(wc -l < http/live_urls.txt 2>$NULL || echo 0) |
| URLs w/ params | $(wc -l < urls/params_merged.txt 2>$NULL || echo 0) |
| Historical URLs | $(wc -l < urls/all_urls.txt 2>$NULL || echo 0) |
| JS URLs | $(wc -l < urls/js_urls.txt 2>$NULL || echo 0) |
| Mobile endpoints | $(wc -l < mobile/all_mobile_endpoints.txt 2>$NULL || echo 0) |

## Vulnerability Findings

| Category | Count |
|----------|-------|
| Takeover candidates | $(wc -l < http/takeover.txt 2>$NULL || echo 0) |
| Nuclei findings | $(wc -l < http/nuclei_findings.txt 2>$NULL || echo 0) |
| CORS findings | $(wc -l < http/cors_findings.txt 2>$NULL || echo 0) |
| XSS findings | $(wc -l < http/xss_findings.txt 2>$NULL || echo 0) |
| Open redirects | $(wc -l < urls/open_redirect_candidates.txt 2>$NULL || echo 0) |

## Correlation

| Category | Count |
|----------|-------|
| Web-only endpoints | $(wc -l < correlation/web_only_endpoints.txt 2>$NULL || echo 0) |
| Mobile-only endpoints | $(wc -l < correlation/mobile_only_endpoints.txt 2>$NULL || echo 0) |
| Shared endpoints | $(wc -l < correlation/shared_endpoints.txt 2>$NULL || echo 0) |
| Combined secrets | $(wc -l < correlation/all_secrets.txt 2>$NULL || echo 0) |

EOF

  ok "Report appended to recon_report.md"
  ok "Phase 7 — Reporting complete!"
}

# ── Run JS Analysis ───────────────────────────────────────────────────────────
run_js_analysis() {
  local js_script="${SCRIPT_DIR}/js_analis.sh"
  if [ -f "$js_script" ] && [ -x "$js_script" ] || [ -f "$js_script" ]; then
    log "Running JS analysis via js_analis.sh..."
    bash "$js_script" "$WORKDIR" "$SCOPE_WILDCARD" || true
    ok "JS analysis complete"
  else
    warn "js_analis.sh not found at ${js_script} — skipping JS analysis"
    warn "You can run it separately: bash js_analis.sh <workdir>"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  case "$VERBOSE_LEVEL" in
    2)
      set -x
      NULL=/dev/stderr
      dbg "Verbose level 2 (-vv): all tool output + debug trace aktif"
      ;;
    1)
      NULL=/dev/null
      dbg "Verbose level 1 (-v): detail fase aktif, tool output disembunyikan"
      ;;
    *)
      NULL=/dev/null
      ;;
  esac

  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║       Universal Recon Framework  (.env-Driven)              ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"

  load_env
  setup_dirs

  if [ "$CHECK_TOOLS_ONLY" = true ]; then
    check_tools
    exit 0
  fi

  # ── Resume: skip completed phases ──
  if [ "$RESUME" = true ] && [ "$PHASE_EXPLICIT" = false ]; then
    for n in 1 2 3 4 5 6 7; do
      if ! phase_is_done "$n"; then
        START_PHASE=$n
        dbg "Resume mode: starting from Phase $n (previous phases already done)"
        break
      fi
      START_PHASE=$((n + 1))
    done
    if [ "$START_PHASE" -gt 7 ]; then
      ok "All phases already completed! Use --phase N to re-run specific phase."
      exit 0
    fi
  fi

  check_tools

  case "$START_PHASE" in
    1) should_run_phase 1 && phase1_passive_web       ;;&
    2) should_run_phase 2 && phase2_active_web        ;;&
    3) should_run_phase 3 && phase3_mobile_passive    ;;&
    4) should_run_phase 4 && phase4_mobile_active     ;;&
    5) should_run_phase 5 && phase5_correlation       ;;&
    6)
      if should_run_phase 6; then
        # Run JS analysis before vuln discovery if applicable
        if [ "$START_PHASE" -le 2 ] || [ "$RANGE_START" -le 2 ]; then
          run_js_analysis
        fi
        phase6_vulnerability
      fi
      ;;
    7) should_run_phase 7 && phase7_reporting         ;;
    *)
      phase1_passive_web
      phase2_active_web
      run_js_analysis
      phase3_mobile_passive
      phase4_mobile_active
      phase5_correlation
      phase6_vulnerability
      phase7_reporting
      ;;
  esac

  echo ""
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${GREEN}  Recon Framework Complete!${RESET}"
  echo -e "${BOLD}${GREEN}  Report: recon_report.md${RESET}"
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
}

main "$@"
