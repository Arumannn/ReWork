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
   6  (standalone: vulndiscovery.sh & js_analis.sh)
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
        START_PHASE="$2"; RANGE_START="$2"; RANGE_END="$2"; PHASE_EXPLICIT=true; shift 2 ;;
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
  : "${RL_LIGHT:=10}" "${RL_MEDIUM:=50}" "${RL_AGGRESSIVE:=100}" "${MASSCAN_RATE:=1000}" "${THREADS:=5}"
  : "${DNS_SERVER:=192.168.1.1}"
  : "${SCOPE_WILDCARD:=}" "${OUT_OF_SCOPE:=}"
  : "${WORKDIR:=${SCRIPT_DIR}}"
  : "${SEED_DOMAINS:=}"
  : "${TARGETS_FILE:=}"
  : "${GITHUB_TOKEN:=}"
  : "${SHODAN_API_KEY:=}"
  : "${WORDLIST_DIR:=}"

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

  log "  Certificate Transparency (crt.sh)..."
  while read -r d; do
    resp=$(curl -s --max-time 30 --retry 2 \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
      "https://crt.sh/?q=%25.${d}&output=json" 2>$NULL) || true
    case "$resp" in
      '['*) echo "$resp" | jq -r '.[].name_value' 2>$NULL || true ;;
      *)    warn "  crt.sh: ${d} returned non-JSON (rate-limited or down)" ;;
    esac
    sleep 0.5
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
  cat subs/subfinder.txt subs/crtsh.txt subs/urlscan.txt \
    2>$NULL | sort -u >> subs/all_subs_raw.txt || true
  sort -u subs/all_subs_raw.txt -o subs/all_subs_raw.txt 2>$NULL || true
  ok "Total subdomains collected: $(wc -l < subs/all_subs_raw.txt 2>$NULL || echo 0)"

  # ── 1.1b Shodan Recon ──
  log "1.1b — Shodan Reconnaissance"
  if command -v shodan &>/dev/null; then
    while read -r d; do
      shodan search "hostname:${d}" 2>$NULL >> subs/shodan_hosts.txt || true
      shodan domain "$d" 2>$NULL >> subs/shodan_domain.txt || true
    done < seeds.txt
    sort -u subs/shodan_hosts.txt -o subs/shodan_hosts.txt 2>$NULL || true
    ok "  Shodan: $(wc -l < subs/shodan_hosts.txt 2>$NULL || echo 0) findings"

    log "  Generating pretty-printed Shodan output..."
    sed 's/\\r\\n/\n/g; s/\\n/\n/g' subs/shodan_hosts.txt \
      > subs/pretty_shodan_hosts.txt 2>$NULL || true
    cp subs/shodan_domain.txt subs/pretty_shodan_domain.txt 2>$NULL || true
    ok "  Pretty Shodan: subs/pretty_shodan_hosts.txt & pretty_shodan_domain.txt"

    log "  Merging Shodan data into subdomain list..."
    awk -F'\t' '{split($3, domains, /;/); for(d in domains) print domains[d]}' \
      subs/shodan_hosts.txt 2>/dev/null >> subs/all_subs_raw.txt || true
    awk '{print $1}' subs/shodan_domain.txt 2>/dev/null >> subs/all_subs_raw.txt || true
    sort -u subs/all_subs_raw.txt -o subs/all_subs_raw.txt 2>/dev/null || true
    ok "  Shodan subdomains merged: $(wc -l < subs/all_subs_raw.txt 2>/dev/null || echo 0) total"
  else
    warn "  shodan CLI not available — skipping"
  fi

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

  # ── 1.2b HTTP Probe on inscope_subs ──
  log "1.2b — httpx-pd probe on inscope subdomains"
  if command -v httpx-pd &>/dev/null; then
    httpx-pd -l subs/inscope_subs.txt -rl "$RL_MEDIUM" -silent \
      "${AUTH_ARGS[@]}" \
      -sc -title -td -location -cl -server -probe -json \
      2>$NULL > http/httpx_inscope.json || true
    mkdir -p http/inscope_status
    jq -r 'select(.status_code >= 100 and .status_code < 200) | .url' http/httpx_inscope.json \
      2>$NULL | sort -u > http/inscope_status/sc_1xx.txt || true
    jq -r 'select(.status_code >= 200 and .status_code < 300) | .url' http/httpx_inscope.json \
      2>$NULL | sort -u > http/inscope_status/sc_2xx.txt || true
    jq -r 'select(.status_code >= 300 and .status_code < 400) | .url' http/httpx_inscope.json \
      2>$NULL | sort -u > http/inscope_status/sc_3xx.txt || true
    jq -r 'select(.status_code >= 400 and .status_code < 500) | .url' http/httpx_inscope.json \
      2>$NULL | sort -u > http/inscope_status/sc_4xx.txt || true
    jq -r 'select(.status_code >= 500) | .url' http/httpx_inscope.json \
      2>$NULL | sort -u > http/inscope_status/sc_5xx.txt || true
    for f in http/inscope_status/sc_*.txt; do [ -s "$f" ] || rm -f "$f"; done
    ok "  Inscope probe: 1xx=$(wc -l < http/inscope_status/sc_1xx.txt 2>$NULL || echo 0) 2xx=$(wc -l < http/inscope_status/sc_2xx.txt 2>$NULL || echo 0) 3xx=$(wc -l < http/inscope_status/sc_3xx.txt 2>$NULL || echo 0) 4xx=$(wc -l < http/inscope_status/sc_4xx.txt 2>$NULL || echo 0) 5xx=$(wc -l < http/inscope_status/sc_5xx.txt 2>$NULL || echo 0)"
  else
    warn "  httpx-pd not available — skipping inscope probe"
  fi

  # ── 1.3 Historical URLs ──
  log "1.3 — Historical URL Gathering"

  if command -v gau &>/dev/null; then
    log "  Running gau (timeout 120s)..."
    timeout 120 gau --subs --providers wayback,otx < seeds.txt \
      2>$NULL >> urls/gau.txt || warn "  gau timed out or failed"
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
    log "  WAF detection via wafw00f (resolve-checked)..."
    : > http/waf_raw.txt
    while read -r h; do
      dig +short @$DNS_SERVER "$h" A 2>$NULL | grep -q '^[0-9]' || continue
      wafw00f "https://${h}" -a 2>/dev/null >> http/waf_raw.txt || true
    done < <(head -20 subs/inscope_subs.txt 2>$NULL) || true
    # Parse: extract URL → WAF status, sort with No WAF first
    : > http/waf_summary.txt
    current_url=""
    while IFS= read -r line; do
      if [[ "$line" =~ ^\[+\]\ Checking\ (https?://[^ ]+) ]]; then
        current_url="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ is\ behind\ (.*)\ WAF ]]; then
        echo "${current_url} → ${BASH_REMATCH[1]} WAF" >> http/waf_summary.txt
      elif [[ "$line" =~ No\ WAF ]]; then
        echo "${current_url} → No WAF" >> http/waf_summary.txt
      fi
    done < http/waf_raw.txt
    sort -u http/waf_summary.txt -o http/waf_summary.txt || true
    grep "No WAF" http/waf_summary.txt > http/waf_tmp.txt 2>$NULL || true
    grep -v "No WAF" http/waf_summary.txt >> http/waf_tmp.txt 2>$NULL || true
    mv http/waf_tmp.txt http/waf_summary.txt 2>$NULL || true
    ok "  WAF summary: http/waf_summary.txt ($(wc -l < http/waf_summary.txt) hosts)"
    rm -f http/waf_raw.txt
  fi

  if command -v wappalyzer-cli &>/dev/null; then
    log "  Tech detection via wappalyzer-cli (resolve-checked)..."
    while read -r h; do
      dig +short @$DNS_SERVER "$h" A 2>$NULL | grep -q '^[0-9]' || continue
      wappalyzer-cli -target "https://${h}" -silent 2>$NULL || true
    done < <(head -20 subs/inscope_subs.txt 2>$NULL) \
      >> http/wappalyzer_results.txt || true
  fi

  # ── 1.7 Google Dorking ──
  log "1.7 — Google Dork Generation"
  while read -r d; do
    cat >> dorks/google_dorks.txt <<EOF
# ── individual ──
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

# ── all-in-one (OR) ──
site:${d} (intitle:login OR filetype:env OR filetype:sql OR filetype:log OR inurl:admin OR inurl:api OR inurl:backup OR intitle:"index of" OR ext:json OR ext:xml OR ext:pdf OR "api_key" OR "secret" OR "token" OR "password" OR "db_password" OR "AWS_ACCESS_KEY" OR "-----BEGIN" OR "bucket" "s3")
EOF
  done < seeds.txt
  ok "  Google dorks saved to dorks/google_dorks.txt ($(wc -l < dorks/google_dorks.txt) queries)"

  # ── 1.8 GitHub Dorking ──
  log "1.8 — GitHub Dorking"
  if [ -n "$GITHUB_TOKEN" ]; then
    mkdir -p github
    local kw
    for kw in api_key secret password token .env AWS_ACCESS_KEY mongodb; do
      # ── search seeds (domains) per-keyword ──
      while read -r d; do
        curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
          -H "Accept: application/vnd.github.v3.text-match+json" \
          "https://api.github.com/search/code?q=${d}+${kw}&per_page=100" 2>$NULL | \
          jq -r --arg kw "$kw" --arg src "domain/${d}" \
            '.items[]? | [.html_url, .repository.full_name, $kw, (.text_matches[0].fragment // "" | gsub("\\n"; " ") | .[0:200]), $src] | join(" | ")' \
          2>$NULL >> github/leak_candidates.txt || true
      done < seeds.txt

      # ── search IP ranges from SCOPE_EXPLICIT ──
      echo "$SCOPE_EXPLICIT" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | sort -u | while read -r ip; do
        [ -n "$ip" ] && curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
          -H "Accept: application/vnd.github.v3.text-match+json" \
          "https://api.github.com/search/code?q=${ip}+${kw}&per_page=100" 2>$NULL | \
          jq -r --arg kw "$kw" --arg src "ip/${ip}" \
            '.items[]? | [.html_url, .repository.full_name, $kw, (.text_matches[0].fragment // "" | gsub("\\n"; " ") | .[0:200]), $src] | join(" | ")' \
          2>$NULL >> github/leak_candidates.txt || true
      done

      # ── search Azure tenants ──
      echo "$SCOPE_EXPLICIT" | grep -oE '[a-zA-Z0-9_-]+\.onmicrosoft\.com' | sort -u | while read -r tenant; do
        [ -n "$tenant" ] && curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
          -H "Accept: application/vnd.github.v3.text-match+json" \
          "https://api.github.com/search/code?q=${tenant}+${kw}&per_page=100" 2>$NULL | \
          jq -r --arg kw "$kw" --arg src "azure/${tenant}" \
            '.items[]? | [.html_url, .repository.full_name, $kw, (.text_matches[0].fragment // "" | gsub("\\n"; " ") | .[0:200]), $src] | join(" | ")' \
          2>$NULL >> github/leak_candidates.txt || true
      done

      # ── search sharepoint URLs ──
      echo "$SCOPE_EXPLICIT" | grep -oE 'https?://[a-zA-Z0-9.-]+\.sharepoint\.com' | sort -u | while read -r sp; do
        [ -n "$sp" ] && curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
          -H "Accept: application/vnd.github.v3.text-match+json" \
          "https://api.github.com/search/code?q=${sp}+${kw}&per_page=100" 2>$NULL | \
          jq -r --arg kw "$kw" --arg src "sp/${sp}" \
            '.items[]? | [.html_url, .repository.full_name, $kw, (.text_matches[0].fragment // "" | gsub("\\n"; " ") | .[0:200]), $src] | join(" | ")' \
          2>$NULL >> github/leak_candidates.txt || true
      done
    done
    sort -u github/leak_candidates.txt -o github/leak_candidates.txt 2>$NULL || true
    ok "  GitHub leak candidates: $(wc -l < github/leak_candidates.txt 2>$NULL || echo 0)"
  else
    log "  GITHUB_TOKEN not set — generating dork queries only"
    while read -r d; do
      cat >> dorks/github_dorks.txt <<EOF
# ── individual ──
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

# ── all-in-one (OR) ──
"${d}" (api_key OR secret OR token OR password OR .env OR AWS_ACCESS_KEY OR "-----BEGIN RSA PRIVATE KEY" OR mongodb)
org:"${d}" (password OR secret)
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
  log "2.1 — DNS Resolution (parallel, $THREADS threads)..."
  total=$(wc -l < subs/inscope_subs.txt 2>$NULL || echo 0)
  : > subs/resolved.txt
  cat subs/inscope_subs.txt | xargs -P "$THREADS" -I{} sh -c '
    ip=$(dig +short @$DNS_SERVER "{}" A 2>/dev/null | grep -E "^[0-9]" | head -1)
    [ -n "$ip" ] && echo "{} $ip"
  ' >> subs/resolved.txt 2>$NULL || true
  sort -u subs/resolved.txt -o subs/resolved.txt 2>$NULL || true
  awk '{print $1}' subs/resolved.txt 2>$NULL | sort -u >> subs/live_hosts.txt || true
  sort -u subs/live_hosts.txt -o subs/live_hosts.txt 2>$NULL || true
  ok "Resolved: $(wc -l < subs/resolved.txt 2>$NULL || echo 0) / ${total} hosts"

  # ── 2.2 HTTP Probing ──
  log "2.2 — HTTP Probing"
  if command -v httpx-pd &>/dev/null; then
    log "  httpx-pd json probe..."
    httpx-pd -l subs/live_hosts.txt -rl "$RL_MEDIUM" -silent \
      "${AUTH_ARGS[@]}" \
      -sc -title -td -location -cl -server -probe -json \
      2>$NULL > http/httpx_full.json || true

    log "  httpx-pd tech-detect (json)..."
    httpx-pd -l subs/live_hosts.txt -rl "$RL_MEDIUM" -silent \
      "${AUTH_ARGS[@]}" -tech-detect -json \
      2>$NULL > http/httpx_tech.json || true

    log "  Splitting by status code..."
    jq -r '.url' http/httpx_full.json 2>$NULL | sort -u > http/live_urls.txt || true
    jq -r 'select(.status_code >= 100 and .status_code < 200) | .url' http/httpx_full.json \
      2>$NULL | sort -u > http/sc_1xx.txt || true
    jq -r 'select(.status_code >= 200 and .status_code < 300) | .url' http/httpx_full.json \
      2>$NULL | sort -u > http/sc_2xx.txt || true
    jq -r 'select(.status_code >= 300 and .status_code < 400) | .url' http/httpx_full.json \
      2>$NULL | sort -u > http/sc_3xx.txt || true
    jq -r 'select(.status_code >= 400 and .status_code < 500) | .url' http/httpx_full.json \
      2>$NULL | sort -u > http/sc_4xx.txt || true
    jq -r 'select(.status_code >= 500) | .url' http/httpx_full.json \
      2>$NULL | sort -u > http/sc_5xx.txt || true
    for f in http/sc_*.txt; do [ -s "$f" ] || rm -f "$f"; done

    # Copy status code results to url/status_code
    mkdir -p url/status_code
    for f in http/sc_*.txt; do
      [ -s "$f" ] && cp "$f" "url/status_code/" 2>$NULL || true
    done

    ok "  Live URLs: $(wc -l < http/live_urls.txt 2>$NULL || echo 0)"
    ok "  Status split: 1xx=$(wc -l < http/sc_1xx.txt 2>$NULL || echo 0) 2xx=$(wc -l < http/sc_2xx.txt 2>$NULL || echo 0) 3xx=$(wc -l < http/sc_3xx.txt 2>$NULL || echo 0) 4xx=$(wc -l < http/sc_4xx.txt 2>$NULL || echo 0) 5xx=$(wc -l < http/sc_5xx.txt 2>$NULL || echo 0)"

    # Create live_hosts_filtered.txt — exclude hosts that return 5xx only
    jq -r 'select(.status_code < 500) | .input' http/httpx_full.json \
      2>$NULL | sort -u > subs/live_hosts_filtered.txt || true
    ok "  Live hosts filtered (excl 5xx): $(wc -l < subs/live_hosts_filtered.txt 2>$NULL || echo 0)"
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

  # ── 2.3 Web Crawling ──
  log "2.3 — Web Crawling"
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
    >> urls/all_urls_final.txt || true
  sort -u urls/all_urls_final.txt -o urls/all_urls_final.txt 2>$NULL || true
  grep '=' urls/all_urls_final.txt | sort -u >> urls/params_merged.txt || true
  ok "Merged URLs: $(wc -l < urls/all_urls_final.txt 2>$NULL || echo 0)"

  # Merge all historical + live URLs
  cat urls/all_urls.txt urls/all_urls_final.txt 2>$NULL | sort -u \
    >> urls/all_urls_final.txt || true
  ok "All URLs (historical + live): $(wc -l < urls/all_urls_final.txt 2>$NULL || echo 0)"

  # Filter URLs by in-scope subdomains
  grep -Ff subs/inscope_subs.txt urls/all_urls_final.txt \
    | sort -u > urls/all_urls_final_inscope.txt || true
  ok "In-scope URLs: $(wc -l < urls/all_urls_final_inscope.txt 2>$NULL || echo 0)"

  # ── Status Code Check ──
  log "  Checking status codes for all URLs..."
  if command -v httpx-pd &>/dev/null; then
    httpx-pd -l urls/all_urls_final_inscope.txt -rl "$RL_MEDIUM" -silent \
      "${AUTH_ARGS[@]}" -sc -json \
      2>$NULL > urls/httpx_all_urls.json || true

    mkdir -p urls/status_code
    jq -r 'select(.status_code >= 100 and .status_code < 200) | .url' urls/httpx_all_urls.json \
      2>$NULL | sort -u > urls/status_code/sc_1xx.txt || true
    jq -r 'select(.status_code >= 200 and .status_code < 300) | .url' urls/httpx_all_urls.json \
      2>$NULL | sort -u > urls/status_code/sc_2xx.txt || true
    jq -r 'select(.status_code >= 300 and .status_code < 400) | .url' urls/httpx_all_urls.json \
      2>$NULL | sort -u > urls/status_code/sc_3xx.txt || true
    jq -r 'select(.status_code >= 400 and .status_code < 500) | .url' urls/httpx_all_urls.json \
      2>$NULL | sort -u > urls/status_code/sc_4xx.txt || true
    jq -r 'select(.status_code >= 500) | .url' urls/httpx_all_urls.json \
      2>$NULL | sort -u > urls/status_code/sc_5xx.txt || true
    for f in urls/status_code/sc_*.txt; do [ -s "$f" ] || rm -f "$f"; done

    # Extract URLs with 2xx/3xx/4xx status codes for extension extraction
    jq -r 'select(.status_code >= 200 and .status_code < 500) | .url' urls/httpx_all_urls.json \
      2>$NULL | sort -u > urls/urls_200_300_400.txt || true

    ok "  Status codes: 1xx=$(wc -l < urls/status_code/sc_1xx.txt 2>$NULL || echo 0) 2xx=$(wc -l < urls/status_code/sc_2xx.txt 2>$NULL || echo 0) 3xx=$(wc -l < urls/status_code/sc_3xx.txt 2>$NULL || echo 0) 4xx=$(wc -l < urls/status_code/sc_4xx.txt 2>$NULL || echo 0) 5xx=$(wc -l < urls/status_code/sc_5xx.txt 2>$NULL || echo 0)"
    ok "  URLs for extension extraction (2xx/3xx/4xx): $(wc -l < urls/urls_200_300_400.txt 2>$NULL || echo 0)"
  fi

  # Extract URLs by extension (only from 2xx/3xx/4xx URLs)
  log "  Extracting URLs by extension..."
  local ext_file="urls/all_urls_final_inscope.txt"
  [ -s urls/urls_200_300_400.txt ] && ext_file="urls/urls_200_300_400.txt"
  mkdir -p urls/by_ext
  EXTENSIONS="js|json|xml|yml|yaml|php|asp|aspx|jsp|do|action|txt|conf|config|env|sql|bak|pdf|doc|xls|xlsx|docx|zip|tar|gz|rar|log|ini|cfg|cert|key|pem|csr|der"
  local IFS='|'
  for ext in $EXTENSIONS; do
    grep -i "\.${ext}\b" "$ext_file" \
      > "urls/by_ext/ext_${ext}.txt" 2>$NULL || true
    local cnt=$(wc -l < "urls/by_ext/ext_${ext}.txt" 2>$NULL || echo 0)
    [ "$cnt" -gt 0 ] && log "    .${ext}: ${cnt} URLs"
  done
  unset IFS

  # ── 2.5 Content Discovery ──
  log "2.5 — Content Discovery"
  local WORDS="api|v1|v2|v3|graphql|rest|auth|login|signin|oauth|token|session|user|admin|internal|dashboard|health|status|metrics|swagger|docs|openapi|webhook|callback|config|settings|payment|checkout|wallet|static|assets|uploads|download|.env|.git|backup|db|migrations|logs|debug|test"

  if command -v ffuf &>/dev/null; then
    log "  Running ffuf fast scan (inline wordlist)..."
    while read -r h; do
      ffuf -u "https://${h}/FUZZ" -w <(echo "$WORDS" | tr '|' '\n') \
        -t "$THREADS" -rate "$RL_AGGRESSIVE" -c -fc 404 \
        2>$NULL >> http/ffuf_results.txt || true
    done < <(head -20 subs/live_hosts.txt 2>$NULL)
    sort -u http/ffuf_results.txt -o http/ffuf_results.txt 2>$NULL || true
    ok "  FFuf fast scan done: $(wc -l < http/ffuf_results.txt 2>$NULL || echo 0) results"

    # Full scan with wordlist
    local full_wordlist=""
    if [ -n "$WORDLIST_DIR" ] && [ -f "$WORDLIST_DIR/common.txt" ]; then
      full_wordlist="$WORDLIST_DIR/common.txt"
    elif [ -f /usr/share/wordlists/dirb/common.txt ]; then
      full_wordlist=/usr/share/wordlists/dirb/common.txt
    elif [ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
      full_wordlist=/usr/share/seclists/Discovery/Web-Content/common.txt
    fi

    if [ -n "$full_wordlist" ]; then
      log "  Running ffuf full scan ($full_wordlist)..."
      while read -r h; do
        ffuf -u "https://${h}/FUZZ" -w "$full_wordlist" \
          -t "$THREADS" -rate "$RL_MEDIUM" -c -fc 404 \
          2>$NULL >> http/ffuf_full_results.txt || true
      done < <(head -10 subs/live_hosts.txt 2>$NULL)
      sort -u http/ffuf_full_results.txt -o http/ffuf_full_results.txt 2>$NULL || true
      ok "  FFuf full scan done: $(wc -l < http/ffuf_full_results.txt 2>$NULL || echo 0) results"
    else
      log "  No external wordlist found — skipping full scan (install seclists or set WORDLIST_DIR)"
    fi
  fi

  # ── 2.6 Hidden Parameter Discovery ──
  log "2.6 — Hidden Parameter Discovery"
  if command -v arjun &>/dev/null; then
    log "  Running arjun..."
    while read -r ep; do
      arjun -u "$ep" --method GET --threads 5 --rate-limit "$RL_LIGHT" \
        2>$NULL >> api/arjun_params.txt || true
    done < <(head -30 urls/all_urls_final_inscope.txt 2>$NULL)
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

    # Try pull APK from connected device via adb
    if command -v adb &>/dev/null && adb get-state 2>$NULL | grep -q device; then
      log "  Connected device detected — pulling APKs via adb..."
      for pkg in $ANDROID_PACKAGES; do
        local apk_path="mobile/android/${pkg}.apk"
        local remote_path
        remote_path=$(adb shell pm path "$pkg" 2>$NULL | sed 's/^package://' | head -1)
        if [ -n "$remote_path" ]; then
          ok "  Pulling ${pkg} from device (${remote_path})..."
          adb pull "$remote_path" "$apk_path" 2>$NULL || true
        else
          warn "  Package ${pkg} not found on device"
        fi
      done
    else
      log "  No adb device — skipping APK pull"
    fi

    for pkg in $ANDROID_PACKAGES; do
      local apk_abs="${WORKDIR}/mobile/android/${pkg}.apk"
      local decomp_abs="${WORKDIR}/mobile/android/decompiled/${pkg}"
      local source_abs="${WORKDIR}/mobile/android/source/${pkg}"
      local apk_path="mobile/android/${pkg}.apk"
      [ ! -f "$apk_abs" ] && warn "  APK not found: ${apk_abs}" && continue

      if command -v apktool &>/dev/null; then
        log "  Decompiling ${pkg} with apktool..."
        apktool d -f -o "$decomp_abs" "$apk_abs" \
          2>$NULL || true
      fi

      if command -v jadx &>/dev/null; then
        log "  Decompiling ${pkg} with jadx..."
        jadx -d "$source_abs" "$apk_abs" 2>$NULL || true
      fi

      log "  Extracting URLs from ${pkg}..."
      strings "$apk_path" | grep -iE 'https?://' \
        | grep -v 'android\.com\|googleapis\|googlesyndication' \
        >> "mobile/android/urls_${pkg}.txt" || true
      sort -u "mobile/android/urls_${pkg}.txt" -o "mobile/android/urls_${pkg}.txt" 2>$NULL || true

      log "  Extracting secrets from ${pkg}..."
      strings "$apk_path" | grep -iE \
'api[_-]?key|token|secret|password|bearer|firebase|supabase|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.eyJ|-----BEGIN.*(RSA|EC|DSA|PRIVATE)|sk_live_|pk_live_|TWILIO|xox[baprs]-|postgresql://|mysql://|mongodb://|redis://' \
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

# ── Phase 6: Standalone Scripts ───────────────────────────────────────────────
phase6_standalone() {
  header "Phase 6 — Standalone Recon Scripts"
  cat <<EOF

  The following scripts should be run separately after Phase 2 completes.
  They are NOT included in the main pipeline — run them manually when ready.

  ====================================================================
  1.  bash portscan.sh              Port scanning
                                    (masscan + nmap, requires root)

  2.  bash js_analis.sh <workdir>   JS/JSON analysis pipeline
                                    (download, endpoints, secrets, XSS, etc.)

  3.  bash vulndiscovery.sh         Vulnerability discovery
                                    (takeover, CVE, CORS, XSS, SQLi, API audit)
  ====================================================================

EOF
  ok "Phase 6 — Standalone instructions shown. Run each script separately."
  mark_phase_done 6
}

# ── Phase 7: Reporting ────────────────────────────────────────────────────────
phase7_reporting() {
  header "Phase 7 — Reporting"

  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')

  cat >> recon_report.md <<EOF
# Recon Report — ${PROGRAM_NAME:-$PROGRAM}
**Generated:** ${ts}

## Surface Summary (recon_framework.sh)

| Metric | Count |
|--------|-------|
| Seed domains | $(wc -l < seeds.txt 2>$NULL || echo 0) |
| Subdomains (all) | $(wc -l < subs/all_subs_raw.txt 2>$NULL || echo 0) |
| Subdomains (in-scope) | $(wc -l < subs/inscope_subs.txt 2>$NULL || echo 0) |
| Live hosts | $(wc -l < subs/live_hosts.txt 2>$NULL || echo 0) |
| Live hosts (filtered, excl 5xx) | $(wc -l < subs/live_hosts_filtered.txt 2>$NULL || echo 0) |
| Live URLs | $(wc -l < http/live_urls.txt 2>$NULL || echo 0) |
| URLs w/ params | $(wc -l < urls/params_merged.txt 2>$NULL || echo 0) |
| In-scope URLs | $(wc -l < urls/all_urls_final_inscope.txt 2>$NULL || echo 0) |
| Historical URLs | $(wc -l < urls/all_urls.txt 2>$NULL || echo 0) |
| JS URLs | $(wc -l < urls/js_urls.txt 2>$NULL || echo 0) |
| Mobile endpoints | $(wc -l < mobile/all_mobile_endpoints.txt 2>$NULL || echo 0) |

## Port Scanning (portscan.sh)

| Metric | Count |
|--------|-------|
| Open ports found | $(wc -l < ports/open_ports_raw.txt 2>$NULL || echo 0) |
| IPs scanned | $(wc -l < ports/ips.txt 2>$NULL || echo 0) |

## JS Analysis (js_analis.sh)

| Metric | Count |
|--------|-------|
| JS/JSON files | $(ls js/raw 2>/dev/null | wc -l || echo 0) |
| Endpoints extracted | $(wc -l < js/findings/endpoints/all.txt 2>$NULL || echo 0) |
| Secret candidates | $(wc -l < js/findings/secrets/hits_filtered.txt 2>$NULL || echo 0) |
| XSS sinks | $(wc -l < js/findings/xss/dangerous_sinks.txt 2>$NULL || echo 0) |

## Vulnerability Discovery (vulndiscovery.sh)

| Metric | Count |
|--------|-------|
| Takeover candidates | $(wc -l < http/takeover.txt 2>$NULL || echo 0) |
| Nuclei findings | $(wc -l < http/nuclei_findings.txt 2>$NULL || echo 0) |
| CORS findings | $(wc -l < http/cors_findings.txt 2>$NULL || echo 0) |
| XSS findings | $(wc -l < http/xss_findings.txt 2>$NULL || echo 0) |
| Open redirect candidates | $(wc -l < urls/open_redirect_candidates.txt 2>$NULL || echo 0) |
| API vulns | $(wc -l < http/api_vulns.txt 2>$NULL || echo 0) |

## Correlation (Phase 5)

| Category | Count |
|----------|-------|
| Web-only endpoints | $(wc -l < correlation/web_only_endpoints.txt 2>$NULL || echo 0) |
| Mobile-only endpoints | $(wc -l < correlation/mobile_only_endpoints.txt 2>$NULL || echo 0) |
| Shared endpoints | $(wc -l < correlation/shared_endpoints.txt 2>$NULL || echo 0) |
| Combined secrets | $(wc -l < correlation/all_secrets.txt 2>$NULL || echo 0) |

## Standalone Scripts

The following scripts should be run separately:
- \`bash portscan.sh\` — Port scanning (masscan + nmap, requires root)
- \`bash js_analis.sh <workdir> [scope]\` — JS analysis pipeline
- \`bash vulndiscovery.sh\` — Vulnerability scanning (takeover, CVE, XSS, SQLi, etc.)

EOF

  ok "Report appended to recon_report.md"
  ok "Phase 7 — Reporting complete!"
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
    for n in 1 2 3 4 5 7; do
      if ! phase_is_done "$n"; then
        START_PHASE=$n
        RANGE_START=$n
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

  should_run_phase 1 && phase1_passive_web
  should_run_phase 2 && phase2_active_web
  should_run_phase 3 && phase3_mobile_passive
  should_run_phase 4 && phase4_mobile_active
  should_run_phase 5 && phase5_correlation
  should_run_phase 6 && phase6_standalone
  should_run_phase 7 && phase7_reporting

  echo ""
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${GREEN}  Recon Framework Complete!${RESET}"
  echo -e "${BOLD}${GREEN}  Report: recon_report.md${RESET}"
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
}

main "$@"
