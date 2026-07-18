#!/usr/bin/env bash
# =============================================================================
#  Universal JS Reconnaissance Pipeline (.env-Driven)
#
#  Reads target config from .env. Accepts workdir + optional scope as args.
#
#  USAGE:
#    bash js_analis.sh <workdir> [scope]
#
#    <workdir>   Program directory containing .env (default: current dir)
#    [scope]     Scope file or inline regex (default: from env SCOPE_WILDCARD)
#
#  INPUT  : <workdir>/urls/all_urls_merged.txt  (from RECON-PLAN Phase 2)
#  OUTPUT : <workdir>/js/{raw,maps,unpacked,beautified,findings}
#
#  .env Variables Used:
#    WORKDIR, SCOPE_WILDCARD, RL_LIGHT, RL_MEDIUM, RL_AGGRESSIVE,
#    THREADS, AUTH_COOKIE, AUTH_HEADER
# =============================================================================
set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
WORKDIR="${1:-$PWD}"
SCOPE_ARG="${2:-}"
WORKDIR="$(cd "$WORKDIR" 2>/dev/null && pwd)" || { echo "workdir not found: ${1:-$PWD}"; exit 1; }
PROGRAM="$(basename "$WORKDIR")"

# ── Load .env ─────────────────────────────────────────────────────────────────
ENV_FILE="${WORKDIR}/.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  source "$ENV_FILE"
  set +a
else
  echo "[!] .env not found at ${ENV_FILE}"
  echo "    Copy .env.template to .env and fill in your target details."
  exit 1
fi

# ── Validate required ─────────────────────────────────────────────────────────
: "${RL_LIGHT:=10}" "${RL_MEDIUM:=50}" "${RL_AGGRESSIVE:=100}" "${THREADS:=5}"
: "${SCOPE_WILDCARD:=}"

# ── Staggered rate limit ──────────────────────────────────────────────────────
#  RL_LIGHT      — strict hosts, auth endpoints
#  RL_MEDIUM     — normal JS download
#  RL_AGGRESSIVE — source maps, internal CDN
RATE_LIMIT=$RL_MEDIUM
INTERVAL_MS=$((1000 / RATE_LIMIT))

PROG_DIR="${WORKDIR}/js"
JS_SRC="${WORKDIR}/urls/all_urls_merged.txt"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
MAX_PARALLEL="$THREADS"
TIMEOUT=15

# Auth headers
AUTH_ARGS=()
[ -n "${AUTH_COOKIE:-}" ] && AUTH_ARGS+=(-H "Cookie: $AUTH_COOKIE")
[ -n "${AUTH_HEADER:-}" ]  && AUTH_ARGS+=(-H "$AUTH_HEADER")

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; RESET='\033[0m'; BOLD='\033[1m'
log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${ORANGE}[!]${RESET} $*"; }
crit() { echo -e "${RED}[CRIT]${RESET} ${BOLD}$*${RESET}"; }

# ── Tool check ────────────────────────────────────────────────────────────────
check_tools() {
  log "Checking required tools..."
  local missing=()
  for t in curl sha256sum python3 jq flock; do
    command -v "$t" &>/dev/null || missing+=("$t")
  done
  command -v js-beautify &>/dev/null || warn "Optional: js-beautify not found (raw only)"
  command -v jsluice &>/dev/null    || warn "Optional: jsluice not found (regex fallback)"
  command -v trufflehog &>/dev/null || warn "Optional: trufflehog not found (regex fallback)"
  if [ ${#missing[@]} -gt 0 ]; then
    crit "Missing required: ${missing[*]}"
    exit 1
  fi
  ok "All required tools present"
}

# ── Load scope ────────────────────────────────────────────────────────────────
# Produces global DOMAINS as alternation regex: "a\.com|b\.net"
DOMAINS=""
load_scope() {
  log "Loading scope..."
  local scope="$SCOPE_ARG"

  if [ -z "$scope" ] && [ -f "${WORKDIR}/scope.txt" ]; then
    scope="${WORKDIR}/scope.txt"
  fi

  if [ -n "$scope" ] && [ -f "$scope" ]; then
    DOMAINS=$(sed -E 's/#.*//; s/[[:space:]]+//g' "$scope" | grep -v '^$' | paste -sd'|' -)
    ok "Scope file : $scope"
  elif [ -n "$scope" ]; then
    DOMAINS="$scope"
    ok "Scope inline"
  elif [ -n "$SCOPE_WILDCARD" ]; then
    DOMAINS="$SCOPE_WILDCARD"
    ok "Scope from .env SCOPE_WILDCARD"
  fi

  if [ -z "$DOMAINS" ]; then
    DOMAINS=".*"
    warn "No scope set — processing ALL JS URLs"
  else
    log "Domains : ${DOMAINS}"
  fi
}

# ── Collect & filter JS URLs ──────────────────────────────────────────────────
collect_js_urls() {
  log "Collecting JS URLs..."
  mkdir -p "$PROG_DIR"
  local all_js="${PROG_DIR}/js_urls_all.txt"
  local out="${PROG_DIR}/js_urls.txt"

  if [ ! -f "$JS_SRC" ]; then
    crit "URL source not found: ${JS_SRC}"
    echo "    Run URL gathering (Phase 2.5-2.6) from RECON-PLAN first."
    exit 1
  fi

  grep -Ei '\.m?js(\?.*)?$' "$JS_SRC" | sort -u > "$all_js"

  if [ "$DOMAINS" = ".*" ]; then
    cp "$all_js" "$out"
  else
    grep -Ei "https?://[a-zA-Z0-9.-]*(${DOMAINS})" "$all_js" > "$out" 2>/dev/null || true
  fi

  local c; c=$(wc -l < "$out")
  ok "JS URLs : ${c} in-scope (from $(wc -l < "$all_js") total JS)"
  [ "$c" -eq 0 ] && { warn "0 in-scope JS — check scope / all_urls_merged.txt"; }
}

# ── Download JS ───────────────────────────────────────────────────────────────
fetch_js() {
  local u="$1" prog_dir="$2" prog_map="$3"
  local tmp; tmp=$(mktemp)
  sleep "$(awk "BEGIN{printf \"%.3f\", ${INTERVAL_MS}/1000 + ($RANDOM % 50)/1000}")"

  local code
  code=$(curl -skL -A "$UA" \
    -H "Accept: application/javascript, */*" \
    "${AUTH_ARGS[@]}" \
    --max-time "$TIMEOUT" --compressed \
    -w '%{http_code}' -o "$tmp" "$u" 2>/dev/null)

  if [ "$code" = "200" ] && [ -s "$tmp" ] && \
     ! head -c 512 "$tmp" | grep -qiE '<!doctype html|<html\b'; then
    local h; h=$(sha256sum "$tmp" | cut -c1-16)
    if [ ! -f "${prog_dir}/raw/${h}.js" ]; then
      mv "$tmp" "${prog_dir}/raw/${h}.js"
    fi
    (
      flock -x 200
      printf '%s\t%s\n' "$h" "$u" >> "$prog_map"
    ) 200>"${prog_map}.lock" 2>/dev/null || true
  fi
  rm -f "$tmp"
}
export -f fetch_js

download_js() {
  local list="${PROG_DIR}/js_urls.txt"
  local map="${PROG_DIR}/url_map.tsv"
  : > "$map"

  local total; total=$(wc -l < "$list")
  [ "$total" -eq 0 ] && { warn "0 JS URLs, skipping download"; return; }

  mkdir -p "${PROG_DIR}/raw"
  log "Downloading ${total} JS files (rate=${RATE_LIMIT}/s, parallel=${MAX_PARALLEL})..."

  INTERVAL_MS="$INTERVAL_MS" TIMEOUT="$TIMEOUT" UA="$UA" RATE_LIMIT="$RATE_LIMIT" \
  AUTH_ARGS="${AUTH_ARGS[*]:-}" \
  xargs -P "$MAX_PARALLEL" -I{} bash -c "fetch_js '{}' '${PROG_DIR}' '${map}'" \
    < "$list" 2>/dev/null || true

  sort -u "$map" -o "$map"
  local dl; dl=$(ls "${PROG_DIR}/raw" 2>/dev/null | wc -l)
  ok "Downloaded ${dl} unique JS files (deduplicated by sha256)"
}

# ── Source maps ───────────────────────────────────────────────────────────────
fetch_source_maps() {
  local maps_dir="${PROG_DIR}/maps"
  mkdir -p "$maps_dir"

  awk -F'\t' '{print $2}' "${PROG_DIR}/url_map.tsv" 2>/dev/null \
    | sed -E 's/(\.m?js)(\?.*)?$/\1.map/' | sort -u > "${PROG_DIR}/map_urls.txt"

  local total; total=$(wc -l < "${PROG_DIR}/map_urls.txt")
  [ "$total" -eq 0 ] && return

  log "Fetching ${total} source maps..."
  fetch_map() {
    local u="$1" d="$2"
    local f; f=$(printf '%s' "$u" | sha256sum | cut -c1-12)
    sleep "$(awk "BEGIN{printf \"%.3f\", ${INTERVAL_MS}/1000 + ($RANDOM % 50)/1000}")"
    curl -skL -A "$UA" "${AUTH_ARGS[@]}" --max-time "$TIMEOUT" "$u" -o "${d}/${f}.map" 2>/dev/null
    if ! head -c 128 "${d}/${f}.map" 2>/dev/null | grep -q '"version"' || \
       ! head -c 256 "${d}/${f}.map" 2>/dev/null | grep -q '"sources"'; then
      rm -f "${d}/${f}.map"
    fi
  }
  export -f fetch_map
  export INTERVAL_MS TIMEOUT UA
  xargs -P "$MAX_PARALLEL" -I{} bash -c "fetch_map '{}' '${maps_dir}'" \
    < "${PROG_DIR}/map_urls.txt" 2>/dev/null || true

  local unpacked="${PROG_DIR}/unpacked"
  mkdir -p "$unpacked"
  for m in "$maps_dir"/*.map; do
    [ -s "$m" ] || continue
    local d="${unpacked}/$(basename "$m" .map)"
    mkdir -p "$d"
    python3 - "$m" "$d" <<'PY' 2>/dev/null || true
import json, sys, os, re
m, d = sys.argv[1], sys.argv[2]
try: j = json.load(open(m, errors='ignore'))
except: sys.exit(1)
for i, src in enumerate(j.get('sources', [])):
    content = (j.get('sourcesContent') or [None])[i]
    if not content: continue
    p = os.path.join(d, re.sub(r'\.\.+/', '', re.sub(r'[^\w./-]', '_', src)).lstrip('./'))
    os.makedirs(os.path.dirname(p) if os.path.dirname(p) else d, exist_ok=True)
    with open(p, 'w', errors='ignore') as f: f.write(content)
PY
  done
  local sm; sm=$(ls "$maps_dir" 2>/dev/null | wc -l)
  ok "${sm} source maps unpacked (check ${unpacked}/ for pre-minified sources)"
}

# ── Beautify ──────────────────────────────────────────────────────────────────
beautify_js() {
  local raw="${PROG_DIR}/raw" bf="${PROG_DIR}/beautified"
  mkdir -p "$bf"
  [ "$(ls "$raw" 2>/dev/null | wc -l)" -eq 0 ] && return

  if command -v js-beautify &>/dev/null; then
    log "Beautifying JS files..."
    for f in "$raw"/*.js; do
      [ -f "$f" ] || continue
      js-beautify -q --indent-size 2 "$f" > "${bf}/$(basename "$f")" 2>/dev/null || cp "$f" "${bf}/$(basename "$f")"
    done
    ok "Beautified ${bf}"
  else
    warn "js-beautify not installed — analysis from raw files (noisier)"
  fi
}

get_js_dirs() {
  if [ -d "${PROG_DIR}/beautified" ] && [ "$(ls -A "${PROG_DIR}/beautified" 2>/dev/null)" ]; then
    echo "${PROG_DIR}/beautified ${PROG_DIR}/unpacked"
  else
    echo "${PROG_DIR}/raw ${PROG_DIR}/unpacked"
  fi
}

# ── Endpoint extraction ───────────────────────────────────────────────────────
extract_endpoints() {
  log "Extracting endpoints from JS..."
  local ep="${PROG_DIR}/findings/endpoints"
  mkdir -p "$ep"
  local out="${ep}/all.txt"
  : > "$out"

  local DIRS; DIRS=$(get_js_dirs)

  if command -v jsluice &>/dev/null; then
    log "  Using jsluice for URL extraction..."
    find $DIRS -type f 2>/dev/null | xargs -r jsluice urls 2>/dev/null | jq -r '.url // empty' 2>/dev/null | sort -u > "$out"
    ok "  jsluice done"
  else
    warn "  jsluice not found — using regex fallback"
  fi

  grep -REohsP '(?:https?:)?//[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{8,}' $DIRS 2>/dev/null >> "$out" || true
  grep -REohsP '["'"'"'`]\K/(?:api|v[0-9]+|auth|oauth|token|user|users|payment|checkout|order|wallet|transaction|kyc|admin|internal|health|metrics|swagger|docs|openapi|bff|merchant|nft|defi|book|hotel|reservation|cart|gift|reward|loyalty|cam|model|stream|broadcast|identity|liveness|biometric|face)[A-Za-z0-9._/-]*(?:\?[^"'"'"'`\s]*)?' \
    $DIRS 2>/dev/null >> "$out" || true
  sort -u "$out" -o "$out"

  grep -iE '(/auth|/login|/logout|/oauth|/token|/session|/signin|/signout|/2fa|/mfa|/verify|/authorize|/sso|/access_token|/refresh_token|/consent|/revoke|/registration|/register|/password)' "$out" | sort -u > "${ep}/auth.txt"
  grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|/grpc|/openapi|/swagger|/bff/|/gateway/)' "$out" | sort -u > "${ep}/api.txt"
  grep -iE '(/admin|/internal|/staff|/management|/backoffice|/_admin|/debug|/test|/health|/metrics|/status|/config)' "$out" | sort -u > "${ep}/admin.txt"
  grep -iE '(/payment|/pay|/checkout|/billing|/invoice|/charge|/refund|/payout|/wallet|/deposit|/withdraw|/transaction|/fund|/balance)' "$out" | sort -u > "${ep}/payment.txt"
  grep -iE '(/defi|/web3|/wallet|/connect|/provider|/rpc|/chain|/blockchain|/contract|/swap|/bridge|/exchange|/trade|/nft)' "$out" | sort -u > "${ep}/crypto.txt"
  grep -iE '(/user/[A-Za-z0-9_-]+|/account/[A-Za-z0-9_-]+|/order/[A-Za-z0-9_-]+|/booking/[A-Za-z0-9_-]+)' "$out" | sort -u > "${ep}/idor_candidates.txt"
  grep -iE '(/cart|/checkout|/shipping|/delivery|/order|/return|/cancel|/coupon|/promo|/discount|/gift|/reward|/loyalty|/points)' "$out" | sort -u > "${ep}/ecommerce.txt"
  grep -iE '(/kyc|/compliance|/verification|/onboarding)' "$out" | sort -u > "${ep}/kyc.txt"
  grep -iE '(/ws|/websocket|/stream|/realtime|/live|/feed|/pricefeed|/ticker|/depth|/orderbook)' "$out" | sort -u > "${ep}/websocket.txt"
  grep -iE '(/notification|/webhook|/push|/email|/sms|/alert|/subscribe)' "$out" | sort -u > "${ep}/notifications.txt"
  grep -iE '(/identity|/liveness|/biometric|/face|/recognition|/capture|/anti-?spoof|/createprocess|/idpay|/idcash|/openfinance)' "$out" | sort -u > "${ep}/identity_liveness.txt"

  ok "Endpoints: $(wc -l < "$out") total"
  ok "  auth=$(wc -l < "${ep}/auth.txt")  api=$(wc -l < "${ep}/api.txt")  admin=$(wc -l < "${ep}/admin.txt")"
  ok "  payment=$(wc -l < "${ep}/payment.txt")  idor=$(wc -l < "${ep}/idor_candidates.txt")"
  ok "  websocket=$(wc -l < "${ep}/websocket.txt")  kyc=$(wc -l < "${ep}/kyc.txt")"
}

# ── Secrets ───────────────────────────────────────────────────────────────────
detect_secrets() {
  log "Scanning for secrets..."
  local sec="${PROG_DIR}/findings/secrets"
  mkdir -p "$sec"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && { warn "No JS files to scan for secrets"; return; }

  if command -v trufflehog &>/dev/null; then
    log "  Running trufflehog (verified + unknown)..."
    trufflehog filesystem $DIRS \
      --no-update --results=verified,unknown --json 2>/dev/null \
      | tee "${sec}/trufflehog.jsonl" \
      | jq -r '[.SourceMetadata.Data.Filesystem.file, .DetectorName, .Raw] | @tsv' \
        2>/dev/null > "${sec}/trufflehog_summary.tsv" || true
    local th; th=$(wc -l < "${sec}/trufflehog_summary.tsv" 2>/dev/null || echo 0)
    ok "  trufflehog: ${th} findings"
  else
    warn "  trufflehog not found — using regex only"
  fi

  local patterns=(
    '(?:api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token)["\s:=]+[A-Za-z0-9/+_-]{24,}'
    'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
    'AKIA[0-9A-Z]{16}'
    '-----BEGIN [A-Z ]*PRIVATE KEY'
    '(?:0x)?[0-9a-fA-F]{64}'
    '(?i)(?:mnemonic|seed.?phrase|recovery.?phrase|secret.?phrase|backup.?phrase)\s*["\s:=]+\s*["\'"'"']?(?:\w+\s+){11,23}\w+["\'"'"']?'
    'gh[pousr]_[A-Za-z0-9]{36,}'
    'AIza[A-Za-z0-9_-]{35}'
    'sk_live_[A-Za-z0-9]{24,}'
    'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'
    'xox[baprs]-[A-Za-z0-9-]{10,}'
    'mongodb(?:\+srv)?://[A-Za-z0-9_:/@.%-]+'
    'postgres(?:ql)?://[A-Za-z0-9_:/@.%-]+'
    '(?:infura|alchemy)[_-]?(?:api[_-]?key|project[_-]?id|token|secret)["\s:=]+[A-Za-z0-9_-]{16,}'
    '(?:stripe|adyen|paypal|braintree)[_-]?(?:api[_-]?key|secret|merchant[_-]?id)["\s:=]+[A-Za-z0-9_-]{12,}'
    'GOCSPX-[A-Za-z0-9_-]{28}'
    '"private_key_id"\s*:\s*"[a-f0-9]{40}"'
  )

  : > "${sec}/regex_hits.txt"
  for pat in "${patterns[@]}"; do
    grep -REinsP "$pat" $DIRS 2>/dev/null | grep -v 'node_modules\|\.test\.\|\.spec\.' >> "${sec}/regex_hits.txt" || true
  done
  grep -v -E '(YOUR_KEY_HERE|example|placeholder|<.*>|TODO|FIXME|xxxxxx|YOUR-|ENTER-|REPLACE)' \
    "${sec}/regex_hits.txt" > "${sec}/hits_filtered.txt" 2>/dev/null || true

  local c; c=$(wc -l < "${sec}/hits_filtered.txt" 2>/dev/null || echo 0)
  [ "$c" -gt 0 ] && crit "${c} secret candidates (hits_filtered.txt)!" || ok "No secrets found via regex"
}

# ── XSS surface ───────────────────────────────────────────────────────────────
detect_xss() {
  log "Scanning for XSS surface..."
  local xss="${PROG_DIR}/findings/xss"
  mkdir -p "$xss"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REinsP '(innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|\.html\s*\(' $DIRS 2>/dev/null | grep -v '\.test\.\|\.spec\.' > "${xss}/dangerous_sinks.txt" || true
  grep -REinsP "(location\.(search|hash|href)|URLSearchParams|getParameter)\s*.*\s*(innerHTML|document\.write|\.html\()" $DIRS 2>/dev/null >> "${xss}/dangerous_sinks.txt" || true
  grep -REinsP 'addEventListener\s*\(\s*["'"'"']message["'"'"']' $DIRS 2>/dev/null > "${xss}/postmessage_handlers.txt" || true
  grep -REinsP "(eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'])" $DIRS 2>/dev/null > "${xss}/eval_usage.txt" || true
  grep -REinsP '(callback\s*=|jsonp\s*=|\?callback=|\&callback=)' $DIRS 2>/dev/null > "${xss}/jsonp_callbacks.txt" || true
  sort -u "${xss}/dangerous_sinks.txt" -o "${xss}/dangerous_sinks.txt" 2>/dev/null || true

  local sc pc; sc=$(wc -l < "${xss}/dangerous_sinks.txt" 2>/dev/null || echo 0)
  pc=$(wc -l < "${xss}/postmessage_handlers.txt" 2>/dev/null || echo 0)
  [ "$sc" -gt 0 ] && warn "${sc} XSS sinks — review ${xss}/dangerous_sinks.txt" || ok "No XSS sinks found"
  [ "$pc" -gt 0 ] && warn "${pc} postMessage handlers — review ${xss}/postmessage_handlers.txt"
  ok "JSONP callbacks: $(wc -l < "${xss}/jsonp_callbacks.txt" 2>/dev/null || echo 0)"
}

# ── CSRF ──────────────────────────────────────────────────────────────────────
detect_csrf() {
  log "Scanning for CSRF surface..."
  local csrf="${PROG_DIR}/findings/csrf"
  mkdir -p "$csrf"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REinsP '(fetch|axios|XMLHttpRequest|\.ajax)\s*\(' $DIRS 2>/dev/null | grep -iE '(POST|PUT|PATCH|DELETE)' | grep -viE '(csrf|xsrf|x-requested-with|authorization|x-api-key)' > "${csrf}/no_token.txt" 2>/dev/null || true
  grep -REinsP '(X-CSRF|X-XSRF|csrf|xsrf|_csrf|csrftoken)' $DIRS 2>/dev/null > "${csrf}/token_usage.txt" || true
  ok "CSRF candidates (no anti-CSRF): $(wc -l < "${csrf}/no_token.txt" 2>/dev/null || echo 0)"
}

# ── WebSocket ─────────────────────────────────────────────────────────────────
detect_ws() {
  log "Scanning for WebSocket endpoints..."
  local ws="${PROG_DIR}/findings/websocket"
  mkdir -p "$ws"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REohsP 'wss?://[A-Za-z0-9._/-]+' $DIRS 2>/dev/null | sort -u > "${ws}/endpoints.txt" || true
  grep -REinsP '(onmessage\s*=|addEventListener\s*\(\s*["'"'"']message["'"'"']|\.on\s*\(\s*["'"'"']message["'"'"'])' $DIRS 2>/dev/null > "${ws}/message_handlers.txt" || true
  grep -REinsP 'ws(\.send|\.emit)\s*\(.*?(auth|token|user|account|payment|admin)' $DIRS 2>/dev/null > "${ws}/sensitive_send.txt" 2>/dev/null || true

  local we mh; we=$(wc -l < "${ws}/endpoints.txt" 2>/dev/null || echo 0)
  mh=$(wc -l < "${ws}/message_handlers.txt" 2>/dev/null || echo 0)
  ok "WS endpoints: ${we} | message handlers: ${mh}"
}

# ── GraphQL ───────────────────────────────────────────────────────────────────
detect_graphql() {
  log "Scanning for GraphQL references..."
  local gql="${PROG_DIR}/findings/graphql"
  mkdir -p "$gql"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REinsP '(__schema|__typename|query\s+\w+\s*\{|mutation\s+\w+\s*\{|gql`|graphql\()' $DIRS 2>/dev/null > "${gql}/usage.txt" || true
  grep -REohsP '["'"'"'`]/graphql[/"'"'"'`]|["'"'"'`]https?://[^"'"'"'`]+/graphql' $DIRS 2>/dev/null | sort -u > "${gql}/endpoints.txt" || true
  local c; c=$(wc -l < "${gql}/usage.txt" 2>/dev/null || echo 0)
  [ "$c" -gt 0 ] && warn "GraphQL detected! Endpoints: $(wc -l < "${gql}/endpoints.txt" 2>/dev/null || echo 0)" || ok "No GraphQL refs"
}

# ── Auth patterns ─────────────────────────────────────────────────────────────
detect_auth() {
  log "Scanning for auth/OAuth patterns..."
  local auth="${PROG_DIR}/findings/auth"
  mkdir -p "$auth"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REinsP '(localStorage|sessionStorage)\.(setItem|getItem)\s*\(' $DIRS 2>/dev/null > "${auth}/storage.txt" || true
  grep -REinsP "(atob\s*\(|jwt_decode|jwtDecode|parseJwt|\.split\s*\(\s*[\"']\.[\"']\s*\)\s*\[[12]\])" $DIRS 2>/dev/null > "${auth}/jwt.txt" || true
  grep -REinsP '(redirect_uri\s*=|response_type\s*=|client_id\s*=|scope\s*=)' $DIRS 2>/dev/null | sort -u > "${auth}/oauth_params.txt" || true
  grep -REinsP "(client_id|client_secret)\s*[:=]\s*[\"'][^\"']{10,}[\"']" $DIRS 2>/dev/null | grep -v -E '(placeholder|example|YOUR_|<|>)' > "${auth}/hardcoded_creds.txt" || true
  grep -REohsP 'process\.env\.[A-Z_]{3,}' $DIRS 2>/dev/null | sort -u > "${auth}/env_vars.txt" || true
  grep -REinsP '(sso|single.?sign.?on|saml|openid|oidc)' $DIRS 2>/dev/null | sort -u > "${auth}/sso.txt" || true
  grep -REinsP '(skip.*2fa|bypass.*mfa|disable.*otp|force.*login|skipVerification)' $DIRS 2>/dev/null > "${auth}/mfa_bypass_hints.txt" || true
  grep -REinsP '(refresh[_-]?token|refreshToken)' $DIRS 2>/dev/null | sort -u > "${auth}/refresh_token.txt" || true

  local hc; hc=$(wc -l < "${auth}/hardcoded_creds.txt" 2>/dev/null || echo 0)
  ok "storage=$(wc -l < "${auth}/storage.txt" 2>/dev/null || echo 0) jwt=$(wc -l < "${auth}/jwt.txt" 2>/dev/null || echo 0) oauth=$(wc -l < "${auth}/oauth_params.txt" 2>/dev/null || echo 0)"
  [ "$hc" -gt 0 ] && crit "${hc} hardcoded OAuth creds!"
}

# ── Payment ───────────────────────────────────────────────────────────────────
detect_payment() {
  log "Scanning for payment patterns..."
  local pay="${PROG_DIR}/findings/payment"
  mkdir -p "$pay"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REinsP '(stripe|adyen|paypal|braintree|klarna|coinbase|binance|moonpay|ramp)' $DIRS 2>/dev/null > "${pay}/providers.txt" || true
  grep -REinsP '(amount|currency|price|total|fee|commission|rate|conversion|slippage|gas|charge)' $DIRS 2>/dev/null > "${pay}/amount_handling.txt" || true
  grep -REinsP '(webhook|callback|return_url|success_url|cancel_url|redirect_url|notify_url)' $DIRS 2>/dev/null > "${pay}/webhooks.txt" || true
  grep -REinsP '(refund|cancel|void|reversal|chargeback|dispute)' $DIRS 2>/dev/null > "${pay}/refund_patterns.txt" || true
  ok "providers=$(wc -l < "${pay}/providers.txt" 2>/dev/null || echo 0) webhooks=$(wc -l < "${pay}/webhooks.txt" 2>/dev/null || echo 0)"
}

# ── Wallet/DeFi ───────────────────────────────────────────────────────────────
detect_wallet() {
  log "Scanning for wallet/DeFi patterns..."
  local w="${PROG_DIR}/findings/wallet"
  mkdir -p "$w"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REinsP '(wallet|defi|web3|ethers|web3js|contract|abi|provider|signer)' $DIRS 2>/dev/null > "${w}/web3_usage.txt" || true
  grep -REinsP '(mnemonic|seed.?phrase|recovery.?phrase|privateKey|keystore)' $DIRS 2>/dev/null > "${w}/seeds.txt" || true
  grep -REinsP '(connectWallet|walletConnect|wc:|wc_url|pairing|sessionRequest)' $DIRS 2>/dev/null > "${w}/wallet_connect.txt" || true
  grep -REinsP '(chainId|chain_id|rpcUrl|rpc_url|network|mainnet|testnet)' $DIRS 2>/dev/null > "${w}/network_config.txt" || true
  grep -REinsP '(postMessage|chrome\.runtime\.sendMessage|port\.postMessage)' $DIRS 2>/dev/null > "${w}/postmessage.txt" || true
  ok "web3=$(wc -l < "${w}/web3_usage.txt" 2>/dev/null || echo 0) seeds=$(wc -l < "${w}/seeds.txt" 2>/dev/null || echo 0)"
}

# ── IDOR ──────────────────────────────────────────────────────────────────────
detect_idor() {
  log "Scanning for IDOR candidates..."
  local idor="${PROG_DIR}/findings/idor"
  mkdir -p "$idor"
  local DIRS; DIRS=$(get_js_dirs)
  [ -z "$(find $DIRS -type f 2>/dev/null | head -1)" ] && return

  grep -REohsP '["'"'"'`](/api/[A-Za-z0-9_/-]*/(user|account|customer|client|order|transaction|payment|wallet|booking|reservation))[/"'"'"'`]?' $DIRS 2>/dev/null | sed 's/["'"'"'`]//g' | sort -u > "${idor}/api_candidates.txt" || true
  grep -REinsP '(admin|impersonate|sudo|masquerade|become|switch.?user|as.?user)' $DIRS 2>/dev/null > "${idor}/admin_impersonation.txt" || true
  ok "IDOR candidates: $(wc -l < "${idor}/api_candidates.txt" 2>/dev/null || echo 0)"
}

# ── Report ────────────────────────────────────────────────────────────────────
generate_report() {
  log "Generating findings report..."
  local f="${PROG_DIR}/findings/REPORT.md"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')

  local js_count=0 ep_count=0 sec_count=0 sec_th=0 xss_count=0 ws_count=0 gql_count=0
  local auth_count=0 pay_count=0 wallet_count=0 idor_count=0 csrf_count=0
  [ -d "${PROG_DIR}/raw" ] && js_count=$(ls "${PROG_DIR}/raw" 2>/dev/null | wc -l)
  [ -f "${PROG_DIR}/findings/endpoints/all.txt" ] && ep_count=$(wc -l < "${PROG_DIR}/findings/endpoints/all.txt")
  [ -f "${PROG_DIR}/findings/secrets/hits_filtered.txt" ] && sec_count=$(wc -l < "${PROG_DIR}/findings/secrets/hits_filtered.txt")
  [ -f "${PROG_DIR}/findings/secrets/trufflehog_summary.tsv" ] && sec_th=$(wc -l < "${PROG_DIR}/findings/secrets/trufflehog_summary.tsv")
  [ -f "${PROG_DIR}/findings/xss/dangerous_sinks.txt" ] && xss_count=$(wc -l < "${PROG_DIR}/findings/xss/dangerous_sinks.txt")
  [ -f "${PROG_DIR}/findings/websocket/endpoints.txt" ] && ws_count=$(wc -l < "${PROG_DIR}/findings/websocket/endpoints.txt")
  [ -f "${PROG_DIR}/findings/graphql/usage.txt" ] && gql_count=$(wc -l < "${PROG_DIR}/findings/graphql/usage.txt")
  [ -f "${PROG_DIR}/findings/auth/hardcoded_creds.txt" ] && auth_count=$(wc -l < "${PROG_DIR}/findings/auth/hardcoded_creds.txt")
  [ -f "${PROG_DIR}/findings/payment/providers.txt" ] && pay_count=$(wc -l < "${PROG_DIR}/findings/payment/providers.txt")
  [ -f "${PROG_DIR}/findings/wallet/web3_usage.txt" ] && wallet_count=$(wc -l < "${PROG_DIR}/findings/wallet/web3_usage.txt")
  [ -f "${PROG_DIR}/findings/idor/api_candidates.txt" ] && idor_count=$(wc -l < "${PROG_DIR}/findings/idor/api_candidates.txt")
  [ -f "${PROG_DIR}/findings/csrf/no_token.txt" ] && csrf_count=$(wc -l < "${PROG_DIR}/findings/csrf/no_token.txt")

  mkdir -p "$(dirname "$f")"
  cat > "$f" <<REPORT
# ${PROGRAM^} — JS Recon Report
**Generated:** ${ts}
**Scope:** \`${DOMAINS}\`

## Summary

| Category | Count |
|---|---|
| JS files downloaded (dedup) | ${js_count} |
| Endpoints extracted | ${ep_count} |
| Secret candidates (regex) | ${sec_count} |
| Secret candidates (trufflehog) | ${sec_th} |
| XSS sinks | ${xss_count} |
| WebSocket endpoints | ${ws_count} |
| GraphQL references | ${gql_count} |
| Hardcoded OAuth creds | ${auth_count} |
| Payment providers | ${pay_count} |
| Web3/Wallet refs | ${wallet_count} |
| IDOR candidates | ${idor_count} |
| CSRF candidates (no token) | ${csrf_count} |

## Findings

### 🔴 Immediate
- [ ] Verify secret candidates: \`findings/secrets/hits_filtered.txt\`
- [ ] Check trufflehog findings: \`findings/secrets/trufflehog_summary.tsv\`
- [ ] Check hardcoded credentials: \`findings/auth/hardcoded_creds.txt\`
- [ ] Review XSS sinks: \`findings/xss/dangerous_sinks.txt\`

### 🟠 High Priority
- [ ] Test endpoints: \`findings/endpoints/all.txt\`
- [ ] Auth endpoints: \`findings/endpoints/auth.txt\`
- [ ] API endpoints: \`findings/endpoints/api.txt\`
- [ ] Admin/internal: \`findings/endpoints/admin.txt\`
- [ ] IDOR candidates: \`findings/idor/api_candidates.txt\`
- [ ] Identity/Liveness: \`findings/endpoints/identity_liveness.txt\`

### 🟡 Medium
- [ ] WebSocket endpoints: \`findings/websocket/endpoints.txt\`
- [ ] GraphQL: \`findings/graphql/usage.txt\`
- [ ] Payment webhooks: \`findings/payment/webhooks.txt\`
- [ ] postMessage handlers: \`findings/xss/postmessage_handlers.txt\`
- [ ] MFA bypass hints: \`findings/auth/mfa_bypass_hints.txt\`

### ⚪ Informational
- [ ] Wallet/DeFi references: \`findings/wallet/\`
- [ ] Auth storage patterns: \`findings/auth/storage.txt\`
- [ ] OAuth params: \`findings/auth/oauth_params.txt\`
- [ ] Env vars exposed: \`findings/auth/env_vars.txt\`

\`\`\`
Trace URL: grep <hash> ${PROG_DIR}/url_map.tsv | cut -f2-
\`\`\`

## Tools Status
- jsluice:     $(command -v jsluice &>/dev/null && echo "✅" || echo "❌ — regex fallback")
- trufflehog:  $(command -v trufflehog &>/dev/null && echo "✅" || echo "❌ — regex only")
- js-beautify: $(command -v js-beautify &>/dev/null && echo "✅" || echo "❌ — raw only")
REPORT
  ok "Report saved: ${f}"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║  Universal JS Recon Pipeline  (.env-Driven)                     ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  ok "Program : ${PROGRAM}"
  ok "Workdir : ${WORKDIR}"
  ok ".env    : ${ENV_FILE}"
  ok "Rate    : ${RATE_LIMIT}/s | Parallel: ${MAX_PARALLEL}"

  check_tools
  load_scope
  collect_js_urls

  echo -e "\n${BOLD}${CYAN}═══ Processing: ${PROGRAM} ═══${RESET}"
  download_js
  fetch_source_maps
  beautify_js
  extract_endpoints
  detect_secrets
  detect_xss
  detect_csrf
  detect_ws
  detect_graphql
  detect_auth
  detect_payment
  detect_wallet
  detect_idor
  generate_report

  echo ""
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${GREEN}  JS Recon Complete: ${PROGRAM}${RESET}"
  echo -e "${BOLD}${GREEN}  Report: ${PROG_DIR}/findings/REPORT.md${RESET}"
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
}

main
