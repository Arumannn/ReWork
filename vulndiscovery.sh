#!/usr/bin/env bash
# =============================================================================
#  Vulnerability Discovery Pipeline (standalone)
#
#  Reads output from recon_framework.sh and runs:
#    1. Subdomain Takeover Check
#    2. CVE & Misconfig Scanning (nuclei)
#    3. CORS Misconfiguration
#    4. Open Redirect Discovery
#    5. XSS Scanning (dalfox)
#    6. SQL Injection (sqlmap)
#    7. API Security Audit (nuclei)
#
#  USAGE:
#    bash vulndiscovery.sh [workdir]
#
#  INPUT (from recon_framework.sh):
#    <workdir>/http/live_urls.txt
#    <workdir>/subs/live_hosts_filtered.txt  (or live_hosts.txt)
#    <workdir>/urls/params_merged.txt
#    <workdir>/urls/api_urls.txt
#    <workdir>/urls/all_urls_final.txt
# =============================================================================
set -euo pipefail

WORKDIR="${1:-$PWD}"
WORKDIR="$(cd "$WORKDIR" 2>/dev/null && pwd)" || { echo "workdir not found: ${1:-$PWD}"; exit 1; }
cd "$WORKDIR"

source .env 2>/dev/null || true
: "${RL_LIGHT:=10}" "${RL_MEDIUM:=50}" "${RL_AGGRESSIVE:=100}" "${THREADS:=5}"
NULL=/dev/null

RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; RESET='\033[0m'; BOLD='\033[1m'
log()   { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${ORANGE}[!]${RESET} $*"; }
crit()  { echo -e "${RED}[CRIT]${RESET} ${BOLD}$*${RESET}"; }
header(){ echo -e "\n${BOLD}${CYAN}═══ $* ═══${RESET}"; }

# Auth
AUTH_ARGS=()
[ -n "${AUTH_COOKIE:-}" ] && AUTH_ARGS+=(-H "Cookie: $AUTH_COOKIE")
[ -n "${AUTH_HEADER:-}" ]  && AUTH_ARGS+=(-H "$AUTH_HEADER")

check_input() {
  if [ ! -f http/live_urls.txt ] || [ ! -s http/live_urls.txt ]; then
    crit "http/live_urls.txt not found. Run recon_framework.sh Phase 2 first."; exit 1
  fi
  ok "Using http/live_urls.txt ($(wc -l < http/live_urls.txt) URLs)"
}

# ── 1. Subdomain Takeover ───────────────────────────────────────────────────
check_takeover() {
  header "1 — Subdomain Takeover Check"
  if command -v nuclei &>/dev/null; then
    nuclei -l http/live_urls.txt -tags takeover -rl "$RL_MEDIUM" \
      -severity medium,high,critical "${AUTH_ARGS[@]}" \
      2>$NULL >> http/takeover.txt || true
    sort -u http/takeover.txt -o http/takeover.txt 2>$NULL || true
    ok "  Takeover findings: $(wc -l < http/takeover.txt 2>$NULL || echo 0)"
  else
    warn "  nuclei not available — skipping"
  fi
}

# ── 2. CVE & Misconfig ──────────────────────────────────────────────────────
check_cve() {
  header "2 — CVE & Misconfig Scanning"
  if command -v nuclei &>/dev/null; then
    nuclei -l http/live_urls.txt \
      -tags exposure,misconfig,cve,config,backup,disclosure \
      -exclude-tags ssl,tls,dos,fuzz,intrusive,token-spray,creds-stuffing,brute-force \
      -severity medium,high,critical -exclude-severity info \
      -rl "$RL_MEDIUM" "${AUTH_ARGS[@]}" \
      2>$NULL >> http/nuclei_findings.txt || true
    sort -u http/nuclei_findings.txt -o http/nuclei_findings.txt 2>$NULL || true
    ok "  Nuclei findings: $(wc -l < http/nuclei_findings.txt 2>$NULL || echo 0)"
  else
    warn "  nuclei not available — skipping"
  fi
}

# ── 3. CORS ──────────────────────────────────────────────────────────────────
check_cors() {
  header "3 — CORS Misconfiguration"
  local host_list="subs/live_hosts_filtered.txt"
  [ ! -f "$host_list" ] && host_list="subs/live_hosts.txt"

  if command -v nuclei &>/dev/null; then
    nuclei -l http/live_urls.txt -tags cors -rl "$RL_MEDIUM" \
      2>$NULL >> http/cors_findings.txt || true
  fi

  for target in $(head -10 "$host_list" 2>$NULL); do
    for origin in "https://evil.com" "https://${target}.evil.com" "null"; do
      curl -sk "https://${target}/" -H "Origin: $origin" -I \
        2>$NULL | grep -i 'access-control' >> http/cors_manual.txt || true
    done
  done
  sort -u http/cors_findings.txt -o http/cors_findings.txt 2>$NULL || true
  ok "  CORS checks done ($(wc -l < http/cors_findings.txt 2>$NULL || echo 0) findings)"
}

# ── 4. Open Redirect ────────────────────────────────────────────────────────
check_open_redirect() {
  header "4 — Open Redirect"
  grep -oE 'https?://[^"'"'"'<> ]*(redirect|return|continue|next|url|goto|dest|target)=https?://' \
    urls/all_urls_final.txt >> urls/open_redirect_candidates.txt 2>$NULL || true
  sort -u urls/open_redirect_candidates.txt -o urls/open_redirect_candidates.txt 2>$NULL || true
  ok "  Open redirect candidates: $(wc -l < urls/open_redirect_candidates.txt 2>$NULL || echo 0)"
}

# ── 5. XSS ───────────────────────────────────────────────────────────────────
check_xss() {
  header "5 — XSS Scanning"
  if command -v dalfox &>/dev/null; then
    head -100 urls/params_merged.txt 2>$NULL \
      | dalfox pipe --mining-dom --mining-dict --rate-limit "$RL_LIGHT" \
        2>$NULL >> http/xss_findings.txt || true
    sort -u http/xss_findings.txt -o http/xss_findings.txt 2>$NULL || true
    ok "  XSS findings: $(wc -l < http/xss_findings.txt 2>$NULL || echo 0)"
  else
    warn "  dalfox not available — skipping"
  fi
}

# ── 6. SQL Injection ────────────────────────────────────────────────────────
check_sqli() {
  header "6 — SQL Injection"
  if command -v sqlmap &>/dev/null; then
    head -10 urls/params_merged.txt 2>$NULL \
      | xargs -I{} sqlmap -u "{}" --batch --level=1 --risk=1 \
        --random-agent --output-dir=api/sqlmap 2>$NULL || true
    ok "  SQLMap scan complete"
  else
    warn "  sqlmap not available — skipping"
  fi
}

# ── 7. API Security Audit ───────────────────────────────────────────────────
check_api() {
  header "7 — API Security Audit"
  if [ -f urls/api_urls.txt ] && [ -s urls/api_urls.txt ]; then
    if command -v nuclei &>/dev/null; then
      nuclei -l urls/api_urls.txt -tags api,graphql,jwt \
        -rl "$RL_LIGHT" "${AUTH_ARGS[@]}" \
        2>$NULL >> http/api_vulns.txt || true
      sort -u http/api_vulns.txt -o http/api_vulns.txt 2>$NULL || true
    fi
    ok "  API security checks done ($(wc -l < http/api_vulns.txt 2>$NULL || echo 0) findings)"
  else
    warn "  urls/api_urls.txt not found — skipping API audit"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  Vulnerability Discovery Pipeline  (standalone)             ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  ok "Workdir: ${WORKDIR}"

  check_input

  check_takeover
  check_cve
  check_cors
  check_open_redirect
  check_xss
  check_sqli
  check_api

  echo ""
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${GREEN}  Vulnerability Discovery Complete!${RESET}"
  echo -e "${BOLD}${GREEN}  Results in: http/ (takeover, nuclei, cors, xss, api)${RESET}"
  echo -e "${BOLD}${GREEN}  SQLMap: api/sqlmap/${RESET}"
  echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
}

main
