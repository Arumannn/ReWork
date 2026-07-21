#!/usr/bin/env bash
# Port Scanning (masscan + nmap) — requires root for masscan
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${RED}[!]${RESET} $*"; }

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$WORKDIR"

source .env 2>/dev/null || true
MASSCAN_RATE="${MASSCAN_RATE:-1000}"
THREADS="${THREADS:-50}"
NULL=/dev/null

PORTS="21,22,25,53,80,110,143,443,465,587,993,995,1080,2082,2083,3000,4443,5000,5432,6379,7001,8000,8008,8080,8081,8443,8888,9000,9200,11211,27017,30000"

echo -e "${BOLD}${CYAN}═══ Port Scanning (requires root) ═══${RESET}"

# Build IPs from resolved subs
if [ -f subs/resolved.txt ]; then
  awk '{print $2}' subs/resolved.txt | sort -u > ports/ips.txt
  ok "IPs to scan: $(wc -l < ports/ips.txt)"
else
  warn "subs/resolved.txt not found — run phase 2 first"
  exit 1
fi

# ── masscan ──
if command -v masscan &>/dev/null; then
  log "Running masscan (rate=$MASSCAN_RATE)..."
  masscan -iL ports/ips.txt -p "$PORTS" --rate "$MASSCAN_RATE" \
    --wait 0 --open-only \
    -oJ ports/masscan.json 2>$NULL || true
  jq -r '.[] | [.ip, (.ports[] | "\(.port)/\(.proto)")] | @tsv' \
    ports/masscan.json 2>$NULL | sort -u > ports/open_ports_raw.txt || true
  ok "masscan done: $(wc -l < ports/open_ports_raw.txt 2>$NULL || echo 0) open ports found"
else
  warn "masscan not available"
  exit 1
fi

# ── nmap ──
if command -v nmap &>/dev/null && [ -s ports/open_ports_raw.txt ]; then
  log "nmap service detection on open ports..."
  awk '{ip=$1; port=$2; gsub(/\/.*/,"",port); ips[ip]=ips[ip]?ips[ip]","port:port} END{for(i in ips) print i, ips[i]}' \
    ports/open_ports_raw.txt > ports/ip_ports.txt 2>$NULL || true
  while read -r ip ports; do
    nmap -p "$ports" -sV --open -T4 --max-retries 1 \
      --host-timeout 2m "$ip" -oN "ports/nmap_${ip}.txt" 2>$NULL || true
  done < ports/ip_ports.txt
  ok "nmap service detection complete"
elif [ ! -s ports/open_ports_raw.txt ]; then
  log "No open ports found — skipping nmap"
else
  warn "nmap not available"
fi
