#!/usr/bin/env bash
# setup.sh — One-shot install for dork_scanner.py on Kali Linux
# Run once:  chmod +x setup.sh && sudo ./setup.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[~]${NC} $*"; }
die()   { echo -e "${RED}[!]${NC} $*"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   OSINT Dork Scanner  ·  Kali Setup Script   ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Check OS ───────────────────────────────────────────────────────────────
if ! grep -qi 'kali\|debian\|ubuntu' /etc/os-release 2>/dev/null; then
    warn "Not detected as Kali/Debian/Ubuntu — continuing anyway."
fi

# ── 2. System packages ────────────────────────────────────────────────────────
info "Updating package index..."
apt-get update -qq

info "Installing Python3 + pip..."
apt-get install -y -qq python3 python3-pip python3-venv curl git 2>/dev/null || \
    warn "Some packages already present or could not be installed."

# ── 3. Virtual environment ────────────────────────────────────────────────────
VENV_DIR="$(dirname "$0")/.venv"
info "Creating virtual environment at $VENV_DIR ..."
python3 -m venv "$VENV_DIR"

# ── 4. Python deps ────────────────────────────────────────────────────────────
info "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$(dirname "$0")/requirements.txt"

ok "Python deps installed: duckduckgo-search, colorama, requests"

# ── 5. Make scanner executable and symlink ────────────────────────────────────
SCANNER="$(realpath "$(dirname "$0")/dork_scanner.py")"
chmod +x "$SCANNER"

WRAPPER="/usr/local/bin/dork_scanner"
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python3" "$SCANNER" "\$@"
EOF
chmod +x "$WRAPPER"
ok "Installed system-wide command: dork_scanner"

# ── 6. Optional: theHarvester check ──────────────────────────────────────────
echo ""
info "Checking for theHarvester (already in Kali by default)..."
if command -v theHarvester &>/dev/null; then
    ok "theHarvester found at $(command -v theHarvester)"
    echo "     Tip: theHarvester -d TARGET -b all -l 500"
else
    warn "theHarvester not found. Install with: sudo apt-get install -y theharvester"
fi

# ── 7. Optional: amass / subfinder ────────────────────────────────────────────
info "Checking for amass (subdomain enum)..."
if command -v amass &>/dev/null; then
    ok "amass found"
    echo "     Tip: amass enum -d TARGET"
else
    warn "amass not found. Install: sudo apt-get install -y amass"
fi

info "Checking for subfinder..."
if command -v subfinder &>/dev/null; then
    ok "subfinder found"
else
    warn "subfinder not found. Install: sudo apt-get install -y subfinder"
fi

# ── 8. Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}  Setup complete!${NC}"
echo ""
echo -e "  ${CYAN}Quick start:${NC}"
echo -e "    ${BOLD}dork_scanner -d braintrustcollectivesllp.com${NC}"
echo ""
echo -e "  ${CYAN}Targeted categories only:${NC}"
echo -e "    ${BOLD}dork_scanner -d example.com --cats login files secrets${NC}"
echo ""
echo -e "  ${CYAN}Verbose (print URLs live) + save JSON:${NC}"
echo -e "    ${BOLD}dork_scanner -d example.com -v --json results.json${NC}"
echo ""
echo -e "  ${CYAN}With Google Custom Search API (100 free/day):${NC}"
echo -e "    ${BOLD}dork_scanner -d example.com --google-key AIza... --google-cx 123:abc${NC}"
echo ""
echo -e "  ${CYAN}All options:${NC}"
echo -e "    ${BOLD}dork_scanner --help${NC}"
echo ""
