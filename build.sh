#!/usr/bin/env bash
#
# Build standalone binary with PyInstaller + bundled Chromium
#
# Output: dist/ipsec_vpn_test/
#   - ipsec_vpn_test          (executable)
#   - config.yaml.example     (copy to config.yaml and edit)
#   - ms-playwright/          (bundled Chromium browser)
#
# Usage after build:
#   cd dist/ipsec_vpn_test
#   cp config.yaml.example config.yaml   # edit with your settings
#   ./ipsec_vpn_test wizard|custom|all
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[BUILD]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Find Python 3.9+ ──
find_python() {
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
            local major minor
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "$major" -eq 3 ] && [ "$minor" -ge 9 ]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON=$(find_python) || error "Python 3.9+ required"
info "Python: $PYTHON ($($PYTHON --version))"

# ── Setup build venv ──
BUILD_VENV="$SCRIPT_DIR/.build_venv"
if [ ! -d "$BUILD_VENV" ]; then
    info "Creating build virtual environment..."
    "$PYTHON" -m venv "$BUILD_VENV"
fi
source "$BUILD_VENV/bin/activate"

info "Installing build dependencies..."
pip install --quiet --upgrade pip
pip install --quiet pyinstaller playwright pyyaml

# ── Install Chromium if needed ──
info "Ensuring Chromium browser is installed..."
playwright install chromium

# ── Locate browser path ──
BROWSERS_BASE=""
for d in "$HOME/Library/Caches/ms-playwright" "$HOME/.cache/ms-playwright"; do
    if [ -d "$d" ]; then
        BROWSERS_BASE="$d"
        break
    fi
done
[ -d "$BROWSERS_BASE" ] || error "Cannot find Playwright browsers directory"

CHROMIUM_DIR=$(ls -d "$BROWSERS_BASE"/chromium-* 2>/dev/null | head -1)
[ -d "$CHROMIUM_DIR" ] || error "Chromium not found in $BROWSERS_BASE"
CHROMIUM_VER=$(basename "$CHROMIUM_DIR")
info "Chromium: $CHROMIUM_VER ($(du -sh "$CHROMIUM_DIR" | cut -f1))"

# ── Build with PyInstaller (without Chromium binary) ──
info "Building with PyInstaller..."

rm -rf "$SCRIPT_DIR/dist" "$SCRIPT_DIR/build" "$SCRIPT_DIR/ipsec_vpn_test.spec"

pyinstaller \
    --name ipsec_vpn_test \
    --onedir \
    --noconfirm \
    --clean \
    --collect-all playwright \
    --hidden-import yaml \
    --hidden-import playwright \
    --hidden-import playwright.async_api \
    --hidden-import playwright.sync_api \
    "$SCRIPT_DIR/ipsec_vpn_test.py"

DIST_DIR="$SCRIPT_DIR/dist/ipsec_vpn_test"

# ── Copy Chromium into dist (bypass PyInstaller codesign issues) ──
info "Copying Chromium browser into dist..."
DIST_BROWSERS="$DIST_DIR/_internal/ms-playwright/$CHROMIUM_VER"
mkdir -p "$DIST_BROWSERS"
cp -a "$CHROMIUM_DIR/." "$DIST_BROWSERS/"
info "Chromium copied to _internal/ms-playwright/$CHROMIUM_VER"

# ── Copy config example & create screenshots dir ──
cp "$SCRIPT_DIR/config.yaml.example" "$DIST_DIR/"
mkdir -p "$DIST_DIR/screenshots"

# ── Verify ──
DIST_SIZE=$(du -sh "$DIST_DIR" | cut -f1)

info ""
info "Build complete!"
info "Output: $DIST_DIR ($DIST_SIZE)"
info ""
echo "Distribution contents:"
echo "  $(ls "$DIST_DIR/ipsec_vpn_test" && echo "ipsec_vpn_test (executable)")"
echo "  config.yaml.example"
echo "  screenshots/"
echo "  _internal/ (Python runtime + Playwright + Chromium)"
echo ""
info "Usage:"
info "  cd dist/ipsec_vpn_test"
info "  cp config.yaml.example config.yaml   # edit with your settings"
info "  ./ipsec_vpn_test wizard              # or: custom, all"
info ""
info "Note: sshpass must be installed on the target machine."

# ── Cleanup build artifacts ──
deactivate 2>/dev/null || true
rm -rf "$BUILD_VENV" "$SCRIPT_DIR/build" "$SCRIPT_DIR/ipsec_vpn_test.spec"
