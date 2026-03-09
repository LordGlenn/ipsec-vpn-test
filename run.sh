#!/usr/bin/env bash
#
# IPSec VPN Automated Test — Bootstrap Runner
#
# Usage:
#   ./run.sh wizard    Run Wizard VPN test
#   ./run.sh custom    Run Custom VPN tests (5 combinations)
#   ./run.sh all       Run both
#
# First run will automatically:
#   1. Create Python virtual environment (.venv)
#   2. Install dependencies (playwright, pyyaml)
#   3. Install Chromium browser
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON_SCRIPT="$SCRIPT_DIR/ipsec_vpn_test.py"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
CONFIG_EXAMPLE="$SCRIPT_DIR/config.yaml.example"

# ── Color output ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Usage ──
if [ $# -eq 0 ] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 <mode>"
    echo ""
    echo "Modes:"
    echo "  wizard    Run Wizard VPN test (IKEv2 Policy-Based)"
    echo "  custom    Run Custom VPN tests (5 IKEv1/IKEv2 combinations)"
    echo "  all       Run both wizard and custom tests"
    echo ""
    echo "First run will automatically set up the environment."
    exit 0
fi

MODE="$1"
if [[ "$MODE" != "wizard" && "$MODE" != "custom" && "$MODE" != "all" ]]; then
    error "Invalid mode: $MODE"
    echo "Valid modes: wizard, custom, all"
    exit 1
fi

# ── Find Python 3 ──
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

PYTHON_CMD=$(find_python) || {
    error "Python 3.9+ is required but not found."
    echo "Please install Python 3.9 or later:"
    echo "  macOS:  brew install python3"
    echo "  Ubuntu: sudo apt install python3"
    exit 1
}
info "Using Python: $PYTHON_CMD ($($PYTHON_CMD --version))"

# ── Check sshpass ──
if ! command -v sshpass &>/dev/null; then
    warn "sshpass is not installed. SSH-based tests will fail."
    echo "  Install:"
    echo "    macOS:  brew install hudochenkov/sshpass/sshpass"
    echo "    Ubuntu: sudo apt install sshpass"
    echo ""
    read -rp "Continue anyway? [y/N] " yn
    [[ "$yn" =~ ^[Yy] ]] || exit 1
fi

# ── Check config.yaml ──
if [ ! -f "$CONFIG_FILE" ]; then
    if [ -f "$CONFIG_EXAMPLE" ]; then
        warn "config.yaml not found. Copying from config.yaml.example..."
        cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
        echo ""
        error "Please edit config.yaml with your actual settings before running."
        echo "  $CONFIG_FILE"
        exit 1
    else
        error "config.yaml not found and no example file available."
        exit 1
    fi
fi

# ── Setup virtual environment ──
if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment..."
    "$PYTHON_CMD" -m venv "$VENV_DIR"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# ── Install dependencies ──
if ! python -c "import playwright" &>/dev/null || ! python -c "import yaml" &>/dev/null; then
    info "Installing Python dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet playwright pyyaml
fi

# ── Install Chromium browser ──
if ! python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); p.chromium.executable_path; p.stop()" &>/dev/null 2>&1; then
    info "Installing Chromium browser (first time only)..."
    playwright install chromium
fi

# ── Run test ──
info "Starting test: $MODE"
echo ""
PYTHONUNBUFFERED=1 python "$PYTHON_SCRIPT" "$MODE"
