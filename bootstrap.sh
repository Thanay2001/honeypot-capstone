#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[+] Tripwyre bootstrap starting from: ${SCRIPT_DIR}"



# 1. Basic sanity checks (make sure docker and docker compose are installed)

if ! command -v docker &>/dev/null; then
    echo "[!] docker command not found. Install Docker first."
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo "[!] 'docker compose' (v2) not available. Make sure Docker Compose v2 is installed."
    exit 1
fi



# 2. Ensure required directories exist

# Tripwyre root (Cowrie + Fluent Bit)
mkdir -p "${SCRIPT_DIR}/logs"
mkdir -p "${SCRIPT_DIR}/fb-out"

#Canarytokens-docker (logs for frontend + switchboard)
if [ -d "${SCRIPT_DIR}/canarytokens-docker" ]; then
    mkdir -p "${SCRIPT_DIR}/canarytokens-docker/logs"
else
    echo "[!] WARNING: ${SCRIPT_DIR}/canarytokens-docker not found"
    echo "      Make sure you cloned the canarytokens-docker repo into this directory: ${SCRIPT_DIR}"
fi



# 3. Start Canarytokens stack

if [ -d "${SCRIPT_DIR}/canarytokens-docker" ]; then
    echo "[+] Starting Canarytokens stack..."
    (
        cd "${SCRIPT_DIR}/canarytokens-docker"

        # Quick check that env files exist
        if [ ! -f frontend.env ] || [ ! -f switchboard.env ]; then
            echo "[!] WARNING: frontend.env and/or switchboard.env missing in canarytokens-docker"
            echo "  Copy the .dist files and configure them before running tokens in production."
        fi

        docker compose up -d
    )
else
    echo "[!] Skipping Canarytokens startup (directory not found)."
fi



# 4. Start the rest of the Tripwyre stack (right now Cowrie + Fluent Bit)...

echo "[+] Starting Tripwyre stack (Cowrie + Fluent Bit)..."
(
    cd "${SCRIPT_DIR}"
    docker compose up -d
)


# 5. Show status

echo
echo "[+] Docker containers currently running (filtered for tripwyre/canary):"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | \
    grep -Ei 'cowrie|fluent|canary|tripwyre|nginx' || \
    echo "  (No matching containers found yet - check 'docker ps' for full list."

echo
echo "[+] Bootstrap complete."
echo "  - Canarytokens UI should be at: http://labtokens.local (or your configured domain"
echo "  - Tripwyre Fluent Bit output dir: ${SCRIPT_DIR}/fb-out"
echo "  - Cowrie logs dir:                ${SCRIPT_DIR}/logs"