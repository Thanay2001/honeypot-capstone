#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[+] Stopping Tripwyre stack (Cowrie + Fluent Bit)..."
(
    cd "${SCRIPT_DIR}"
    docker compose down
)

if [ -d "${SCRIPT_DIR}/canarytokens-docker" ]; then
    echo "[+] Stopping Canarytokens stack..."
    (
        cd "${SCRIPT_DIR}/canarytokens-docker"
        docker compose down
    )
else
    echo "${SCRIPT_DIR}/canarytokens-docker not found, failed to stop canarytokens-docker"
    echo "Use docker ps to see if the containers are still running, you may need to stop them manually"
fi

echo "[+] All stacks stopped."