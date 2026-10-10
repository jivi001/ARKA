#!/usr/bin/env bash
# ARKA Allowlisted TCP_CONNECT Capability Wrapper
# Strictly parses host and port arguments; outputs bounded JSON result envelope.
set -euo pipefail

TARGET_HOST="${1:-}"
TARGET_PORT="${2:-}"
TIMEOUT_SECS="${3:-5}"

if [[ -z "$TARGET_HOST" || -z "$TARGET_PORT" ]]; then
    echo '{"error": "Missing target host or port", "connected": false}'
    exit 1
fi

# Validate numeric port 1..65535
if ! [[ "$TARGET_PORT" =~ ^[0-9]+$ ]] || [ "$TARGET_PORT" -lt 1 ] || [ "$TARGET_PORT" -gt 65535 ]; then
    echo '{"error": "Invalid port number", "connected": false}'
    exit 2
fi

START_TIME=$(date +%s%N)
# Bounded TCP probe using /dev/tcp or nc
if timeout "${TIMEOUT_SECS}" bash -c "exec 3<>/dev/tcp/${TARGET_HOST}/${TARGET_PORT}" 2>/dev/null; then
    END_TIME=$(date +%s%N)
    LATENCY_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    echo "{\"status\": \"CONNECTED\", \"host\": \"${TARGET_HOST}\", \"port\": ${TARGET_PORT}, \"latency_ms\": ${LATENCY_MS}}"
    exit 0
else
    echo "{\"status\": \"CONNECTION_REFUSED_OR_TIMED_OUT\", \"host\": \"${TARGET_HOST}\", \"port\": ${TARGET_PORT}}"
    exit 3
fi
