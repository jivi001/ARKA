#!/usr/bin/env bash
# ARKA Allowlisted TCP_CONNECT Capability Wrapper
# Strictly parses host and port arguments; outputs bounded JSON result envelope.
# Neutralizes VULN-001 (CWE-78 Command Injection) via strict character allowlisting
# and positional parameter passing without shell command interpolation.
set -euo pipefail

TARGET_HOST="${1:-}"
TARGET_PORT="${2:-}"
TIMEOUT_SECS="${3:-5}"

if [[ -z "$TARGET_HOST" || -z "$TARGET_PORT" ]]; then
    echo '{"error": "Missing target host or port", "connected": false}'
    exit 1
fi

# Reject hostnames exceeding RFC maximum length (253 characters)
if [ "${#TARGET_HOST}" -gt 253 ]; then
    echo '{"error": "Target host length exceeds maximum limit of 253 characters", "connected": false}'
    exit 2
fi

# Strictly allowlist hostname, IPv4, and IPv6 characters (alphanumeric, dot, hyphen, colon)
# Explicitly rejects quotes, semicolons, backticks, dollar signs, spaces, control chars, and slashes
if ! [[ "$TARGET_HOST" =~ ^[a-zA-Z0-9.:-]+$ ]]; then
    echo '{"error": "Illegal characters in target host", "connected": false}'
    exit 2
fi

# Additional defense: reject leading or consecutive hyphens and dots if present
if [[ "$TARGET_HOST" =~ (^[-.]|\.\.|--) ]]; then
    echo '{"error": "Malformed target host structure", "connected": false}'
    exit 2
fi

# Validate numeric port 1..65535
if ! [[ "$TARGET_PORT" =~ ^[0-9]+$ ]] || [ "$TARGET_PORT" -lt 1 ] || [ "$TARGET_PORT" -gt 65535 ]; then
    echo '{"error": "Invalid port number", "connected": false}'
    exit 2
fi

# Validate numeric timeout 1..300
if ! [[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]] || [ "$TIMEOUT_SECS" -lt 1 ] || [ "$TIMEOUT_SECS" -gt 300 ]; then
    TIMEOUT_SECS=5
fi

# Escape any potential quote/backslash in TARGET_HOST for safe JSON serialization
SAFE_HOST=$(printf '%s' "$TARGET_HOST" | sed 's/\\/\\\\/g; s/"/\\"/g')

START_TIME=$(date +%s%N)

# Safe probe: positional parameters "$1" and "$2" prevent subshell string interpretation
if timeout "${TIMEOUT_SECS}" bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "${TARGET_HOST}" "${TARGET_PORT}" 2>/dev/null; then
    END_TIME=$(date +%s%N)
    LATENCY_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    echo "{\"status\": \"CONNECTED\", \"host\": \"${SAFE_HOST}\", \"port\": ${TARGET_PORT}, \"latency_ms\": ${LATENCY_MS}}"
    exit 0
else
    echo "{\"status\": \"CONNECTION_REFUSED_OR_TIMED_OUT\", \"host\": \"${SAFE_HOST}\", \"port\": ${TARGET_PORT}}"
    exit 3
fi
