#!/usr/bin/env bash
# Test whether Cloudflare's DoH server accepts a TLS 0-RTT resumption token
# obtained from one source IP when reconnecting from a different source IP.
#
# The test connects first via IPv4, saves the resumption token, then connects
# via IPv6 loading that token to attempt 0-RTT.
#
# Usage:
#   ./test/test-0rtt-cross-ip.sh [path-to-neqo-client]
#
# If no path is given, the script builds neqo-client first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# A DNS query for example.com A record, base64url-encoded wire format.
# Wire format: ID=0, QR=0, RD=1, QDCOUNT=1, QNAME=example.com, QTYPE=A, QCLASS=IN
DOH_URL="https://cloudflare-dns.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

if [[ $# -ge 1 ]]; then
    CLIENT="$1"
else
    echo "==> Building neqo-client..."
    cargo build --release --bin neqo-client --manifest-path "$REPO_ROOT/Cargo.toml"
    CLIENT="$REPO_ROOT/target/release/neqo-client"
fi

if [[ ! -x "$CLIENT" ]]; then
    echo "ERROR: neqo-client not found or not executable: $CLIENT"
    exit 1
fi

TOKEN_FILE="$(mktemp /tmp/neqo-resumption-token.XXXXXX)"
trap 'rm -f "$TOKEN_FILE"' EXIT

# Flags common to both connections.
COMMON_ARGS=(-vv -H "accept: application/dns-message" --output-read-data "$DOH_URL")

echo
echo "==> Step 1: Connect via IPv4, fetch DoH response, save resumption token"
echo "    URL: $DOH_URL"
echo

IPV4_OUTPUT=$("$CLIENT" -4 --save-token "$TOKEN_FILE" "${COMMON_ARGS[@]}" 2>&1) || true
echo "$IPV4_OUTPUT"

if [[ ! -s "$TOKEN_FILE" ]]; then
    echo
    echo "FAIL: No resumption token was saved (token file is empty)."
    echo "      The server may not have issued a session ticket, or the IPv4 connection failed."
    exit 1
fi

echo
echo "    Resumption token saved ($(wc -c < "$TOKEN_FILE") bytes)."

echo
echo "==> Step 2: Connect via IPv6, load token, attempt 0-RTT"
echo "    URL: $DOH_URL"
echo

IPV6_OUTPUT=$("$CLIENT" -6 --load-token "$TOKEN_FILE" "${COMMON_ARGS[@]}" 2>&1) || true
echo "$IPV6_OUTPUT"

echo
echo "==> Result"

if grep -q "ZeroRttRejected" <<< "$IPV6_OUTPUT"; then
    echo "RESULT: 0-RTT REJECTED"
    echo "        Cloudflare rejected the token obtained over IPv4 when used from IPv6."
    echo "        The server does NOT allow 0-RTT token reuse across different source IPs."
    exit 0
fi

# 0-RTT was attempted if RequestsCreatable fires before the handshake completes
# (i.e. before "Connection established").  With 0-RTT, the client sends requests
# at t=0 while the handshake is still in flight.
if awk '/RequestsCreatable/{saw=1} /Connection established/{exit !saw}' <<< "$IPV6_OUTPUT" \
   && grep -q "StateChange(Connected)" <<< "$IPV6_OUTPUT"; then
    echo "RESULT: 0-RTT ACCEPTED"
    echo "        RequestsCreatable fired before the handshake completed (0-RTT data was sent)"
    echo "        and the server did not reject it.  Cloudflare accepts cross-IP 0-RTT token reuse."
    exit 0
fi

if grep -q "StateChange(Connected)" <<< "$IPV6_OUTPUT"; then
    echo "RESULT: TOKEN LOADED BUT 0-RTT NOT ATTEMPTED"
    echo "        The IPv6 connection succeeded but 0-RTT was not attempted."
    echo "        The token may have been for a different QUIC version or lacked 0-RTT support."
    exit 0
fi

echo "RESULT: INCONCLUSIVE"
echo "        The IPv6 connection did not complete.  Check the verbose output above."
exit 1
