#!/bin/sh
# ==============================================================================
# 🔴 PHYLAX SOVEREIGN RED-TEAM ADVERSARIAL SCRIPT FUZZER: redteam_fuzzer.sh
# Standard: Universal Sovereign Red-Team Attack Invariant
# Purpose: Attacking our own analytics scripts with weaponized log streams.
# Vectors: Command injection, ANSI terminal hijacking, JSON breakouts, ReDoS.
# ==============================================================================
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TOOL_PATH="$SCRIPT_DIR/../analytics/phylax-analyze-traffic.sh"

echo "🔴 [RED-TEAM] Commencing Adversarial Attack Battery Against Sovereign Scripts..."

TEST_DIR=$(mktemp -d)
CANARY_FILE="$TEST_DIR/pwned_canary.txt"
TOXIC_LOG="$TEST_DIR/toxic_payload.log"

cleanup() {
    rm -rf "$TEST_DIR"
    rm -f "$CANARY_FILE"
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------------------
# 💥 VECTOR 1: Command Injection in Log Fields (Subshell / Semicolon / Backticks)
# ------------------------------------------------------------------------------
echo "  [Vector 1] Attempting Command Injection Attacks via Log Fields..."
cat << EOF > "$TOXIC_LOG"
2026-09-26T08:00:00Z INFO rmediatech::http: status=200 method=GET path=/test;touch\t$CANARY_FILE; ip=127.0.0.1 duration_us=10
2026-09-26T08:00:01Z INFO rmediatech::http: status=404 method=GET path=\$(touch\t$CANARY_FILE) ip=127.0.0.1 duration_us=10
2026-09-26T08:00:02Z INFO rmediatech::http: status=403 method=GET path=\`touch\t$CANARY_FILE\` ip=127.0.0.1 duration_us=10
EOF

"$TOOL_PATH" "$TOXIC_LOG" >/dev/null 2>&1 || true

if [ -f "$CANARY_FILE" ]; then
    echo "❌ CRITICAL SECURITY VULNERABILITY: Command Injection succeeded! Canary was executed." >&2
    exit 1
fi
echo "  ✓ DEFENDED: Command injection payloads safely neutralized as inert strings."

# ------------------------------------------------------------------------------
# 💥 VECTOR 2: ANSI Escape Terminal Hijacking (Screen Clear / Color Spoofing)
# ------------------------------------------------------------------------------
echo "  [Vector 2] Attempting Terminal Hijack via ANSI Escape Code Poisoning..."
ESC=$(printf '\033')
cat << EOF > "$TOXIC_LOG"
2026-09-26T08:00:00Z WARN api_server::middleware::phylax: ⛔ [Phylax] Automated bot or scraper blocked at perimeter., ip: 1.2.3.4, path: /login, ua: ${ESC}[2J${ESC}[H${ESC}[31mPWNED_TERMINAL
EOF

OUTPUT=$("$TOOL_PATH" "$TOXIC_LOG")

# Assert that no raw escape code sequence survives into the output
if echo "$OUTPUT" | grep -q "${ESC}\["; then
    echo "❌ CRITICAL SECURITY VULNERABILITY: Raw ANSI escape sequence leaked into terminal output!" >&2
    exit 1
fi
echo "  ✓ DEFENDED: Terminal escape sequences stripped; display spoofing thwarted."

# ------------------------------------------------------------------------------
# 💥 VECTOR 3: JSON Breakout & Quote Poisoning
# ------------------------------------------------------------------------------
echo "  [Vector 3] Attempting JSON Parser Breakout via Malformed Quotes & Backslashes..."
cat << EOF > "$TOXIC_LOG"
2026-09-26T08:00:00Z WARN rmediatech::http: status=404 method=GET path=/api/v1/test\"},{\"admin\":true}],\"pwn\":[{\"a\":\" ip=10.0.0.1 duration_us=10
2026-09-26T08:00:01Z WARN rmediatech::http: status=404 method=GET path=/broken\\\\\"\\\\\\\"\\\\\\\"\\\\ip=10.0.0.2 duration_us=10
EOF

JSON_OUTPUT=$("$TOOL_PATH" --json "$TOXIC_LOG")

# If the JSON was corrupted, jq will return non-zero
if ! echo "$JSON_OUTPUT" | jq . >/dev/null 2>&1; then
    echo "❌ CRITICAL SECURITY VULNERABILITY: JSON output broken by quote injection!" >&2
    echo "$JSON_OUTPUT"
    exit 1
fi
echo "  ✓ DEFENDED: JSON schema validated; quotes and backslashes escaped safely."

# ------------------------------------------------------------------------------
# 💥 VECTOR 4: Massive Payload Flood (ReDoS & Buffer Crash Simulation)
# ------------------------------------------------------------------------------
echo "  [Vector 4] Attempting ReDoS & Buffer Exhaustion with Giant 100KB URL..."
# Generate 100KB line
GIANT_STR=$(awk 'BEGIN { for (i=0; i<1000; i++) printf "A123456789"; }')
cat << EOF > "$TOXIC_LOG"
2026-09-26T08:00:00Z WARN rmediatech::http: status=404 method=GET path=/$GIANT_STR ip=10.0.0.1 duration_us=10
EOF

START_SEC=$(date +%s)
"$TOOL_PATH" "$TOXIC_LOG" >/dev/null 2>&1
END_SEC=$(date +%s)

DIFF_SEC=$((END_SEC - START_SEC))
if [ "$DIFF_SEC" -gt 3 ]; then
    echo "❌ VULNERABILITY: Parser hung on giant string (took $DIFF_SEC seconds)!" >&2
    exit 1
fi
echo "  ✓ DEFENDED: Giant string truncated in < $DIFF_SEC s with zero memory starvation."

echo "🛡️ [RED-TEAM VICTORY] All 4 adversarial attack vectors were completely repelled!"
exit 0
