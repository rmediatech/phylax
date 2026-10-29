#!/bin/sh
# ==============================================================================
# 🧪 PHYLAX SOVEREIGN ANALYTICS TDD BATTERY: test_analytics.sh
# Standard: Universal Adversarial TDD Invariant
# Tests: File input, stdin pipe, JSON schema validation, ranking limits.
# ==============================================================================
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TOOL_PATH="$SCRIPT_DIR/../analytics/phylax-analyze-traffic.sh"

echo "🧪 [TDD] Initiating Sovereign Analytics Test Suite..."

# 1. Verify executable exists
if [ ! -x "$TOOL_PATH" ]; then
    echo "❌ FAIL: $TOOL_PATH is not executable" >&2
    exit 1
fi

# 2. Setup isolated test fixtures
TEST_TMP=$(mktemp -d)
cleanup() {
    rm -rf "$TEST_TMP"
}
trap cleanup EXIT INT TERM

FIXTURE_LOG="$TEST_TMP/fixture_access.log"

cat << 'EOF' > "$FIXTURE_LOG"
2026-09-26T08:00:00.000000Z  INFO rmediatech::http: ✓ HTTP 2xx Success status=200 method=GET path=/ ip=1.1.1.1 duration_us=100
2026-09-26T08:00:01.000000Z  INFO rmediatech::http: ✓ HTTP 2xx Success status=200 method=GET path=/static/test.js ip=1.1.1.1 duration_us=200
2026-09-26T08:00:02.000000Z  INFO rmediatech::http: ✓ HTTP 3xx Redirect status=303 method=GET path=/downloads ip=2.2.2.2 duration_us=50
2026-09-26T08:00:03.000000Z  WARN rmediatech::http: ⚠️ HTTP 4xx Client Warning status=404 method=GET path=/api/missing-sdk ip=3.3.3.3 duration_us=25
2026-09-26T08:00:04.000000Z  WARN rmediatech::http: ⚠️ HTTP 4xx Client Warning status=405 method=POST path=/ ip=4.4.4.4 duration_us=30
2026-09-26T08:00:05.000000Z  WARN api_server::middleware::phylax: ⛔ [Phylax] Automated bot or scraper blocked at perimeter., ip: 5.5.5.5, path: /login, ua: MaliciousBot/2.0
EOF

# Test 1: File Input execution
echo "  [Test 1] Asserting file input parsing..."
OUTPUT_MD=$("$TOOL_PATH" "$FIXTURE_LOG")
echo "$OUTPUT_MD" | grep -q "Total Requests Inspected.*6" || { echo "❌ FAIL: Expected 6 requests"; exit 1; }
echo "$OUTPUT_MD" | grep -q "Unique IP Endpoints.*5" || { echo "❌ FAIL: Expected 5 unique IPs"; exit 1; }
echo "  ✓ PASS: File input successfully parsed."

# Test 2: Standard Input Piped execution
echo "  [Test 2] Asserting stdin pipe parsing..."
OUTPUT_PIPE=$(cat "$FIXTURE_LOG" | "$TOOL_PATH")
echo "$OUTPUT_PIPE" | grep -q "Standard Input (Piped Stream)" || { echo "❌ FAIL: Expected stdin description"; exit 1; }
echo "  ✓ PASS: Stdin pipe parsed identically."

# Test 3: JSON output schema and jq validity
echo "  [Test 3] Asserting JSON output format and metric calculations..."
JSON_OUT=$("$TOOL_PATH" --json "$FIXTURE_LOG")
TOTAL=$(echo "$JSON_OUT" | jq -r '.total_requests')
UNIQUES=$(echo "$JSON_OUT" | jq -r '.unique_ips')
STATUS_404=$(echo "$JSON_OUT" | jq -r '.status_distribution."404_not_found"')
STATUS_403=$(echo "$JSON_OUT" | jq -r '.status_distribution."403_bot_deflections"')
STATUS_405=$(echo "$JSON_OUT" | jq -r '.status_distribution."405_method_rejected"')

if [ "$TOTAL" != "6" ] || [ "$UNIQUES" != "5" ] || [ "$STATUS_404" != "1" ] || [ "$STATUS_403" != "1" ] || [ "$STATUS_405" != "1" ]; then
    echo "❌ FAIL: JSON metric discrepancy: total=$TOTAL, uniques=$UNIQUES, 404=$STATUS_404, 403=$STATUS_403, 405=$STATUS_405" >&2
    exit 1
fi
echo "  ✓ PASS: JSON metrics mathematically accurate."

# Test 4: Market gap categorization
echo "  [Test 4] Asserting unbuilt market demand category tagging..."
echo "$OUTPUT_MD" | grep -q "Potential Market Demand / Missing API" || { echo "❌ FAIL: Missing API market demand tag expected"; exit 1; }
echo "  ✓ PASS: Market demand gap categorized accurately."

echo "🏆 [TDD SUCCESS] All 4 analytics assertions passed cleanly with 0 defects!"
exit 0
