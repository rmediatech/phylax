#!/bin/sh
# ==============================================================================
# 🛡️ PHYLAX THREAT RECONNAISSANCE & ABUSE INTELLIGENCE: phylax-threat-recon.sh
# Standard: Universal Sovereign Threat Reconnaissance Standard
# Architecture: Pure POSIX /bin/sh - Zero external runtime dependencies.
# Royalty Mode: Automatically discovers hostile ingress entities on Node 1 / host.
# Agnostic Mode: Ingests raw IPs, access logs, or piped streams.
# Intelligence: Enriches IPs with Geo, ISP, ASN, AbuseIPDB confidence & categories.
# Autonomous Action: Optional --report flag dispatches formal dossiers to AbuseIPDB.
# ==============================================================================
set -eu

SCRIPT_NAME="phylax-threat-recon"
VERSION="1.0.0"

# --- Output Formatting Flags ---
OUTPUT_JSON=0
AUTO_REPORT=0
MAX_IPS=10
CUSTOM_IPS=""
PHYLAX_WEBHOOK_URL="${PHYLAX_WEBHOOK_URL:-}"

# --- Print Usage ---
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] [IP_ADDRESSES...]
       cat access.log | $SCRIPT_NAME [OPTIONS]

Sovereign Threat Reconnaissance & Abuse Intelligence Engine (Pure POSIX).
Enriches threat actors with ASN, ISP, Geolocation, AbuseIPDB metrics, and
observed attack vectors.

Options:
  --report          Autonomously dispatch incident dossiers (requires ABUSEIPDB_API_KEY or PHYLAX_WEBHOOK_URL)
  --webhook <URL>   Optional generic webhook URL for SIEM/Discord/Slack/Datadog alerting
  --json            Emit structured JSON rather than Markdown table
  -n <NUM>          Maximum IP entities to investigate (default: 10)
  -h, --help        Show this help message and exit
  -v, --version     Show version and exit

Context Auto-Discovery:
  If no IP or piped log is specified, $SCRIPT_NAME interrogates local
  system journalctl or application / reverse proxy logs for recent 4xx/404 offenders.

Environment:
  ABUSEIPDB_API_KEY Optional API key for AbuseIPDB v2 score check & automated reporting.
  PHYLAX_WEBHOOK_URL Optional Webhook URL for SIEM / external alerting.
EOF
    exit 0
}

# --- Parse Arguments ---
while [ $# -gt 0 ]; do
    case "$1" in
        --report)
            AUTO_REPORT=1
            shift
            ;;
        --webhook)
            shift
            if [ -n "${1:-}" ]; then
                PHYLAX_WEBHOOK_URL="$1"
                shift
            fi
            ;;
        --json)
            OUTPUT_JSON=1
            shift
            ;;
        -n)
            shift
            if [ -n "${1:-}" ]; then
                MAX_IPS="$1"
                shift
            fi
            ;;
        -h|--help)
            usage
            ;;
        -v|--version)
            echo "$SCRIPT_NAME v$VERSION (Sovereign Ecosystem Standard)"
            exit 0
            ;;
        *)
            # Collect positional IP arguments
            if [ -z "$CUSTOM_IPS" ]; then
                CUSTOM_IPS="$1"
            else
                CUSTOM_IPS="$CUSTOM_IPS $1"
            fi
            shift
            ;;
    esac
done

# --- Security / Sanitization Helpers ---
sanitize_string() {
    # Remove control chars, ANSI CSI escapes, and double quotes
    printf '%s' "$1" | tr -d '\000-\037\177"' | sed "s/'//g"
}

# --- Auto-load Threat Intelligence credentials from environment or configs ---
if [ -z "${ABUSEIPDB_API_KEY:-}" ]; then
    if [ -f "$HOME/.env" ]; then
        ABUSEIPDB_API_KEY=$(grep -E '^(export )?ABUSEIPDB_API_KEY=' "$HOME/.env" 2>/dev/null | head -n 1 | cut -d'=' -f2- | tr -d '"'\'' ' || true)
    fi
    if [ -z "${ABUSEIPDB_API_KEY:-}" ] && [ -f "$HOME/.bashrc" ]; then
        ABUSEIPDB_API_KEY=$(grep -E 'ABUSEIPDB_API_KEY=' "$HOME/.bashrc" 2>/dev/null | head -n 1 | cut -d'=' -f2- | tr -d '"'\'' ' || true)
    fi
    if [ -z "${ABUSEIPDB_API_KEY:-}" ]; then
        for cfg in "phylax.toml" "/etc/phylax/phylax.toml" "$HOME/.config/phylax/phylax.toml"; do
            if [ -f "$cfg" ]; then
                ABUSEIPDB_API_KEY=$(grep -E '^api_key\s*=\s*' "$cfg" 2>/dev/null | head -n 1 | cut -d'=' -f2- | tr -d '"'\'' ' || true)
                [ -n "${ABUSEIPDB_API_KEY:-}" ] && break
            fi
        done
    fi
fi

if [ -z "${PHYLAX_WEBHOOK_URL:-}" ]; then
    if [ -f "$HOME/.env" ]; then
        PHYLAX_WEBHOOK_URL=$(grep -E '^(export )?PHYLAX_WEBHOOK_URL=' "$HOME/.env" 2>/dev/null | head -n 1 | cut -d'=' -f2- | tr -d '"'\'' ' || true)
    fi
    if [ -z "${PHYLAX_WEBHOOK_URL:-}" ]; then
        for cfg in "phylax.toml" "/etc/phylax/phylax.toml" "$HOME/.config/phylax/phylax.toml"; do
            if [ -f "$cfg" ]; then
                PHYLAX_WEBHOOK_URL=$(grep -E '^webhook_url\s*=\s*' "$cfg" 2>/dev/null | head -n 1 | cut -d'=' -f2- | tr -d '"'\'' ' || true)
                [ -n "${PHYLAX_WEBHOOK_URL:-}" ] && break
            fi
        done
    fi
fi

# Temporary workspace
TMP_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

CANDIDATES_FILE="$TMP_DIR/candidates.txt"
touch "$CANDIDATES_FILE"

# Snapshot journalctl logs once early if available (for discovery and campaign attribution)
JOURNAL_LOGS="$TMP_DIR/journal_snapshot.log"
touch "$JOURNAL_LOGS"
if command -v journalctl >/dev/null 2>&1; then
    journalctl _UID=$(id -u) -q -n 2000 --no-pager 2>/dev/null > "$JOURNAL_LOGS" || true
    if [ ! -s "$JOURNAL_LOGS" ]; then
        journalctl -q -n 2000 --no-pager 2>/dev/null > "$JOURNAL_LOGS" || true
    fi
fi

# --- Target IP Discovery & Ingestion ---
if [ -n "$CUSTOM_IPS" ]; then
    for ip in $CUSTOM_IPS; do
        echo "$ip" >> "$CANDIDATES_FILE"
    done
else
    # Check if standard input has data (using non-blocking timeout if available)
    if [ ! -t 0 ]; then
        if command -v timeout >/dev/null 2>&1; then
            first_line=$(timeout 0.1 head -n 1 2>/dev/null || true)
            if [ -n "$first_line" ]; then
                STDIN_STREAM="$TMP_DIR/stdin_raw.log"
                printf '%s\n' "$first_line" > "$STDIN_STREAM"
                cat >> "$STDIN_STREAM"
                grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$STDIN_STREAM" | \
                    grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|0\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)' | \
                    sort | uniq -c | sort -nr | head -n "$MAX_IPS" | awk '{print $2}' >> "$CANDIDATES_FILE"
            fi
        fi
    fi

    # Royalty Auto-Discovery Mode: If no candidate IPs from stdin or stdin was empty
    if [ ! -s "$CANDIDATES_FILE" ]; then
        if [ -s "$JOURNAL_LOGS" ]; then
            grep -E "(404|403|405|WARN|Client Warning)" "$JOURNAL_LOGS" 2>/dev/null | \
                grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | \
                grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|0\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)' | \
                sort | uniq -c | sort -nr | head -n "$MAX_IPS" | awk '{print $2}' >> "$CANDIDATES_FILE" || true
        fi

        # Fallback to local files if journalctl yielded nothing
        if [ ! -s "$CANDIDATES_FILE" ]; then
            for log_f in \
                "logs/app.out.log" \
                "logs/access.log" \
                "/var/log/phylax/phylax.log" \
                "/var/log/propylea/propylea.log" \
                "/var/log/syslog" \
                "/var/log/nginx/access.log" \
                "/var/log/caddy/access.log"; do
                if [ -r "$log_f" ]; then
                    grep -E "(404|403|405|WARN|Bot)" "$log_f" 2>/dev/null | \
                        grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | \
                        grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|0\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)' | \
                        sort | uniq -c | sort -nr | head -n "$MAX_IPS" | awk '{print $2}' >> "$CANDIDATES_FILE"
                    break
                fi
            done
        fi
    fi
fi

# Ensure unique candidate list capped at MAX_IPS
sort -u "$CANDIDATES_FILE" | head -n "$MAX_IPS" > "$TMP_DIR/unique_targets.txt"
TARGET_COUNT=$(wc -l < "$TMP_DIR/unique_targets.txt" | tr -d ' ')

if [ "$TARGET_COUNT" -eq 0 ]; then
    if [ "$OUTPUT_JSON" -eq 1 ]; then
        echo '{"status":"empty","inspected_count":0,"entities":[]}'
    else
        echo "ℹ️ [Phylax Threat Recon] No external threat actors detected in current log window."
    fi
    exit 0
fi

# --- Threat Intelligence Reconnaissance Engine ---
RESULTS_JSON="$TMP_DIR/results.json"
echo "[" > "$RESULTS_JSON"
FIRST=1

if [ "$OUTPUT_JSON" -eq 0 ]; then
    cat << EOF
### 🛡️ Phylax Threat Intelligence & Entity Reconnaissance

* **Target Entities Investigated:** \`$TARGET_COUNT\`
* **AbuseIPDB Integration:** $( [ -n "${ABUSEIPDB_API_KEY:-}" ] && echo "🟢 Active (Authenticated)" || echo "⚪ Passive (Public RDAP)" )
* **Auto-Reporting Mode:** $( [ "$AUTO_REPORT" -eq 1 ] && echo "🚨 Enabled (--report)" || echo "🔒 Monitoring Only" )

| Attacker IP | Organization / ISP | ASN | Location | Abuse Score | Attack Campaign Detected | Action Taken |
| :--- | :--- | :---: | :---: | :---: | :--- | :---: |
EOF
fi

while IFS= read -r ip; do
    [ -z "$ip" ] && continue

    # 1. Fetch IP-API Geo & ASN Data
    GEO_RAW=$(curl -s -m 3 "http://ip-api.com/json/$ip?fields=status,country,regionName,city,isp,org,as" 2>/dev/null || echo '{"status":"fail"}')
    
    COUNTRY="Unknown"
    CITY=""
    ISP="Unknown ISP"
    ASN="Unknown"

    if echo "$GEO_RAW" | grep -q '"status":"success"'; then
        COUNTRY=$(echo "$GEO_RAW" | grep -o '"country":"[^"]*"' | cut -d'"' -f4 || echo "Unknown")
        CITY=$(echo "$GEO_RAW" | grep -o '"city":"[^"]*"' | cut -d'"' -f4 || echo "")
        ISP=$(echo "$GEO_RAW" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4 || echo "Unknown ISP")
        ASN=$(echo "$GEO_RAW" | grep -o '"as":"[^"]*"' | cut -d'"' -f4 | cut -d' ' -f1 || echo "Unknown")
    fi

    # 2. Query AbuseIPDB v2 if API key is present
    ABUSE_SCORE="N/A"
    TOTAL_REPORTS=0
    if [ -n "${ABUSEIPDB_API_KEY:-}" ]; then
        ABUSE_RAW=$(curl -s -G "https://api.abuseipdb.com/api/v2/check" \
            --data-urlencode "ipAddress=$ip" \
            -H "Key: $ABUSEIPDB_API_KEY" \
            -H "Accept: application/json" 2>/dev/null || echo '{}')
        
        if echo "$ABUSE_RAW" | grep -q '"abuseConfidenceScore"'; then
            ABUSE_SCORE=$(echo "$ABUSE_RAW" | grep -o '"abuseConfidenceScore":[0-9]*' | cut -d':' -f2 || echo "0")
            TOTAL_REPORTS=$(echo "$ABUSE_RAW" | grep -o '"totalReports":[0-9]*' | cut -d':' -f2 || echo "0")
        fi
    fi

    # 3. Detect Attack Campaign from Local Ingress Logs
    CAMPAIGN="Reconnaissance Scan"
    LOG_MATCHES=""
    if [ -s "${JOURNAL_LOGS:-}" ]; then
        LOG_MATCHES=$(grep "$ip" "$JOURNAL_LOGS" 2>/dev/null | grep -E "(GET|POST|HEAD|OPTIONS)" | head -n 3 || true)
    fi

    if echo "$LOG_MATCHES" | grep -qiE "(\.env|config\.php|credential)"; then
        CAMPAIGN="Credential & Environment Spray"
    elif echo "$LOG_MATCHES" | grep -qiE "(\.\./|\%2e\%2e|bin/sh|pathscan)"; then
        CAMPAIGN="Path Traversal & RCE Probe"
    elif echo "$LOG_MATCHES" | grep -qiE "(solr|actuator|admin/cores|api/session)"; then
        CAMPAIGN="Enterprise Actuator / Metabase RCE"
    elif echo "$LOG_MATCHES" | grep -qiE "(mcp|sse)"; then
        CAMPAIGN="Model Context Protocol (MCP) Scraper"
    elif echo "$LOG_MATCHES" | grep -qiE "(wp-|wordpress|xmlrpc)"; then
        CAMPAIGN="WordPress Vulnerability Scan"
    fi

    # 4. Autonomous Abuse Reporting
    REPORT_STATUS="Monitored"
    if [ "$AUTO_REPORT" -eq 1 ]; then
        if [ -n "${ABUSEIPDB_API_KEY:-}" ]; then
            REPORT_COMMENT="Phylax Edge Perimeter Defense caught unauthorized attack probe ($CAMPAIGN) from $ip against sovereign services."
            DISPATCH_RESP=$(curl -s "https://api.abuseipdb.com/api/v2/report" \
                -H "Key: $ABUSEIPDB_API_KEY" \
                -H "Accept: application/json" \
                --data-urlencode "ip=$ip" \
                --data-urlencode "categories=15,21" \
                --data-urlencode "comment=$REPORT_COMMENT" 2>/dev/null || echo '{}')
            
            if echo "$DISPATCH_RESP" | grep -q '"abuseConfidenceScore"'; then
                REPORT_STATUS="🚨 AbuseIPDB Reported"
            else
                REPORT_STATUS="⚠️ AbuseIPDB Failed"
            fi
        fi

        if [ -n "${PHYLAX_WEBHOOK_URL:-}" ]; then
            WH_PAYLOAD=$(printf '{"event":"threat_detected","ip":"%s","asn":"%s","isp":"%s","campaign":"%s"}' \
                "$ip" "$ASN" "$(sanitize_string "$ISP")" "$CAMPAIGN")
            if curl -s -X POST -H "Content-Type: application/json" -d "$WH_PAYLOAD" "$PHYLAX_WEBHOOK_URL" 2>/dev/null >/dev/null; then
                if [ "$REPORT_STATUS" = "Monitored" ]; then
                    REPORT_STATUS="🚨 Webhook Alerted"
                else
                    REPORT_STATUS="$REPORT_STATUS + Webhook"
                fi
            else
                if [ "$REPORT_STATUS" = "Monitored" ]; then
                    REPORT_STATUS="⚠️ Webhook Failed"
                fi
            fi
        fi
    fi

    # Location formatting
    LOC_STR="$COUNTRY"
    [ -n "$CITY" ] && LOC_STR="$CITY, $COUNTRY"

    SCORE_DISPLAY="$ABUSE_SCORE"
    if [ "$ABUSE_SCORE" != "N/A" ]; then
        if [ "$ABUSE_SCORE" -ge 75 ]; then
            SCORE_DISPLAY="🔴 $ABUSE_SCORE% ($TOTAL_REPORTS rpts)"
        elif [ "$ABUSE_SCORE" -ge 25 ]; then
            SCORE_DISPLAY="🟡 $ABUSE_SCORE%"
        else
            SCORE_DISPLAY="🟢 $ABUSE_SCORE%"
        fi
    fi

    # Output Markdown Row
    if [ "$OUTPUT_JSON" -eq 0 ]; then
        echo "| **\`$ip\`** | $(sanitize_string "$ISP") | \`$ASN\` | $(sanitize_string "$LOC_STR") | $SCORE_DISPLAY | $(sanitize_string "$CAMPAIGN") | $REPORT_STATUS |"
    fi

    # Build JSON Record
    [ "$FIRST" -eq 0 ] && echo "," >> "$RESULTS_JSON"
    cat << JSON_ITEM >> "$RESULTS_JSON"
  {
    "ip": "$ip",
    "isp": "$ISP",
    "asn": "$ASN",
    "location": "$LOC_STR",
    "abuse_confidence_score": "$ABUSE_SCORE",
    "total_reports": $TOTAL_REPORTS,
    "attack_campaign": "$CAMPAIGN",
    "action": "$REPORT_STATUS"
  }
JSON_ITEM
    FIRST=0
done < "$TMP_DIR/unique_targets.txt"

echo "]" >> "$RESULTS_JSON"

if [ "$OUTPUT_JSON" -eq 1 ]; then
    cat "$RESULTS_JSON"
fi
