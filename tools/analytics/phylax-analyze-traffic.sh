#!/bin/sh
# ==============================================================================
# 🛡️ PHYLAX SOVEREIGN ANALYTICS ENGINE: phylax-analyze-traffic.sh
# Standard: Universal Sovereign Observability Standard
# Architecture: Pure POSIX /bin/sh - Zero external runtime dependencies.
# Royalty Mode: Automatically discovers local project logs if none provided.
# Agnostic Mode: Ingests any access log or JSON stream via pipe or argument.
# Security: Defensively sanitized against log poisoning and terminal injection.
# ==============================================================================
set -eu

SCRIPT_NAME="phylax-analyze-traffic"
VERSION="1.0.0"

# --- Output Formatting Flags ---
OUTPUT_JSON=0
MAX_RESULTS=10
INPUT_FILE=""

# --- Print Usage ---
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] [LOG_FILE]
       cat access.log | $SCRIPT_NAME [OPTIONS]

Sovereign Traffic & Security Intelligence Engine (Pure POSIX).
Operates in Universal Agnostic Mode or Native Context Auto-Discovery Mode.

Options:
  --json            Emit structured JSON rather than Markdown table
  -n <NUM>          Maximum entries to display in top rankings (default: 10)
  -h, --help        Show this help message and exit
  -v, --version     Show version and exit

Context Auto-Discovery:
  If no LOG_FILE or pipe is specified, $SCRIPT_NAME checks the current
  environment for local application logs, gateway logs, or system journalctl.
EOF
    exit 0
}

# --- Parse Arguments ---
while [ $# -gt 0 ]; do
    case "$1" in
        --json)
            OUTPUT_JSON=1
            shift
            ;;
        -n)
            shift
            if [ -n "${1:-}" ]; then
                MAX_RESULTS="$1"
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
        -*)
            echo "Error: Unknown flag '$1'" >&2
            echo "Run '$SCRIPT_NAME --help' for usage." >&2
            exit 1
            ;;
        *)
            if [ -z "$INPUT_FILE" ]; then
                INPUT_FILE="$1"
                shift
            else
                echo "Error: Multiple input files specified: '$INPUT_FILE' and '$1'" >&2
                exit 1
            fi
            ;;
    esac
done

# --- Royalty Context Auto-Discovery ---
# If no file was passed and stdin is a terminal, search for project native logs
AUTO_DISCOVERED_DESC="Standard Input (Piped Stream)"
TMP_STREAM=""

cleanup() {
    if [ -n "$TMP_STREAM" ] && [ -f "$TMP_STREAM" ]; then
        rm -f "$TMP_STREAM"
    fi
}
trap cleanup EXIT INT TERM

if [ -z "$INPUT_FILE" ]; then
    if [ ! -t 0 ]; then
        if command -v timeout >/dev/null 2>&1; then
            first_line=$(timeout 0.1 head -n 1 2>/dev/null || true)
            if [ -n "$first_line" ]; then
                TMP_STREAM=$(mktemp)
                printf '%s\n' "$first_line" > "$TMP_STREAM"
                cat >> "$TMP_STREAM"
                INPUT_FILE="$TMP_STREAM"
                AUTO_DISCOVERED_DESC="Standard Input (Piped Stream)"
            fi
        fi
    fi

    # Auto-Discovery Mode (when stdin is empty or interactive)
    if [ -z "$INPUT_FILE" ]; then
        if [ -f "logs/app.out.log" ]; then
            INPUT_FILE="logs/app.out.log"
            AUTO_DISCOVERED_DESC="Application Native Log (logs/app.out.log)"
        elif [ -f "logs/access.log" ]; then
            INPUT_FILE="logs/access.log"
            AUTO_DISCOVERED_DESC="Web Server Access Log (logs/access.log)"
        elif [ -f "propylea.log" ]; then
            INPUT_FILE="propylea.log"
            AUTO_DISCOVERED_DESC="Edge Gateway Log"
        fi

        # Fallback to host journalctl or syslog if running on a live server node
        if [ -z "$INPUT_FILE" ] && command -v journalctl >/dev/null 2>&1; then
            TMP_STREAM=$(mktemp)
            if journalctl _UID=$(id -u) -n 2000 --no-pager > "$TMP_STREAM" 2>/dev/null && [ -s "$TMP_STREAM" ]; then
                INPUT_FILE="$TMP_STREAM"
                AUTO_DISCOVERED_DESC="Host Ingress Journal (User UID $(id -u), Last 2000 events)"
            elif journalctl -n 2000 --no-pager > "$TMP_STREAM" 2>/dev/null && [ -s "$TMP_STREAM" ]; then
                INPUT_FILE="$TMP_STREAM"
                AUTO_DISCOVERED_DESC="Host System Journal (Last 2000 events)"
            else
                rm -f "$TMP_STREAM"
                TMP_STREAM=""
            fi
        fi

        if [ -z "$INPUT_FILE" ] && [ -r "/var/log/syslog" ]; then
            INPUT_FILE="/var/log/syslog"
            AUTO_DISCOVERED_DESC="System Log (/var/log/syslog)"
        fi

        if [ -z "$INPUT_FILE" ]; then
            echo "Error: No log file specified and no native project log auto-discovered." >&2
            echo "Usage: $SCRIPT_NAME [OPTIONS] [LOG_FILE] or pipe via stdin." >&2
            exit 1
        fi
    fi
else
    AUTO_DISCOVERED_DESC="Specified File: $INPUT_FILE"
    if [ ! -r "$INPUT_FILE" ]; then
        echo "Error: Cannot read input file '$INPUT_FILE'" >&2
        exit 1
    fi
fi

# ==============================================================================
# 🧠 SOVEREIGN LOG PARSING & THREAT CORRELATION ENGINE (POSIX AWK)
# Hardened against terminal injection, null bytes, and malicious payloads.
# ==============================================================================
awk -v max_rank="$MAX_RESULTS" \
    -v as_json="$OUTPUT_JSON" \
    -v source_desc="$AUTO_DISCOVERED_DESC" '
BEGIN {
    total_requests = 0;
    count_2xx = 0;
    count_3xx = 0;
    count_4xx = 0;
    count_5xx = 0;
    count_403_bot = 0;
    count_404_notfound = 0;
    count_405_method = 0;
    count_429_ratelimit = 0;
    total_latency_us = 0;
    latency_samples = 0;
}

# --- Defensive String Sanitization ---
function sanitize(str) {
    # Strip ANSI escape sequences and control characters (\000-\037, \177)
    gsub(/\033\[[0-9;]*[a-zA-Z]/, "", str);
    gsub(/[\000-\037\177]/, "", str);
    # Defensively percent-encode backslashes and quotes (RFC 3986) to prevent JSON breakouts
    gsub(/\\/, "%5C", str);
    gsub(/"/, "%22", str);
    # Truncate overly long strings to prevent memory abuse
    if (length(str) > 128) {
        str = substr(str, 1, 125) "...";
    }
    return str;
}

function extract_subnet(ip) {
    # Extract IPv4 /24 subnet or truncated IPv6 prefix
    if (index(ip, ".") > 0) {
        split(ip, octets, ".");
        if (length(octets) >= 3) {
            return octets[1] "." octets[2] "." octets[3] ".0/24";
        }
    } else if (index(ip, ":") > 0) {
        split(ip, colons, ":");
        if (length(colons) >= 3) {
            return colons[1] ":" colons[2] ":" colons[3] "::/48";
        }
    }
    return ip;
}

{
    line = $0;
    if (length(line) == 0) next;

    status = 0;
    method = "";
    path = "";
    ip = "";
    latency = 0;

    # --- Matcher 1: Structured Key-Value Web Service Logger ---
    # Example: status=200 method=GET path=/ ip=1.2.3.4 duration_us=123
    if (line ~ /status=[0-9]+/) {
        if (match(line, /status=([0-9]+)/)) {
            substr_match = substr(line, RSTART + 7, RLENGTH - 7);
            status = substr_match + 0;
        }
        if (match(line, /method=([A-Z]+)/)) {
            method = substr(line, RSTART + 7, RLENGTH - 7);
        }
        if (match(line, /path=([^ ]+)/)) {
            path = substr(line, RSTART + 5, RLENGTH - 5);
        }
        if (match(line, /ip=([0-9a-fA-F.:]+)/)) {
            ip = substr(line, RSTART + 3, RLENGTH - 3);
        }
        if (match(line, /duration_us=([0-9]+)/)) {
            substr_dur = substr(line, RSTART + 12, RLENGTH - 12);
            latency = substr_dur + 0;
        }
    }
    # --- Matcher 2: Standard Combined / Caddy / Nginx Access Log ---
    # Example: 1.2.3.4 - - [date] "GET /path HTTP/1.1" 200 123
    else if (match(line, /^([0-9a-fA-F.:]+) - [^"]*"([A-Z]+) ([^ "]+)[^"]*" ([0-9]{3})/)) {
        split(line, parts, " ");
        ip = parts[1];
        # Locate the quoted request
        idx = index(line, "\"");
        if (idx > 0) {
            req_part = substr(line, idx + 1);
            idx_end = index(req_part, "\"");
            if (idx_end > 0) {
                req_str = substr(req_part, 1, idx_end - 1);
                split(req_str, req_fields, " ");
                method = req_fields[1];
                path = req_fields[2];
                rest = substr(req_part, idx_end + 2);
                split(rest, rest_fields, " ");
                status = rest_fields[1] + 0;
            }
        }
    }
    # --- Matcher 3: Phylax WAF Perimeter Interceptions ---
    # Example: ⛔ [Phylax] Automated bot or scraper blocked at perimeter., ip: 198.51.100.42, path: /login, ua: GPTBot/1.4
    else if (line ~ /\[Phylax\]/) {
        status = 403;
        method = "BOT_WAF";
        if (match(line, /ip: ([0-9a-fA-F.:]+)/)) {
            ip = substr(line, RSTART + 4, RLENGTH - 4);
        }
        if (match(line, /path: ([^,]+)/)) {
            path = substr(line, RSTART + 6, RLENGTH - 6);
        }
        if (match(line, /ua: (.+)$/)) {
            bot_ua = substr(line, RSTART + 4, RLENGTH - 4);
            bot_ua = sanitize(bot_ua);
            bot_agents[bot_ua]++;
        }
    }

    # If extracted successfully, record statistics
    if (status > 0) {
        total_requests++;
        path = sanitize(path);
        ip = sanitize(ip);
        method = sanitize(method);

        # Strip query params from path for clean aggregation
        q_idx = index(path, "?");
        base_path = (q_idx > 0) ? substr(path, 1, q_idx - 1) : path;
        if (length(base_path) == 0) base_path = "/";

        # Track unique IPs & Subnets
        if (length(ip) > 0) {
            unique_ips[ip]++;
            subnet = extract_subnet(ip);
            subnets[subnet]++;
        }

        # Status category tracking
        if (status >= 200 && status < 300) {
            count_2xx++;
        } else if (status >= 300 && status < 400) {
            count_3xx++;
        } else if (status >= 400 && status < 500) {
            count_4xx++;
            if (status == 403) count_43_bot++;
            else if (status == 404) {
                count_404_notfound++;
                paths_404[base_path]++;
            } else if (status == 405) {
                count_405_method++;
                method_probes[method " " base_path]++;
            } else if (status == 429) {
                count_429_ratelimit++;
            }
        } else if (status >= 500) {
            count_5xx++;
        }

        # Track latency if reported
        if (latency > 0) {
            total_latency_us += latency;
            latency_samples++;
        }

        paths_all[base_path]++;
        methods[method]++;
    }
}

END {
    # Calculate Unique Metrics
    total_unique_ips = 0;
    for (i in unique_ips) total_unique_ips++;

    avg_latency_us = (latency_samples > 0) ? int(total_latency_us / latency_samples) : 0;

    if (as_json == 1) {
        # --- JSON OUTPUT ---
        printf "{\n";
        printf "  \"source\": \"%s\",\n", source_desc;
        printf "  \"total_requests\": %d,\n", total_requests;
        printf "  \"unique_ips\": %d,\n", total_unique_ips;
        printf "  \"avg_latency_us\": %d,\n", avg_latency_us;
        printf "  \"status_distribution\": {\n";
        printf "    \"2xx_success\": %d,\n", count_2xx;
        printf "    \"3xx_redirect\": %d,\n", count_3xx;
        printf "    \"4xx_client_warning\": %d,\n", count_4xx;
        printf "    \"404_not_found\": %d,\n", count_404_notfound;
        printf "    \"403_bot_deflections\": %d,\n", count_43_bot;
        printf "    \"405_method_rejected\": %d,\n", count_405_method;
        printf "    \"429_rate_limited\": %d,\n", count_429_ratelimit;
        printf "    \"5xx_server_error\": %d\n", count_5xx;
        printf "  },\n";

        # Top 404 Market / Threat Gaps
        printf "  \"top_404_probes\": [\n";
        n = 0;
        # Simple sorting in AWK
        for (p in paths_404) {
            n++;
            arr_p[n] = p;
            arr_c[n] = paths_404[p];
        }
        for (i = 1; i <= n; i++) {
            for (j = i + 1; j <= n; j++) {
                if (arr_c[j] > arr_c[i]) {
                    tmp_c = arr_c[i]; arr_c[i] = arr_c[j]; arr_c[j] = tmp_c;
                    tmp_p = arr_p[i]; arr_p[i] = arr_p[j]; arr_p[j] = tmp_p;
                }
            }
        }
        printed = 0;
        limit = (n < max_rank) ? n : max_rank;
        for (i = 1; i <= limit; i++) {
            if (printed > 0) printf ",\n";
            printf "    {\"path\": \"%s\", \"hits\": %d}", arr_p[i], arr_c[i];
            printed++;
        }
        printf "\n  ]\n";
        printf "}\n";
    } else {
        # --- SOVEREIGN MARKDOWN TABLE OUTPUT ---
        printf "### 📊 Sovereign Intelligence & Traffic Audit Report\n\n";
        printf "* **Ingress Stream:** `%s`\n", source_desc;
        printf "* **Total Requests Inspected:** `%d`\n", total_requests;
        printf "* **Unique IP Endpoints:** `%d`\n", total_unique_ips;
        if (avg_latency_us > 0) {
            printf "* **Average Upstream Latency:** `%d µs` (%.2f ms)\n", avg_latency_us, avg_latency_us / 1000.0;
        }
        printf "\n#### 1. Ingress Status & Deflection Breakdown\n\n";
        printf "| HTTP Category | Count | Percentage | Sovereign Role / Action |\n";
        printf "| :--- | :--- | :--- | :--- |\n";
        
        pct_2xx = (total_requests > 0) ? (count_2xx * 100.0 / total_requests) : 0;
        pct_3xx = (total_requests > 0) ? (count_3xx * 100.0 / total_requests) : 0;
        pct_4xx = (total_requests > 0) ? (count_4xx * 100.0 / total_requests) : 0;
        pct_5xx = (total_requests > 0) ? (count_5xx * 100.0 / total_requests) : 0;

        printf "| **`2xx Success`** | %d | %.1f%% | Nominal traffic / static assets |\n", count_2xx, pct_2xx;
        printf "| **`3xx Redirect`** | %d | %.1f%% | Canonical URL & Auth routing |\n", count_3xx, pct_3xx;
        printf "| **`4xx Warnings`** | %d | %.1f%% | Bot deflections & unmapped probes |\n", count_4xx, pct_4xx;
        printf "| • *404 Not Found* | *%d* | - | Threat Harvester candidates / Missing paths |\n", count_404_notfound;
        printf "| • *403 Bot Trapped* | *%d* | - | Headless scrapers deflecting at edge |\n", count_43_bot;
        printf "| • *405 Method Block* | *%d* | - | Root POST/PUT injection deflections |\n", count_405_method;
        printf "| • *429 Throttled* | *%d* | - | Token-bucket sliding limit active |\n", count_429_ratelimit;
        printf "| **`5xx Server Error`** | %d | %.1f%% | Server faults (**Zero-defect goal**) |\n", count_5xx, pct_5xx;

        # Top 404 Market Gaps / Threat Vectors
        n = 0;
        for (p in paths_404) {
            n++;
            arr_p[n] = p;
            arr_c[n] = paths_404[p];
        }
        for (i = 1; i <= n; i++) {
            for (j = i + 1; j <= n; j++) {
                if (arr_c[j] > arr_c[i]) {
                    tmp_c = arr_c[i]; arr_c[i] = arr_c[j]; arr_c[j] = tmp_c;
                    tmp_p = arr_p[i]; arr_p[i] = arr_p[j]; arr_p[j] = tmp_p;
                }
            }
        }

        if (n > 0) {
            printf "\n#### 2. Unmapped Probes & Market Demand Gaps (Top 404s)\n\n";
            printf "> Probed paths indicate either hostile reconnaissance campaigns (elevated to Layer 13) or unbuilt user demand.\n\n";
            printf "| Path Probed | Ingress Hits | Threat / Market Category |\n";
            printf "| :--- | :--- | :--- |\n";
            limit = (n < max_rank) ? n : max_rank;
            for (i = 1; i <= limit; i++) {
                path_str = arr_p[i];
                category = "Unknown Probe";
                if (index(path_str, "wp-") > 0 || index(path_str, "xmlrpc") > 0) category = "WordPress Exploit Scanner";
                else if (index(path_str, "env") > 0 || index(path_str, "config") > 0 || index(path_str, "claude") > 0) category = "Credential / Secret Harvester";
                else if (index(path_str, "session") > 0 || index(path_str, "actuator") > 0) category = "Spring / Java Actuator Probe";
                else if (index(path_str, "sitemap") > 0 || index(path_str, "robots") > 0) category = "SEO Discovery / Crawler";
                else if (index(path_str, "api") > 0 || index(path_str, "sdk") > 0) category = "🔥 **Potential Market Demand / Missing API**";
                else if (index(path_str, "login") > 0 || index(path_str, "admin") > 0) category = "Admin Interface Reconnaissance";

                printf "| `%s` | %d | %s |\n", path_str, arr_c[i], category;
            }
        }

        # Top Hostile Subnets
        m = 0;
        for (s in subnets) {
            m++;
            arr_sub[m] = s;
            arr_sub_c[m] = subnets[s];
        }
        for (i = 1; i <= m; i++) {
            for (j = i + 1; j <= m; j++) {
                if (arr_sub_c[j] > arr_sub_c[i]) {
                    tmp_c = arr_sub_c[i]; arr_sub_c[i] = arr_sub_c[j]; arr_sub_c[j] = tmp_c;
                    tmp_s = arr_sub[i]; arr_sub[i] = arr_sub[j]; arr_sub[j] = tmp_s;
                }
            }
        }

        if (m > 0) {
            printf "\n#### 3. Top Active Ingress Subnets (IPv4 /24 Correlation)\n\n";
            printf "| Subnet / CIDR | Total Ingress Requests |\n";
            printf "| :--- | :--- |\n";
            limit = (m < max_rank) ? m : max_rank;
            for (i = 1; i <= limit; i++) {
                printf "| `%s` | %d |\n", arr_sub[i], arr_sub_c[i];
            }
        }
        printf "\n";
    }
}
' "$INPUT_FILE"
