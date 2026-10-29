# ==============================================================================
# [Phylax] PHYLAX SOVEREIGN ANALYTICS ENGINE: phylax-analyze-traffic.ps1
# Standard: Universal Sovereign Observability Standard
# Architecture: Native PowerShell Core (Windows & Cross-Platform).
# Royalty Mode: Automatically discovers local project logs if none provided.
# Agnostic Mode: Ingests any access log or JSON stream via pipe or argument.
# Security: Defensively sanitized against log poisoning and injection.
# ==============================================================================
[CmdletBinding()]
param (
    [Parameter(Position = 0, ValueFromPipeline = $true)]
    [string]$InputPath,

    [switch]$Json,

    [int]$Top = 10,

    [switch]$Version
)

$ScriptVersion = "1.0.0"

if ($Version) {
    Write-Output "phylax-analyze-traffic.ps1 v$ScriptVersion (Sovereign Ecosystem Standard)"
    exit 0
}

# --- Defensive Sanitization Helper ---
function Sanitize-String ([string]$raw) {
    if ([string]::IsNullOrEmpty($raw)) { return "" }
    # Strip ANSI escape sequences and non-printable control characters
    $clean = $raw -replace '\x1B\[[0-9;]*[a-zA-Z]', ''
    $clean = $clean -replace '[\x00-\x1F\x7F]', ''
    # Defensively percent-encode backslashes and quotes (RFC 3986)
    $clean = $clean -replace '\\', '%5C'
    $clean = $clean -replace '"', '%22'
    if ($clean.Length -gt 128) {
        $clean = $clean.Substring(0, 125) + "..."
    }
    return $clean
}

function Extract-Subnet ([string]$ip) {
    if ($ip.Contains('.')) {
        $parts = $ip.Split('.')
        if ($parts.Length -ge 3) {
            return "$($parts[0]).$($parts[1]).$($parts[2]).0/24"
        }
    } elseif ($ip.Contains(':')) {
        $parts = $ip.Split(':')
        if ($parts.Length -ge 3) {
            return "$($parts[0]):$($parts[1]):$($parts[2])::/48"
        }
    }
    return $ip
}

# --- Context Auto-Discovery ("Royalty Mode") ---
$SourceDesc = "Standard Input Pipe"
$Lines = @()

if ($InputPath -and (Test-Path $InputPath)) {
    $SourceDesc = "File: $InputPath"
    $Lines = Get-Content -Path $InputPath
} elseif ($Input) {
    $Lines = $Input
} else {
    # Attempt local auto-discovery
    if (Test-Path "logs/app.out.log") {
        $SourceDesc = "Application Native Log (logs/app.out.log)"
        $Lines = Get-Content -Path "logs/app.out.log" -Tail 2000
    } elseif (Test-Path "propylea.log") {
        $SourceDesc = "Propylea Gateway Log"
        $Lines = Get-Content -Path "propylea.log" -Tail 2000
    } else {
        Write-Error "Error: No log file specified and no native project log auto-discovered.`nUsage: .\phylax-analyze-traffic.ps1 [-InputPath <log_file>] [-Json] [-Top 10]"
        exit 1
    }
}

# --- Metrics Aggregators ---
$TotalRequests = 0
$Count2xx = 0
$Count3xx = 0
$Count4xx = 0
$Count5xx = 0
$Count404 = 0
$Count403Bot = 0
$Count405Method = 0
$Count429Rate = 0
$TotalLatencyUs = 0
$LatencySamples = 0

$UniqueIPs = @{}
$Subnets = @{}
$Paths404 = @{}
$Methods = @{}

foreach ($line in $Lines) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    $status = 0
    $method = ""
    $path = ""
    $ip = ""
    $latency = 0

    # Axum / RMediaTech format
    if ($line -match 'status=(\d+)') {
        $status = [int]$Matches[1]
        if ($line -match 'method=([A-Z]+)') { $method = $Matches[1] }
        if ($line -match 'path=([^ ]+)') { $path = $Matches[1] }
        if ($line -match 'ip=([0-9a-fA-F.:]+)') { $ip = $Matches[1] }
        if ($line -match 'duration_us=(\d+)') { $latency = [int64]$Matches[1] }
    }
    # Combined / Nginx format
    elseif ($line -match '^([0-9a-fA-F.:]+) - [^"]*"([A-Z]+) ([^ "]+)[^"]*" (\d{3})') {
        $ip = $Matches[1]
        $method = $Matches[2]
        $path = $Matches[3]
        $status = [int]$Matches[4]
    }
    # Phylax WAF block
    elseif ($line -match '\[Phylax\]') {
        $status = 403
        $method = "BOT_WAF"
        if ($line -match 'ip: ([0-9a-fA-F.:]+)') { $ip = $Matches[1] }
        if ($line -match 'path: ([^,]+)') { $path = $Matches[1] }
    }

    if ($status -gt 0) {
        $TotalRequests++
        $path = Sanitize-String $path
        $ip = Sanitize-String $ip
        $method = Sanitize-String $method

        $basePath = if ($path.Contains('?')) { $path.Split('?')[0] } else { $path }
        if ([string]::IsNullOrEmpty($basePath)) { $basePath = "/" }

        if ($ip) {
            $UniqueIPs[$ip] = $true
            $sub = Extract-Subnet $ip
            if (-not $Subnets.ContainsKey($sub)) { $Subnets[$sub] = 0 }
            $Subnets[$sub]++
        }

        if ($status -ge 200 -and $status -lt 300) { $Count2xx++ }
        elseif ($status -ge 300 -and $status -lt 400) { $Count3xx++ }
        elseif ($status -ge 400 -and $status -lt 500) {
            $Count4xx++
            if ($status -eq 403) { $Count403Bot++ }
            elseif ($status -eq 404) {
                $Count404++
                if (-not $Paths404.ContainsKey($basePath)) { $Paths404[$basePath] = 0 }
                $Paths404[$basePath]++
            }
            elseif ($status -eq 405) { $Count405Method++ }
            elseif ($status -eq 429) { $Count429Rate++ }
        }
        elseif ($status -ge 500) { $Count5xx++ }

        if ($latency -gt 0) {
            $TotalLatencyUs += $latency
            $LatencySamples++
        }
    }
}

$AvgLatencyUs = if ($LatencySamples -gt 0) { [int]($TotalLatencyUs / $LatencySamples) } else { 0 }
$UniqueIPCount = $UniqueIPs.Keys.Count

if ($Json) {
    $Top404List = $Paths404.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | ForEach-Object {
        @{ path = $_.Key; hits = $_.Value }
    }

    $Result = [PSCustomObject]@{
        source = $SourceDesc
        total_requests = $TotalRequests
        unique_ips = $UniqueIPCount
        avg_latency_us = $AvgLatencyUs
        status_distribution = [PSCustomObject]@{
            "2xx_success" = $Count2xx
            "3xx_redirect" = $Count3xx
            "4xx_client_warning" = $Count4xx
            "404_not_found" = $Count404
            "403_bot_deflections" = $Count403Bot
            "405_method_rejected" = $Count405Method
            "429_rate_limited" = $Count429Rate
            "5xx_server_error" = $Count5xx
        }
        top_404_probes = $Top404List
    }

    $Result | ConvertTo-Json -Depth 4
} else {
    Write-Output "### [Phylax] Sovereign Intelligence & Traffic Audit Report (PowerShell)"
    Write-Output ""
    Write-Output ("* **Ingress Stream:** ``{0}``" -f $SourceDesc)
    Write-Output ("* **Total Requests Inspected:** ``{0}``" -f $TotalRequests)
    Write-Output ("* **Unique IP Endpoints:** ``{0}``" -f $UniqueIPCount)
    if ($AvgLatencyUs -gt 0) {
        $ms = [math]::Round($AvgLatencyUs / 1000.0, 2)
        Write-Output ("* **Average Upstream Latency:** ``{0} us`` ({1} ms)" -f $AvgLatencyUs, $ms)
    }
    Write-Output ""
    Write-Output "#### 1. Ingress Status & Deflection Breakdown"
    Write-Output ""
    Write-Output "| HTTP Category | Count | Percentage | Sovereign Role / Action |"
    Write-Output "| :--- | :--- | :--- | :--- |"
    
    $p2 = if ($TotalRequests -gt 0) { [math]::Round(($Count2xx * 100.0 / $TotalRequests), 1) } else { 0 }
    $p3 = if ($TotalRequests -gt 0) { [math]::Round(($Count3xx * 100.0 / $TotalRequests), 1) } else { 0 }
    $p4 = if ($TotalRequests -gt 0) { [math]::Round(($Count4xx * 100.0 / $TotalRequests), 1) } else { 0 }
    $p5 = if ($TotalRequests -gt 0) { [math]::Round(($Count5xx * 100.0 / $TotalRequests), 1) } else { 0 }

    Write-Output ("| **``2xx Success``** | {0} | {1}% | Nominal traffic / static assets |" -f $Count2xx, $p2)
    Write-Output ("| **``3xx Redirect``** | {0} | {1}% | Canonical URL & Auth routing |" -f $Count3xx, $p3)
    Write-Output ("| **``4xx Warnings``** | {0} | {1}% | Bot deflections & unmapped probes |" -f $Count4xx, $p4)
    Write-Output ("| - *404 Not Found* | *{0}* | - | Threat Harvester candidates / Missing paths |" -f $Count404)
    Write-Output ("| - *403 Bot Trapped* | *{0}* | - | Headless scrapers deflecting at edge |" -f $Count403Bot)
    Write-Output ("| - *405 Method Block* | *{0}* | - | Root POST/PUT injection deflections |" -f $Count405Method)
    Write-Output ("| - *429 Throttled* | *{0}* | - | Token-bucket sliding limit active |" -f $Count429Rate)
    Write-Output ("| **``5xx Server Error``** | {0} | {1}% | Server faults (**Zero-defect goal**) |" -f $Count5xx, $p5)

    if ($Paths404.Count -gt 0) {
        Write-Output ""
        Write-Output "#### 2. Unmapped Probes & Market Demand Gaps (Top 404s)"
        Write-Output ""
        Write-Output "| Path Probed | Ingress Hits | Threat / Market Category |"
        Write-Output "| :--- | :--- | :--- |"
        $Paths404.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | ForEach-Object {
            $p = $_.Key
            $val = $_.Value
            $cat = "Unknown Probe"
            if ($p -match "wp-|xmlrpc") { $cat = "WordPress Exploit Scanner" }
            elseif ($p -match "env|config|claude") { $cat = "Credential / Secret Harvester" }
            elseif ($p -match "session|actuator") { $cat = "Spring / Java Actuator Probe" }
            elseif ($p -match "sitemap|robots") { $cat = "SEO Discovery / Crawler" }
            elseif ($p -match "api|sdk") { $cat = "**Potential Market Demand / Missing API**" }
            elseif ($p -match "login|admin") { $cat = "Admin Interface Reconnaissance" }
            Write-Output ("| ``{0}`` | {1} | {2} |" -f $p, $val, $cat)
        }
    }

    if ($Subnets.Count -gt 0) {
        Write-Output ""
        Write-Output "#### 3. Top Active Ingress Subnets (IPv4 /24 Correlation)"
        Write-Output ""
        Write-Output "| Subnet / CIDR | Total Ingress Requests |"
        Write-Output "| :--- | :--- |"
        $Subnets.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | ForEach-Object {
            Write-Output ("| ``{0}`` | {1} |" -f $_.Key, $_.Value)
        }
    }
}
