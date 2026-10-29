# ==============================================================================
# [Phylax] PHYLAX THREAT RECONNAISSANCE & ABUSE INTELLIGENCE: phylax-threat-recon.ps1
# Standard: Universal Sovereign Threat Reconnaissance Standard
# Cross-Platform Parity: Pure PowerShell Core (Windows / macOS / Linux)
# ==============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
    [string[]]$IpAddresses,

    [Parameter()]
    [switch]$Report,

    [Parameter()]
    [switch]$Json,

    [Parameter()]
    [int]$Limit = 10,

    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Usage: phylax-threat-recon.ps1 [OPTIONS] [IP_ADDRESSES...]

Options:
  -Report           Autonomously dispatch incident dossiers to AbuseIPDB
  -Json             Emit structured JSON rather than Markdown table
  -Limit <NUM>      Maximum IP entities to investigate (default: 10)
  -Help             Show this help message
"@
    exit 0
}

$apiKey = $env:ABUSEIPDB_API_KEY
if (-not $apiKey -and (Test-Path "$HOME/.env")) {
    $envLines = Get-Content "$HOME/.env" -ErrorAction SilentlyContinue
    foreach ($line in $envLines) {
        if ($line -match '^(export\s+)?ABUSEIPDB_API_KEY=(.+)$') {
            $apiKey = $Matches[2].Trim('"', "'", ' ')
            break
        }
    }
}

$targets = @()
if ($IpAddresses -and $IpAddresses.Count -gt 0) {
    $targets = $IpAddresses
} else {
    Write-Host "[INFO] Please specify IP addresses or pipe log lines to investigate."
    exit 0
}

$results = @()

foreach ($ip in ($targets | Select-Object -Unique -First $Limit)) {
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }

    $geo = $null
    try {
        $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip?fields=status,country,regionName,city,isp,org,as" -TimeoutSec 3 -ErrorAction SilentlyContinue
    } catch {}

    $country = if ($geo -and $geo.country) { $geo.country } else { "Unknown" }
    $city = if ($geo -and $geo.city) { $geo.city } else { "" }
    $isp = if ($geo -and $geo.isp) { $geo.isp } else { "Unknown ISP" }
    $asn = if ($geo -and $geo.as) { ($geo.as -split ' ')[0] } else { "Unknown" }

    $abuseScore = "N/A"
    $totalReports = 0

    if ($apiKey) {
        try {
            $headers = @{ "Key" = $apiKey; "Accept" = "application/json" }
            $abuse = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" -Headers $headers -TimeoutSec 3 -ErrorAction SilentlyContinue
            if ($abuse -and $abuse.data) {
                $abuseScore = $abuse.data.abuseConfidenceScore
                $totalReports = $abuse.data.totalReports
            }
        } catch {}
    }

    $action = "Monitored"
    if ($Report -and $apiKey) {
        try {
            $body = @{
                ip = $ip
                categories = "15,21"
                comment = "Phylax Edge Perimeter Defense caught unauthorized attack probe from $ip against sovereign services."
            }
            $postHeaders = @{ "Key" = $apiKey; "Accept" = "application/json" }
            $resp = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/report" -Method Post -Headers $postHeaders -Body $body -TimeoutSec 4 -ErrorAction SilentlyContinue
            if ($resp -and $resp.data) {
                $action = "[REPORTED]"
            }
        } catch {
            $action = "[REPORT FAILED]"
        }
    }

    $locationStr = if ($city) { "$city, $country" } else { $country }

    $results += [PSCustomObject]@{
        IpAddress = $ip
        ISP = $isp
        ASN = $asn
        Location = $locationStr
        AbuseConfidenceScore = $abuseScore
        TotalReports = $totalReports
        Action = $action
    }
}

if ($Json) {
    $results | ConvertTo-Json -Depth 3
} else {
    $abuseStatus = if ($apiKey) { "[ACTIVE]" } else { "[PASSIVE]" }
    $reportStatus = if ($Report) { "[ENABLED]" } else { "[MONITORING ONLY]" }
    Write-Host "### [Phylax] Threat Intelligence & Entity Reconnaissance"
    Write-Host ("* **Target Entities Investigated:** {0}" -f $results.Count)
    Write-Host ("* **AbuseIPDB Integration:** {0}" -f $abuseStatus)
    Write-Host ("* **Auto-Reporting Mode:** {0}" -f $reportStatus)
    Write-Host ""
    Write-Host "| Attacker IP | Organization / ISP | ASN | Location | Abuse Score | Action Taken |"
    Write-Host "| :--- | :--- | :---: | :---: | :---: | :---: |"
    foreach ($r in $results) {
        Write-Host ("| **``{0}``** | {1} | ``{2}`` | {3} | {4}% | {5} |" -f $r.IpAddress, $r.ISP, $r.ASN, $r.Location, $r.AbuseConfidenceScore, $r.Action)
    }
}
