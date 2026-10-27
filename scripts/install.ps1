# ==============================================================================
# Phylax (φύλαξ) — Sovereign Edge Defense Windows PowerShell Installer
# ==============================================================================
[CmdletBinding()]
param (
    [string]$InstallDir = "$HOME\.cargo\bin"
)

$ErrorActionPreference = "Stop"

Write-Host "
  ██████╗ ██╗  ██╗██╗   ██╗██╗      █████╗ ██╗  ██╗
  ██╔══██╗██║  ██║╚██╗ ██╔╝██║     ██╔══██╗╚██╗██╔╝
  ██████╔╝███████║ ╚████╔╝ ██║     ███████║ ╚███╔╝ 
  ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██╔══██║ ██╔██╗ 
  ██║     ██║  ██║   ██║   ███████╗██║  ██║██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
  Sovereign Zero-Telemetry WAF & Edge Defense Daemon
" -ForegroundColor Cyan

# Create installation directory if missing
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$Installed = $false
if (-not (Test-Path "Cargo.toml")) {
    $LatestTag = try {
        $Resp = Invoke-WebRequest -Uri "https://github.com/rmediatech/phylax/releases/latest" -MaximumRedirection 0 -ErrorAction SilentlyContinue
        $Resp.Headers.Location | Split-Path -Leaf
    } catch {
        "v0.2.1"
    }
    if (-not $LatestTag) { $LatestTag = "v0.2.1" }

    $ReleaseUrl = "https://github.com/rmediatech/phylax/releases/download/$LatestTag/phylax-$LatestTag-x86_64-pc-windows-msvc.zip"
    $ZipPath = "$env:TEMP\phylax.zip"
    try {
        Write-Host "🌐 Attempting to download prebuilt binary release ($LatestTag) from GitHub..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $ReleaseUrl -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
        Remove-Item $ZipPath -Force
        $Installed = $true
    } catch {
        Write-Host "Prebuilt release not found or network unavailable; falling back to Cargo source build..." -ForegroundColor Yellow
    }
}

if (-not $Installed) {
    if (Test-Path "Cargo.toml") {
        Write-Host "📦 Building from local repository source..." -ForegroundColor Green
        cargo build --release --features cli
        Copy-Item "target\release\phylax.exe" "$InstallDir\phylax.exe" -Force
    } else {
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            Write-Error "Neither prebuilt release nor Rust/Cargo was found. Please install Rust from https://rustup.rs"
            exit 1
        }
        Write-Host "📦 Installing via Cargo from GitHub..." -ForegroundColor Green
        cargo install --git https://github.com/rmediatech/phylax.git --features cli
    }
}

Write-Host "✅ Installed: $InstallDir\phylax.exe" -ForegroundColor Green

# Generate default configuration if missing
$ConfigFile = "$HOME\.config\phylax\phylax.toml"
$ConfigDir = Split-Path -Parent $ConfigFile
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

if (-not (Test-Path $ConfigFile)) {
    & "$InstallDir\phylax.exe" init --output $ConfigFile
    Write-Host "⚙️  Generated default configuration: $ConfigFile" -ForegroundColor Cyan
}

Write-Host "`n🎉 Phylax installation complete!" -ForegroundColor Green
Write-Host "Quick Start:"
Write-Host "  1. Test CLI:             phylax --help"
Write-Host "  2. Run Microbenchmarks:  phylax bench"
Write-Host "  3. Start WAF Proxy:      phylax serve --upstream http://127.0.0.1:8080 --listen 127.0.0.1:3000"
