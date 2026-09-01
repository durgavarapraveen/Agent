# Kali Docker Setup for Windows PowerShell
# Run: .\setup_kali.ps1

Write-Host "=== Kali Docker Setup ===" -ForegroundColor Cyan

# 1. Check Docker
$dockerCheck = docker --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker not installed. Install Docker Desktop first." -ForegroundColor Red
    Write-Host "Download: https://www.docker.com/products/docker-desktop"
    exit 1
}
Write-Host "[OK] Docker installed: $dockerCheck" -ForegroundColor Green

# 2. Check if Kali container already running
$existing = docker ps -a --filter "name=kali" --format "{{.Names}}"
if ($existing -match "kali") {
    Write-Host "[OK] Kali container 'kali' already exists" -ForegroundColor Green
    $running = docker ps --filter "name=kali" --format "{{.Names}}"
    if ($running -notmatch "kali") {
        Write-Host "Starting existing Kali container..." -ForegroundColor Yellow
        docker start kali
    }
} else {
    Write-Host "Pulling Kali Rolling image (this may take a few minutes)..." -ForegroundColor Yellow
    docker pull kalilinux/kali-rolling

    Write-Host "Creating Kali container..." -ForegroundColor Yellow
    docker run -dit --name kali --restart unless-stopped kalilinux/kali-rolling /bin/bash
}

# 3. Wait for container to be ready
Start-Sleep -Seconds 2

# 4. Update apt + install essential tools
Write-Host "`nInstalling essential Kali tools..." -ForegroundColor Cyan
Write-Host "This will take 5-10 minutes on first run..." -ForegroundColor Yellow

docker exec kali bash -c "apt-get update -qq"

$tools = @(
    "dnsutils",       # dig, host, nslookup
    "whois",
    "curl",
    "wget",
    "nmap",
    "masscan",
    "amass",
    "subfinder",
    "assetfinder",
    "dnsenum",
    "fierce",
    "gobuster",
    "feroxbuster",
    "dirsearch",
    "ffuf",
    "nikto",
    "nuclei",
    "whatweb",
    "wafw00f",
    "sslscan",
    "httpx-toolkit"
)

$installed = 0
$failed = @()
foreach ($tool in $tools) {
    Write-Host "  Installing $tool..." -NoNewline
    $result = docker exec kali bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $tool 2>&1"
    if ($LASTEXITCODE -eq 0) {
        Write-Host " [OK]" -ForegroundColor Green
        $installed++
    } else {
        Write-Host " [FAIL]" -ForegroundColor Red
        $failed += $tool
    }
}

Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "Installed: $installed / $($tools.Count) tools" -ForegroundColor Green
if ($failed.Count -gt 0) {
    Write-Host "Failed: $($failed -join ', ')" -ForegroundColor Yellow
    Write-Host "(These will be attempted at runtime when needed)" -ForegroundColor Yellow
}

Write-Host "`nVerify with:" -ForegroundColor Cyan
Write-Host "  docker exec kali nmap --version"
Write-Host "  docker exec kali subfinder -version"
Write-Host "`nRun your scanner:" -ForegroundColor Cyan
Write-Host "  python main.py --target https://juice-shop.herokuapp.com/#/ --mode PASSIVE"