# ==============================================================================
# Cynux Production & Cloud Deployment Script (PowerShell)
# ==============================================================================
param (
    [switch]$Tunnel,
    [switch]$Prod
)

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "           Cynux Platform Deployment                " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Check prerequisites
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Docker is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# 2. Initialize .env file
if (-not (Test-Path ".env")) {
    Write-Host "[+] Creating .env from template..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
}

# 3. Generate production secrets
Write-Host "[+] Generating secure cryptographic secrets..." -ForegroundColor Green
if (Get-Command python -ErrorAction SilentlyContinue) {
    python docker/gen-secrets.py
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    python3 docker/gen-secrets.py
} else {
    Write-Host "[!] Python not found in PATH; skipping automated secret generation." -ForegroundColor Yellow
}

# 4. Check LLM Key
$envContent = Get-Content ".env" -Raw
if ($envContent -notmatch "CYNUX_LLM__ANTHROPIC_API_KEY=sk-") {
    Write-Host "[!] WARNING: CYNUX_LLM__ANTHROPIC_API_KEY is not configured in .env." -ForegroundColor Yellow
    Write-Host "    The agent worker requires an LLM API key to perform security scans." -ForegroundColor Yellow
}

# 5. Bring up DefectDojo vulnerability store
Write-Host "[+] Starting DefectDojo vulnerability store..." -ForegroundColor Green
docker compose --profile defectdojo up -d defectdojo-postgres defectdojo-redis defectdojo-initializer defectdojo-uwsgi defectdojo-nginx

Write-Host "[+] Waiting for DefectDojo initialization..." -ForegroundColor Cyan
$maxRetries = 40
$retry = 0
while ($retry -lt $maxRetries) {
    $initStatus = docker inspect -f '{{.State.Status}}' cynux-defectdojo-initializer-1 2>$null
    if (-not $initStatus) {
        $initStatus = docker inspect -f '{{.State.Status}}' cyber-ai-defectdojo-initializer-1 2>$null
    }
    if ($initStatus -eq "exited") {
        break
    }
    Start-Sleep -Seconds 3
    $retry++
}

# 6. Mint DefectDojo token into .env
Write-Host "[+] Minting DefectDojo API token..." -ForegroundColor Green
if (Get-Command python -ErrorAction SilentlyContinue) {
    python docker/defectdojo-token.py
}

# 7. Spin up full Cynux application stack
if ($Prod) {
    Write-Host "[+] Launching Production Stack with Caddy Auto-HTTPS..." -ForegroundColor Green
    docker compose -f docker-compose.prod.yml --profile defectdojo up -d --build
} elseif ($Tunnel) {
    Write-Host "[+] Launching Stack with Cloudflare Tunnel Public HTTPS..." -ForegroundColor Green
    docker compose --profile defectdojo -f docker-compose.yml -f docker-compose.tunnel.yml up -d --build
    Start-Sleep -Seconds 5
    docker compose logs cloudflared | Select-String "https://.*\.trycloudflare\.com"
} else {
    Write-Host "[+] Launching Standard Docker Stack..." -ForegroundColor Green
    docker compose --profile defectdojo up -d --build
}

Write-Host "====================================================" -ForegroundColor Green
Write-Host "    Cynux Deployment Completed Successfully!        " -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host "Frontend Web App:  http://localhost:3000"
Write-Host "API Endpoints:     http://localhost:8000/docs"
Write-Host "MinIO S3 Console:  http://localhost:9001"
Write-Host "DefectDojo Store:  http://localhost:8080"
