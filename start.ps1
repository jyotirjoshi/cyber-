# Cynux — Windows PowerShell startup helper (no Docker required).
#
# Prerequisites:
#   - Python 3.11+  (pip install in backend)
#   - Node.js 22+   (npm install in frontend)
#   - PostgreSQL 16 running on localhost:5432
#   - Redis 7 running on localhost:6379
#   - MinIO (optional) running on localhost:9000  — or use real AWS S3
#
# Usage:  .\start.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# ── 1. Ensure .env exists ──────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example — fill in secrets before continuing." -ForegroundColor Yellow
    Write-Host "  Edit .env, then run this script again."
    exit 0
}

# ── 2. Install Python deps ─────────────────────────────────────────────────
Write-Step "Installing Python dependencies"
Push-Location backend
pip install -e ".[dev]"
Pop-Location

# ── 3. Install Node deps ───────────────────────────────────────────────────
Write-Step "Installing frontend dependencies"
Push-Location frontend
npm install
Pop-Location

# ── 4. Run database migrations ─────────────────────────────────────────────
Write-Step "Running database migrations"
Push-Location backend
alembic upgrade head
Pop-Location

# ── 5. Start services in separate windows ─────────────────────────────────
Write-Step "Starting API server (port 8000)"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\backend'; uvicorn --factory app.api.app:create_app --host 0.0.0.0 --port 8000 --reload" -WindowStyle Normal

Write-Step "Starting worker"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\backend'; python -m app.worker" -WindowStyle Normal

Write-Step "Starting frontend dev server (port 3000)"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\frontend'; npm run dev" -WindowStyle Normal

Write-Host "`nAll services started in separate windows." -ForegroundColor Green
Write-Host "  API:      http://localhost:8000"
Write-Host "  Frontend: http://localhost:3000"
Write-Host "  API docs: http://localhost:8000/docs"
