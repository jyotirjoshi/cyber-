$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "start-defectdojo.sh"
if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Expected DefectDojo launcher at $scriptPath"
}

$content = Get-Content -LiteralPath $scriptPath -Raw
$initializer = $content.IndexOf("/entrypoint-initializer.sh /bin/true")
$worker = $content.IndexOf("/entrypoint-celery-worker.sh")
$beat = $content.IndexOf("/entrypoint-celery-beat.sh")
$web = $content.IndexOf("/entrypoint-uwsgi.sh")

if ($initializer -lt 0 -or $worker -lt 0 -or $beat -lt 0 -or $web -lt 0) {
    throw "Launcher must initialize DefectDojo, then run its worker, scheduler, and web process."
}

if (-not ($initializer -lt $worker -and $worker -lt $web -and $beat -lt $web)) {
    throw "DefectDojo initialization must occur before the long-running processes."
}

if ($content -notmatch "trap .*TERM") {
    throw "Launcher must forward termination signals to all child processes."
}
