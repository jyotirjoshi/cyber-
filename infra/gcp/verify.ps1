[CmdletBinding()]
param(
    [string]$DeploymentFile = (Join-Path $PSScriptRoot ".deployment.env"),
    [string]$OutputFile = (Join-Path $PSScriptRoot ".verification.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "tooling.ps1")

function Invoke-CynuxVerification {
    param([Parameter(Mandatory)][string]$DeploymentFile, [Parameter(Mandatory)][string]$OutputFile)
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Initialize-CynuxGcloudEnvironment -RepoRoot $repoRoot
    $gcloud = Resolve-CynuxCli -Name "gcloud" -RepoRoot $repoRoot
    $config = @{}
    foreach ($line in Get-Content -LiteralPath $DeploymentFile) {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) { $config[$parts[0].Trim()] = $parts[1].Trim() }
    }
    $project = $config.CYNUX_GCP_PROJECT_ID
    $region = $config.CYNUX_GCP_REGION
    $zone = $config.CYNUX_GCP_ZONE
    $base = "https://$project.web.app"
    $checks = [System.Collections.Generic.List[object]]::new()

    function Add-Check([string]$Name, [scriptblock]$Action) {
        try {
            & $Action
            $checks.Add([ordered]@{ name = $Name; status = "PASS" })
        }
        catch {
            $checks.Add([ordered]@{ name = $Name; status = "FAIL"; error = $_.Exception.Message.Split("`n")[0] })
        }
    }

    Add-Check "firebase-tls-headers" {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "$base/login" -MaximumRedirection 5
        if ($response.StatusCode -ne 200) { throw "unexpected HTTP status $($response.StatusCode)" }
        if (-not $response.Headers["strict-transport-security"]) { throw "HSTS header missing" }
    }
    Add-Check "api-health" {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "$base/healthz" -TimeoutSec 60
        if ($response.StatusCode -ne 200 -or $response.Headers["content-type"] -notmatch "json") { throw "API liveness response unavailable" }
    }
    Add-Check "api-data-connectivity" {
        $snapshot = Invoke-RestMethod -Uri "$base/readyz" -TimeoutSec 60
        foreach ($name in @("database", "redis")) {
            $dependency = @($snapshot.dependencies | Where-Object name -eq $name)
            if ($dependency.Count -ne 1 -or -not $dependency[0].healthy) { throw "$name is unreachable from the API" }
        }
    }
    Add-Check "openapi" {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "$base/openapi.json"
        if ($response.StatusCode -ne 200 -or $response.Headers["content-type"] -notmatch "json") { throw "OpenAPI unavailable" }
    }
    Add-Check "cors" {
        $response = Invoke-WebRequest -UseBasicParsing -Method Options -Uri "$base/api/v1/health" -Headers @{ Origin = $base; "Access-Control-Request-Method" = "GET" }
        if ($response.Headers["access-control-allow-origin"] -ne $base) { throw "CORS origin mismatch" }
    }
    Add-Check "websocket-upgrade" {
        $socket = [System.Net.WebSockets.ClientWebSocket]::new()
        $deadline = [Threading.CancellationTokenSource]::new(20000)
        try {
            $uri = [Uri]("wss://$project.web.app/ws/agent/00000000-0000-0000-0000-000000000000")
            $socket.ConnectAsync($uri, $deadline.Token).GetAwaiter().GetResult()
            if ($socket.State -ne [System.Net.WebSockets.WebSocketState]::Open) { throw "WebSocket did not upgrade" }
            $payload = [Text.Encoding]::UTF8.GetBytes('{"type":"auth","token":"verification-invalid"}')
            $segment = [ArraySegment[byte]]::new($payload)
            $socket.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $deadline.Token).GetAwaiter().GetResult()
        }
        finally { $socket.Dispose(); $deadline.Dispose() }
    }
    Add-Check "cloud-run-ready" {
        foreach ($service in @("cynux-api", "cynux-web")) {
            $ready = (& $gcloud run services describe $service --project=$project --region=$region --format="value(status.conditions[0].status)").Trim()
            if ($LASTEXITCODE -ne 0 -or $ready -ne "True") { throw "$service is not ready" }
        }
    }
    Add-Check "migration" {
        $result = (& $gcloud run jobs executions list --job=cynux-migrate --project=$project --region=$region --limit=1 --format="value(status.conditions[0].type)").Trim()
        if ($LASTEXITCODE -ne 0 -or $result -ne "Completed") { throw "latest migration did not complete" }
    }
    Add-Check "sql-redis" {
        $sql = (& $gcloud sql instances describe cynux-postgres --project=$project --format="value(state)").Trim()
        $redis = (& $gcloud redis instances describe cynux-redis --project=$project --region=$region --format="value(state)").Trim()
        if ($sql -ne "RUNNABLE" -or $redis -ne "READY") { throw "managed data service is not ready" }
    }
    Add-Check "budget" {
        $billingAccount = (& $gcloud billing projects describe $project --format="value(billingAccountName)" | Out-String).Trim().Replace("billingAccounts/", "")
        if ($LASTEXITCODE -ne 0 -or -not $billingAccount) { throw "billing account lookup failed" }
        $budget = (& $gcloud billing budgets list --billing-account=$billingAccount --filter="displayName='Cynux production credit guardrail'" --format="value(displayName)" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $budget) { throw "budget missing" }
    }
    Add-Check "artifact-bucket-roundtrip" {
        $bucket = "$project-cynux-artifacts"
        $object = ".cynux-verification/$([guid]::NewGuid().ToString('N')).txt"
        $temporary = [IO.Path]::GetTempFileName()
        try {
            $expected = [guid]::NewGuid().ToString("N")
            Set-Content -LiteralPath $temporary -Value $expected -NoNewline
            $null = & $gcloud storage cp $temporary "gs://$bucket/$object" --quiet
            if ($LASTEXITCODE -ne 0) { throw "artifact upload failed" }
            $actual = (& $gcloud storage cat "gs://$bucket/$object" | Out-String).Trim()
            if ($LASTEXITCODE -ne 0 -or $actual -ne $expected) { throw "artifact roundtrip mismatch" }
        }
        finally {
            $null = & $gcloud storage rm "gs://$bucket/$object" --quiet 2>$null
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
    Add-Check "worker-systemd" {
        $state = (& $gcloud compute ssh cynux-scanner-01 --project=$project --zone=$zone --tunnel-through-iap --quiet --command "sudo systemctl is-active cynux-worker" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $state -ne "active") { throw "worker service is not active" }
    }
    Add-Check "defectdojo-private-health" {
        $privateIp = (& $gcloud compute instances describe cynux-defectdojo-01 --project=$project --zone=$zone --format="value(networkInterfaces[0].networkIP)" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $privateIp -notmatch '^10\.[0-9]+\.[0-9]+\.[0-9]+$') { throw "DefectDojo private address unavailable" }
        $status = (& $gcloud compute ssh cynux-defectdojo-01 --project=$project --zone=$zone --tunnel-through-iap --quiet --command "curl --max-time 20 -fsS http://${privateIp}:8080/login >/dev/null && echo healthy" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $status -ne "healthy") { throw "DefectDojo private health check failed" }
    }

    $passed = @($checks | Where-Object status -eq "PASS").Count
    $result = [ordered]@{
        generated_at_utc = [DateTime]::UtcNow.ToString("o")
        project_id = $project
        passed = $passed
        failed = $checks.Count - $passed
        checks = $checks
    }
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputFile -Encoding utf8
    if ($result.failed -gt 0) { throw "$($result.failed) production verification checks failed; see $OutputFile" }
    return $result
}

if ($MyInvocation.InvocationName -ne ".") {
    try { $null = Invoke-CynuxVerification -DeploymentFile $DeploymentFile -OutputFile $OutputFile }
    catch { Write-Error $_; exit 1 }
}
