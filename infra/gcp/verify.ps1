[CmdletBinding()]
param(
    [string]$DeploymentFile = "",
    [string]$OutputFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not $DeploymentFile) { $DeploymentFile = Join-Path $PSScriptRoot ".deployment.env" }
if (-not $OutputFile) { $OutputFile = Join-Path $PSScriptRoot ".verification.json" }
. (Join-Path $PSScriptRoot "tooling.ps1")

function Invoke-VerificationCommand {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$Arguments = @())
    $previousErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $FilePath @Arguments 2>&1 | ForEach-Object { $_.ToString() })
        $commandExitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorPreference }
    if ($commandExitCode -ne 0) {
        throw "Command failed ($commandExitCode): $FilePath $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    return @($output)
}

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
        $response = Invoke-WebRequest -UseBasicParsing -Uri "$base/health" -TimeoutSec 60
        if ($response.StatusCode -ne 200 -or $response.Headers["content-type"] -notmatch "json") { throw "API liveness response unavailable" }
    }
    Add-Check "api-data-connectivity" {
        $snapshot = Invoke-RestMethod -Uri "$base/readyz" -TimeoutSec 60
        foreach ($name in @("database", "redis", "pgvector", "worker")) {
            $dependency = @($snapshot.dependencies | Where-Object name -eq $name)
            if ($dependency.Count -ne 1 -or -not $dependency[0].healthy) { throw "$name is unreachable from the API" }
        }
    }
    Add-Check "openapi" {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "$base/openapi.json"
        if ($response.StatusCode -ne 200 -or $response.Headers["content-type"] -notmatch "json") { throw "OpenAPI unavailable" }
        $schema = $response.Content | ConvertFrom-Json
        foreach ($path in @(
            "/api/v1/agents/definitions",
            "/api/v1/agents/tools",
            "/api/v1/knowledge/collections",
            "/api/v1/knowledge/search",
            "/api/v1/agent/runs",
            "/api/v1/agent/runs/{run_id}",
            "/api/v1/agent/runs/{run_id}/events",
            "/api/v1/agent/runs/{run_id}/cancel",
            "/api/v1/agent/runs/{run_id}/tasks/{task_id}/retry",
            "/api/v1/agent/runs/{run_id}/tasks/{task_id}/approve"
        )) {
            if (-not $schema.paths.PSObject.Properties[$path]) { throw "rollout route missing: $path" }
        }
    }
    Add-Check "cors" {
        $response = Invoke-WebRequest -UseBasicParsing -Method Options -Uri "$base/api/v1/health" -Headers @{ Origin = $base; "Access-Control-Request-Method" = "GET" }
        if ($response.Headers["access-control-allow-origin"] -ne $base) { throw "CORS origin mismatch" }
    }
    Add-Check "websocket-upgrade" {
        $socket = [System.Net.WebSockets.ClientWebSocket]::new()
        $deadline = [Threading.CancellationTokenSource]::new(20000)
        try {
            $projectNumber = (Invoke-VerificationCommand $gcloud @("projects", "describe", $project, "--format=value(projectNumber)") | Select-Object -First 1).Trim()
            if ($projectNumber -notmatch '^[0-9]+$') { throw "project number lookup failed" }
            $uri = [Uri]("wss://cynux-api-$projectNumber.$region.run.app/ws/agent/00000000-0000-0000-0000-000000000000")
            $socket.ConnectAsync($uri, $deadline.Token).GetAwaiter().GetResult()
            if ($socket.State -ne [System.Net.WebSockets.WebSocketState]::Open) { throw "WebSocket did not upgrade" }
            $payload = [Text.Encoding]::UTF8.GetBytes('{"type":"auth","token":"verification-invalid"}')
            $segment = [ArraySegment[byte]]::new($payload)
            $socket.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $deadline.Token).GetAwaiter().GetResult()
        }
        finally { $socket.Dispose(); $deadline.Dispose() }
    }
    Add-Check "multi-agent-websocket-upgrade" {
        $socket = [System.Net.WebSockets.ClientWebSocket]::new()
        $deadline = [Threading.CancellationTokenSource]::new(20000)
        try {
            $projectNumber = (Invoke-VerificationCommand $gcloud @("projects", "describe", $project, "--format=value(projectNumber)") | Select-Object -First 1).Trim()
            if ($projectNumber -notmatch '^[0-9]+$') { throw "project number lookup failed" }
            $uri = [Uri]("wss://cynux-api-$projectNumber.$region.run.app/ws/agent/runs/00000000-0000-0000-0000-000000000000")
            $socket.ConnectAsync($uri, $deadline.Token).GetAwaiter().GetResult()
            if ($socket.State -ne [System.Net.WebSockets.WebSocketState]::Open) { throw "Run WebSocket did not upgrade" }
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
            $null = Invoke-VerificationCommand $gcloud @("storage", "cp", $temporary, "gs://$bucket/$object", "--quiet")
            $actual = (Invoke-VerificationCommand $gcloud @("storage", "cat", "gs://$bucket/$object") | Out-String).Trim()
            if ($actual -ne $expected) { throw "artifact roundtrip mismatch" }
        }
        finally {
            $null = Invoke-VerificationCommand $gcloud @("storage", "rm", "gs://$bucket/$object", "--quiet")
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
    Add-Check "worker-systemd" {
        $state = (& $gcloud compute ssh cynux-scanner-01 --project=$project --zone=$zone --tunnel-through-iap --quiet --command "sudo systemctl is-active cynux-worker" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $state -ne "active") { throw "worker service is not active" }
    }
    Add-Check "worker-multi-agent-config" {
        # Keep this command free of nested shell quotes and regex alternation:
        # gcloud.cmd routes those characters through cmd.exe before SSH.
        $command = 'sudo grep -q ^CYNUX_FEATURES__MULTI_AGENT= /etc/cynux/worker.env && sudo grep -q ^CYNUX_AGENT__WORKER_MAX_CONCURRENCY= /etc/cynux/worker.env && sudo grep -q ^CYNUX_AGENT__TASK_LEASE_SECONDS= /etc/cynux/worker.env && echo configured'
        $state = (& $gcloud compute ssh cynux-scanner-01 --project=$project --zone=$zone --tunnel-through-iap --quiet --command $command | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $state -ne "configured") { throw "worker multi-agent ceilings are missing" }
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
