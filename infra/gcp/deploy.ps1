[CmdletBinding()]
param(
    [switch]$ApproveApply,
    [switch]$AllowDirtySnapshot,
    [switch]$SkipBuild,
    [string]$ExistingImageTag,
    [string]$FirebaseAccount,
    [string]$MigrationImageTag = "",
    [switch]$StopPrivateHostsAfterDeploy,
    [string]$DeploymentFile = "",
    [string]$LastDeploymentFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not $DeploymentFile) { $DeploymentFile = Join-Path $PSScriptRoot ".deployment.env" }
if (-not $LastDeploymentFile) { $LastDeploymentFile = Join-Path $PSScriptRoot ".last-deployment.json" }
. (Join-Path $PSScriptRoot "tooling.ps1")

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$Arguments = @())
    $null = Get-Command $FilePath -ErrorAction Stop
    $previousErrorPreference = $ErrorActionPreference
    try {
        # Windows PowerShell turns native stderr (including successful CLI
        # progress) into ErrorRecords. The process exit code is authoritative.
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

function Read-DeploymentConfig {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Missing deployment config: $Path" }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) { $values[$parts[0].Trim()] = $parts[1].Trim() }
    }
    foreach ($required in @("CYNUX_GCP_PROJECT_ID", "CYNUX_GCP_REGION", "CYNUX_GCP_ZONE", "CYNUX_GCP_TERRAFORM_STATE_BUCKET")) {
        if (-not $values.ContainsKey($required) -or -not $values[$required]) {
            throw "Deployment config is missing $required."
        }
    }
    return $values
}

function Resolve-ImageTag {
    param(
        [Parameter(Mandatory)][string]$GitSha,
        [string]$DirtyFingerprint,
        [switch]$AllowDirtySnapshot
    )
    if (-not $DirtyFingerprint) { return $GitSha }
    if (-not $AllowDirtySnapshot) {
        throw "Working tree is dirty. Commit it or pass -AllowDirtySnapshot to create a content-derived tag."
    }
    $safe = $DirtyFingerprint.ToLowerInvariant() -replace '[^a-z0-9._-]', '-'
    return "$GitSha-dirty-$safe"
}

function Get-DirtyFingerprint {
    param([Parameter(Mandatory)][string]$RepoRoot)
    $status = (& git -C $RepoRoot status --porcelain=v1 --untracked-files=all | Out-String).Trim()
    if (-not $status) { return $null }
    $material = [System.Text.StringBuilder]::new()
    $null = $material.Append((& git -C $RepoRoot diff HEAD --binary | Out-String))
    $untracked = @(& git -C $RepoRoot ls-files --others --exclude-standard)
    foreach ($relative in ($untracked | Sort-Object)) {
        $path = Join-Path $RepoRoot $relative
        $null = $material.Append($relative)
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $null = $material.Append((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)
        }
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($material.ToString())
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 12).ToLowerInvariant()
}

function Resolve-ReleaseImageTag {
    param([string]$GitSha, [string]$DirtyFingerprint, [switch]$AllowDirtySnapshot,
        [switch]$SkipBuild, [string]$ExistingImageTag)
    if ($ExistingImageTag) {
        if (-not $SkipBuild -or $ExistingImageTag -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{6,127}$' -or $ExistingImageTag -eq 'latest') {
            throw "An existing immutable image tag requires -SkipBuild; latest is not allowed."
        }
        return $ExistingImageTag
    }
    if ($SkipBuild) { throw "-SkipBuild requires -ExistingImageTag so recovery cannot select an unbuilt snapshot." }
    return Resolve-ImageTag -GitSha $GitSha -DirtyFingerprint $DirtyFingerprint -AllowDirtySnapshot:$AllowDirtySnapshot
}

function Write-DeploymentRecord {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Values)
    $allowed = @(
        "project_id", "region", "image_tag", "firebase_url", "api_service_uri",
        "web_service_uri", "migration_job_name", "scanner_instance_name",
        "defectdojo_instance_name", "artifact_bucket_name", "deployed_at_utc"
    )
    $record = [ordered]@{}
    foreach ($name in $allowed) {
        if ($Values.ContainsKey($name)) { $record[$name] = $Values[$name] }
    }
    $record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Invoke-ReleasePipeline {
    param([Parameter(Mandatory)][scriptblock]$RunStage)
    foreach ($stage in @(
        "preflight", "billing-budget", "terraform-plan", "apply-approval",
        "artifact-foundation", "terraform-replan", "build-push",
        "terraform-apply", "migration", "private-host-bootstrap", "secret-check", "cloud-run-readiness",
        "firebase-deploy", "smoke-tests"
    )) {
        & $RunStage $stage
    }
}

function Invoke-CynuxDeploy {
    [CmdletBinding()]
    param(
        [switch]$ApproveApply,
        [switch]$AllowDirtySnapshot,
        [switch]$SkipBuild,
        [string]$ExistingImageTag,
        [string]$FirebaseAccount,
        [string]$MigrationImageTag = "",
        [switch]$StopPrivateHostsAfterDeploy,
        [string]$DeploymentFile = "",
        [string]$LastDeploymentFile = ""
    )
    if (-not $DeploymentFile) { $DeploymentFile = Join-Path $PSScriptRoot ".deployment.env" }
    if (-not $LastDeploymentFile) { $LastDeploymentFile = Join-Path $PSScriptRoot ".last-deployment.json" }

    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Initialize-CynuxGcloudEnvironment -RepoRoot $repoRoot
    $gcloud = Resolve-CynuxCli -Name "gcloud" -RepoRoot $repoRoot
    $terraformDir = Join-Path $PSScriptRoot "terraform"
    $terraform = Join-Path $repoRoot ".tools\terraform\terraform.exe"
    $verify = Join-Path $PSScriptRoot "verify.ps1"
    $planFile = Join-Path $PSScriptRoot ".production.tfplan"
    $firebaseRc = Join-Path $repoRoot ".firebaserc"
    $config = Read-DeploymentConfig -Path $DeploymentFile
    $project = $config.CYNUX_GCP_PROJECT_ID
    $region = $config.CYNUX_GCP_REGION
    $zone = $config.CYNUX_GCP_ZONE
    $stateBucket = $config.CYNUX_GCP_TERRAFORM_STATE_BUCKET
    $multiAgentEnabled = if ($config.ContainsKey("CYNUX_MULTI_AGENT_ENABLED")) {
        $config.CYNUX_MULTI_AGENT_ENABLED.ToLowerInvariant()
    } else { "false" }
    if ($multiAgentEnabled -notin @("true", "false")) {
        throw "CYNUX_MULTI_AGENT_ENABLED must be true or false."
    }
    $multiAgentTerraformVar = "-var=multi_agent_enabled=$multiAgentEnabled"
    $sha = (Invoke-Checked git @("-C", $repoRoot, "rev-parse", "HEAD") | Select-Object -First 1).Trim()
    $fingerprint = Get-DirtyFingerprint -RepoRoot $repoRoot
    $imageTag = Resolve-ReleaseImageTag -GitSha $sha -DirtyFingerprint $fingerprint -AllowDirtySnapshot:$AllowDirtySnapshot -SkipBuild:$SkipBuild -ExistingImageTag $ExistingImageTag
    # A mutable reference is intentional: Invoke-ReleasePipeline executes callbacks in
    # child scope, while release state must survive for cleanup and the final record.
    $releaseState = @{
        TerraformOutputs   = $null
        PrivateHostsStarted = $false
        FirebaseAccount = $FirebaseAccount
    }

    try {
        Invoke-ReleasePipeline -RunStage {
        param($stage)
        Write-Host "[cynux-deploy] $stage"
        switch ($stage) {
            "preflight" {
                if (-not (Test-Path -LiteralPath $terraform)) { throw "Terraform is not installed at $terraform" }
                $firebaseConfig = Get-Content -Raw -LiteralPath $firebaseRc
                if ($firebaseConfig -match '__PROJECT_ID__' -or $firebaseConfig -notmatch [regex]::Escape($project)) {
                    throw ".firebaserc does not target the recorded production project."
                }
                $activeAccount = (Invoke-Checked $gcloud @("auth", "list", "--filter=status:ACTIVE", "--format=value(account)") | Select-Object -First 1)
                if (-not $releaseState.FirebaseAccount) { $releaseState.FirebaseAccount = $activeAccount }
                if (-not $releaseState.FirebaseAccount) { throw "No deployment account is selected." }
            }
            "billing-budget" {
                $billing = (Invoke-Checked $gcloud @("billing", "projects", "describe", $project, "--format=value(billingEnabled)") | Select-Object -First 1).Trim()
                if ($billing.ToLowerInvariant() -ne "true") { throw "Billing is disabled for $project." }
                $billingAccount = (Invoke-Checked $gcloud @("billing", "projects", "describe", $project, "--format=value(billingAccountName)") | Select-Object -First 1).Trim().Replace("billingAccounts/", "")
                $budgets = Invoke-Checked $gcloud @("billing", "budgets", "list", "--billing-account=$billingAccount", "--filter=displayName='Cynux production credit guardrail'", "--format=value(displayName)")
                if (-not ($budgets -match 'Cynux production credit guardrail')) { throw "The production credit budget guardrail is missing." }
            }
            "build-push" {
                $apiImage = "$region-docker.pkg.dev/$project/cynux/api:$imageTag"
                $webImage = "$region-docker.pkg.dev/$project/cynux/frontend:$imageTag"
                $bothExist = $true
                foreach ($image in @($apiImage, $webImage)) {
                    try { $null = Invoke-Checked $gcloud @("artifacts", "docker", "images", "describe", $image, "--project=$project") }
                    catch { $bothExist = $false }
                }
                if (-not $bothExist) {
                    if ($SkipBuild) { throw "The requested recovery image tag is not present for both API and frontend." }
                    $null = Invoke-Checked $gcloud @("builds", "submit", $repoRoot, "--project=$project", "--config=$repoRoot\cloudbuild.yaml", "--substitutions=_IMAGE_TAG=$imageTag")
                }
            }
            "terraform-plan" {
                $null = Invoke-Checked $terraform @("-chdir=$terraformDir", "init", "-reconfigure", "-backend-config=bucket=$stateBucket", "-backend-config=prefix=cynux/production")
                $null = Invoke-Checked $terraform @("-chdir=$terraformDir", "plan", "-out=$planFile", "-var=project_id=$project", "-var=region=$region", "-var=zone=$zone", "-var=image_tag=$imageTag", "-var=migration_image_tag=$MigrationImageTag", $multiAgentTerraformVar)
            }
            "apply-approval" {
                if (-not $ApproveApply) { throw "Terraform plan is ready. Re-run with -ApproveApply to create or update paid resources." }
            }
            "artifact-foundation" {
                # Cloud Build must push the release images before Cloud Run can
                # consume them. Apply only the repository, then re-plan so the
                # final plan is based on the updated remote state.
                $null = Invoke-Checked $terraform @(
                    "-chdir=$terraformDir", "apply", "-auto-approve",
                    "-target=google_artifact_registry_repository.cynux",
                    "-var=project_id=$project", "-var=region=$region",
                    "-var=zone=$zone", "-var=image_tag=$imageTag", "-var=migration_image_tag=$MigrationImageTag", $multiAgentTerraformVar
                )
            }
            "terraform-replan" {
                $null = Invoke-Checked $terraform @(
                    "-chdir=$terraformDir", "plan", "-out=$planFile",
                    "-var=project_id=$project", "-var=region=$region",
                    "-var=zone=$zone", "-var=image_tag=$imageTag", "-var=migration_image_tag=$MigrationImageTag", $multiAgentTerraformVar
                )
            }
            "terraform-apply" {
                $null = Invoke-Checked $terraform @("-chdir=$terraformDir", "apply", "-auto-approve", $planFile)
                $releaseState.TerraformOutputs = (Invoke-Checked $terraform @("-chdir=$terraformDir", "output", "-json") | Out-String | ConvertFrom-Json)
            }
            "private-host-bootstrap" {
                $releaseState.PrivateHostsStarted = $true
                $null = Invoke-Checked $gcloud @("compute", "instances", "start", "cynux-defectdojo-01", "--project=$project", "--zone=$zone", "--quiet")
                $null = Invoke-Checked $gcloud @("compute", "ssh", "cynux-defectdojo-01", "--project=$project", "--zone=$zone", "--tunnel-through-iap", "--quiet", "--command=sudo cloud-init status --wait")
                # Recover interrupted first-boot setup only when the managed
                # service is absent. Repeated releases leave healthy hosts alone.
                $null = Invoke-Checked python @((Join-Path $repoRoot ".tools/gcloud/google-cloud-sdk/lib/gcloud.py"), "compute", "ssh", "cynux-defectdojo-01", "--project=$project", "--zone=$zone", "--tunnel-through-iap", "--quiet", "--command=sudo test -f /etc/systemd/system/cynux-defectdojo.service || sudo /usr/local/sbin/cynux-defectdojo-bootstrap")
                $null = Invoke-Checked $gcloud @("compute", "instances", "start", "cynux-scanner-01", "--project=$project", "--zone=$zone", "--quiet")
                $null = Invoke-Checked $gcloud @("compute", "ssh", "cynux-scanner-01", "--project=$project", "--zone=$zone", "--tunnel-through-iap", "--quiet", "--command=sudo cloud-init status --wait")
                $null = Invoke-Checked python @((Join-Path $repoRoot ".tools/gcloud/google-cloud-sdk/lib/gcloud.py"), "compute", "ssh", "cynux-scanner-01", "--project=$project", "--zone=$zone", "--tunnel-through-iap", "--quiet", "--command=sudo test -f /etc/systemd/system/cynux-worker.service || sudo /usr/local/sbin/cynux-worker-bootstrap")
                $workerRefresh = Join-Path $PSScriptRoot "scripts\refresh-worker.sh"
                $null = Invoke-Checked $gcloud @("compute", "scp", $workerRefresh, "cynux-scanner-01:/tmp/cynux-worker-refresh.sh", "--project=$project", "--zone=$zone", "--tunnel-through-iap", "--quiet")
                $null = Invoke-Checked $gcloud @("compute", "ssh", "cynux-scanner-01", "--project=$project", "--zone=$zone", "--tunnel-through-iap", "--quiet", "--command=sudo bash /tmp/cynux-worker-refresh.sh")
            }
            "secret-check" {
                foreach ($secretId in $releaseState.TerraformOutputs.secret_resource_ids.value.PSObject.Properties.Value) {
                    $state = (Invoke-Checked $gcloud @("secrets", "versions", "list", $secretId, "--project=$project", "--filter=state=enabled", "--format=value(state)") | Select-Object -First 1)
                    if (-not $state) { throw "Secret $secretId has no enabled version." }
                }
            }
            "migration" {
                $null = Invoke-Checked $gcloud @("run", "jobs", "execute", "cynux-migrate", "--project=$project", "--region=$region", "--wait")
            }
            "cloud-run-readiness" {
                foreach ($service in @("cynux-api", "cynux-web")) {
                    $ready = (Invoke-Checked $gcloud @("run", "services", "describe", $service, "--project=$project", "--region=$region", "--format=value(status.conditions[0].status)") | Select-Object -First 1).Trim()
                    if ($ready.ToLowerInvariant() -ne "true") { throw "Cloud Run service $service is not ready." }
                }
            }
            "firebase-deploy" {
                $null = Invoke-Checked firebase @("deploy", "--only", "hosting", "--project", $project, "--account", $releaseState.FirebaseAccount, "--non-interactive")
            }
            "smoke-tests" {
                & $verify -DeploymentFile $DeploymentFile
                if ($LASTEXITCODE -ne 0) { throw "Production verification failed." }
            }
        }
    }
    }
    finally {
        if ($StopPrivateHostsAfterDeploy -and $releaseState.PrivateHostsStarted) {
            foreach ($vm in @("cynux-scanner-01", "cynux-defectdojo-01")) {
                try {
                    $null = Invoke-Checked $gcloud @("compute", "instances", "stop", $vm, "--project=$project", "--zone=$zone", "--quiet")
                }
                catch { Write-Warning "Failed to stop $vm; stop it manually to avoid compute charges." }
            }
        }
    }

    $record = @{
        project_id = $project
        region = $region
        image_tag = $imageTag
        firebase_url = "https://$project.web.app"
        api_service_uri = $releaseState.TerraformOutputs.api_service_uri.value
        web_service_uri = $releaseState.TerraformOutputs.web_service_uri.value
        migration_job_name = $releaseState.TerraformOutputs.migration_job_name.value
        scanner_instance_name = $releaseState.TerraformOutputs.scanner_instance_name.value
        defectdojo_instance_name = $releaseState.TerraformOutputs.defectdojo_instance_name.value
        artifact_bucket_name = $releaseState.TerraformOutputs.artifact_bucket_name.value
        deployed_at_utc = [DateTime]::UtcNow.ToString("o")
    }
    Write-DeploymentRecord -Path $LastDeploymentFile -Values $record
    return $record
}

if ($MyInvocation.InvocationName -ne ".") {
    Invoke-CynuxDeploy -ApproveApply:$ApproveApply -AllowDirtySnapshot:$AllowDirtySnapshot `
        -SkipBuild:$SkipBuild -ExistingImageTag $ExistingImageTag -FirebaseAccount $FirebaseAccount `
        -MigrationImageTag $MigrationImageTag `
        -StopPrivateHostsAfterDeploy:$StopPrivateHostsAfterDeploy `
        -DeploymentFile $DeploymentFile -LastDeploymentFile $LastDeploymentFile
}
