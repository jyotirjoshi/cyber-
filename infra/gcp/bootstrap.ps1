[CmdletBinding()]
param(
    [string]$BillingAccountId,
    [string]$ProjectId,
    [string]$Account = "nexrasecurity@gmail.com",
    [string]$Region = "asia-south1",
    [string]$Zone = "asia-south1-a",
    [switch]$DryRun,
    [string]$DeploymentFile = (Join-Path $PSScriptRoot ".deployment.env"),
    [string]$FirebaseRc = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ".firebaserc")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Gcloud {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $output = & gcloud @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gcloud command failed: gcloud $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    return $output
}

function Invoke-Firebase {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $output = & firebase @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Firebase command failed: firebase $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    return $output
}

function Test-GcloudProjectExists {
    param([Parameter(Mandatory)][string]$Candidate)
    try {
        $null = Invoke-Gcloud -Arguments @("projects", "describe", $Candidate, "--format=value(projectId)")
        return $true
    }
    catch {
        return $false
    }
}

function Get-RecordedProjectId {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $line = Get-Content -LiteralPath $Path | Where-Object { $_ -match '^CYNUX_GCP_PROJECT_ID=' } | Select-Object -First 1
    if (-not $line) { return $null }
    return ($line -split '=', 2)[1].Trim()
}

function Resolve-CynuxProjectId {
    param(
        [string]$RequestedProjectId,
        [Parameter(Mandatory)][string]$DeploymentFile,
        [scriptblock]$ProjectExists = { param($Candidate) Test-GcloudProjectExists -Candidate $Candidate }
    )
    $recorded = Get-RecordedProjectId -Path $DeploymentFile
    if ($recorded) {
        if (-not (& $ProjectExists $recorded)) {
            throw "Recorded project '$recorded' is no longer accessible; refusing to replace it."
        }
        return $recorded
    }
    if ($RequestedProjectId) {
        if (& $ProjectExists $RequestedProjectId) {
            throw "Requested project '$RequestedProjectId' already exists and is not recorded for this deployment."
        }
        return $RequestedProjectId
    }
    $base = "cynux-security-prod"
    if (-not (& $ProjectExists $base)) { return $base }
    return "$base-$(([guid]::NewGuid().ToString('N')).Substring(0, 6))"
}

function Get-OpenBillingAccounts {
    $rows = Invoke-Gcloud -Arguments @("billing", "accounts", "list", "--filter=open=true", "--format=value(name)")
    return @($rows | ForEach-Object { ([string]$_).Replace("billingAccounts/", "").Trim() } | Where-Object { $_ })
}

function Assert-OpenBillingAccount {
    param(
        [Parameter(Mandatory)][string]$BillingAccountId,
        [scriptblock]$Describe = {
            param($AccountId)
            Invoke-Gcloud -Arguments @(
                "billing", "accounts", "describe", $AccountId, "--format=value(open)"
            )
        }
    )
    $open = (& $Describe $BillingAccountId | Select-Object -First 1)
    if (([string]$open).Trim().ToLowerInvariant() -ne "true") {
        throw "Billing account '$BillingAccountId' is not open."
    }
}

function Set-FirebaseProjectAlias {
    param([string]$Path, [string]$ResolvedProjectId)
    $document = [ordered]@{ projects = [ordered]@{ production = $ResolvedProjectId } }
    $document | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Invoke-CynuxBootstrap {
    [CmdletBinding()]
    param(
        [string]$BillingAccountId,
        [string]$ProjectId,
        [string]$Account = "nexrasecurity@gmail.com",
        [string]$Region = "asia-south1",
        [string]$Zone = "asia-south1-a",
        [switch]$DryRun,
        [string]$DeploymentFile = (Join-Path $PSScriptRoot ".deployment.env"),
        [string]$FirebaseRc = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ".firebaserc"),
        [scriptblock]$ProjectExists = { param($Candidate) Test-GcloudProjectExists -Candidate $Candidate },
        [scriptblock]$OpenAccounts = { Get-OpenBillingAccounts },
        [scriptblock]$AssertBilling = { param($AccountId) Assert-OpenBillingAccount -BillingAccountId $AccountId }
    )

    $resolved = Resolve-CynuxProjectId -RequestedProjectId $ProjectId -DeploymentFile $DeploymentFile -ProjectExists $ProjectExists
    $accounts = @(& $OpenAccounts)
    if (-not $BillingAccountId) {
        if ($accounts.Count -ne 1) {
            throw "Specify -BillingAccountId; expected exactly one open account, found $($accounts.Count)."
        }
        $BillingAccountId = $accounts[0]
    }
    if ($BillingAccountId -notin $accounts) {
        throw "Billing account '$BillingAccountId' is not in the open billing-account list."
    }
    & $AssertBilling $BillingAccountId

    $stages = [System.Collections.Generic.List[string]]::new()
    $stages.Add("project-create")
    $stages.Add("billing-link")
    $stages.Add("foundation-apis-enable")
    $stages.Add("budget-create")
    $stages.Add("application-apis-enable")
    $stages.Add("firebase-register")
    $stages.Add("terraform-state-create")
    if ($DryRun) { return $stages.ToArray() }

    if (-not (Test-GcloudProjectExists -Candidate $resolved)) {
        $null = Invoke-Gcloud -Arguments @(
            "projects", "create", $resolved, "--name=Cynux Security Production", "--labels=application=cynux,environment=production"
        )
    }
    $null = Invoke-Gcloud -Arguments @("billing", "projects", "link", $resolved, "--billing-account=$BillingAccountId")
    $null = Invoke-Gcloud -Arguments @("config", "set", "project", $resolved)

    $foundationApis = @(
        "serviceusage.googleapis.com", "cloudbilling.googleapis.com",
        "billingbudgets.googleapis.com", "cloudresourcemanager.googleapis.com",
        "firebase.googleapis.com"
    )
    $null = Invoke-Gcloud -Arguments (@("services", "enable", "--project=$resolved") + $foundationApis)

    $projectNumber = (Invoke-Gcloud -Arguments @("projects", "describe", $resolved, "--format=value(projectNumber)") | Select-Object -First 1).Trim()
    $budgetName = "Cynux production USD 300"
    $existingBudget = Invoke-Gcloud -Arguments @(
        "billing", "budgets", "list", "--billing-account=$BillingAccountId",
        "--filter=displayName='$budgetName'", "--format=value(displayName)"
    )
    if (-not ($existingBudget | Where-Object { ([string]$_).Trim() -eq $budgetName })) {
        $null = Invoke-Gcloud -Arguments @(
            "billing", "budgets", "create", "--billing-account=$BillingAccountId",
            "--display-name=$budgetName", "--budget-amount=300USD", "--calendar-period=year",
            "--filter-projects=projects/$projectNumber",
            "--threshold-rule=percent=0.25", "--threshold-rule=percent=0.50",
            "--threshold-rule=percent=0.75", "--threshold-rule=percent=0.90",
            "--threshold-rule=percent=1.00", "--threshold-rule=percent=0.90,basis=forecasted-spend"
        )
    }

    $applicationApis = @(
        "compute.googleapis.com", "run.googleapis.com", "cloudbuild.googleapis.com",
        "artifactregistry.googleapis.com", "sqladmin.googleapis.com", "redis.googleapis.com",
        "servicenetworking.googleapis.com", "secretmanager.googleapis.com",
        "storage.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com",
        "logging.googleapis.com", "monitoring.googleapis.com", "iap.googleapis.com"
    )
    $null = Invoke-Gcloud -Arguments (@("services", "enable", "--project=$resolved") + $applicationApis)

    $firebaseProjects = (Invoke-Firebase -Arguments @("projects:list", "--json", "--account", $Account) | Out-String)
    if ($firebaseProjects -notmatch ('"projectId"\s*:\s*"' + [regex]::Escape($resolved) + '"')) {
        $null = Invoke-Firebase -Arguments @("projects:addfirebase", $resolved, "--account", $Account, "--non-interactive")
    }

    $stateBucket = "$resolved-tfstate"
    try {
        $null = Invoke-Gcloud -Arguments @("storage", "buckets", "describe", "gs://$stateBucket", "--project=$resolved")
    }
    catch {
        $null = Invoke-Gcloud -Arguments @(
            "storage", "buckets", "create", "gs://$stateBucket", "--project=$resolved",
            "--location=$Region", "--uniform-bucket-level-access", "--public-access-prevention"
        )
        $null = Invoke-Gcloud -Arguments @("storage", "buckets", "update", "gs://$stateBucket", "--versioning")
    }

    @(
        "CYNUX_GCP_PROJECT_ID=$resolved",
        "CYNUX_GCP_REGION=$Region",
        "CYNUX_GCP_ZONE=$Zone",
        "CYNUX_GCP_TERRAFORM_STATE_BUCKET=$stateBucket"
    ) | Set-Content -LiteralPath $DeploymentFile -Encoding utf8
    Set-FirebaseProjectAlias -Path $FirebaseRc -ResolvedProjectId $resolved

    Write-Host "Cynux cloud bootstrap complete for project $resolved."
    return $resolved
}

if ($MyInvocation.InvocationName -ne ".") {
    Invoke-CynuxBootstrap -BillingAccountId $BillingAccountId -ProjectId $ProjectId -Account $Account `
        -Region $Region -Zone $Zone -DryRun:$DryRun -DeploymentFile $DeploymentFile -FirebaseRc $FirebaseRc
}
