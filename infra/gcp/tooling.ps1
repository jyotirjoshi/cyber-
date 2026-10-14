Set-StrictMode -Version Latest

function Resolve-CynuxCli {
    param(
        [Parameter(Mandatory)][ValidateSet("gcloud")][string]$Name,
        [Parameter(Mandatory)][string]$RepoRoot,
        [scriptblock]$PathExists = { param($Path) Test-Path -LiteralPath $Path -PathType Leaf },
        [scriptblock]$CommandLookup = { param($CommandName) Get-Command $CommandName -ErrorAction Stop }
    )

    $portable = switch ($Name) {
        "gcloud" { Join-Path $RepoRoot ".tools\gcloud\google-cloud-sdk\bin\gcloud.cmd" }
    }
    if (& $PathExists $portable) { return $portable }

    try {
        $command = & $CommandLookup $Name
        if ($command.Path) { return $command.Path }
        if ($command.Source) { return $command.Source }
        return $Name
    }
    catch {
        throw "Required CLI '$Name' was not found at '$portable' or on PATH."
    }
}

function Initialize-CynuxGcloudEnvironment {
    param([Parameter(Mandatory)][string]$RepoRoot)

    if (-not $env:CLOUDSDK_CONFIG) {
        $env:CLOUDSDK_CONFIG = Join-Path $RepoRoot ".tools\gcloud-config"
    }
    $adc = Join-Path $env:CLOUDSDK_CONFIG "application_default_credentials.json"
    if (-not $env:GOOGLE_APPLICATION_CREDENTIALS -and (Test-Path -LiteralPath $adc -PathType Leaf)) {
        # Terraform's Google provider does not honor a non-default
        # CLOUDSDK_CONFIG path when discovering ADC, so provide it explicitly.
        $env:GOOGLE_APPLICATION_CREDENTIALS = $adc
    }
    if (-not $env:CLOUDSDK_PYTHON) {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($python) { $env:CLOUDSDK_PYTHON = $python.Source }
    }
}
