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
    if (-not $env:CLOUDSDK_PYTHON) {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($python) { $env:CLOUDSDK_PYTHON = $python.Source }
    }
}
