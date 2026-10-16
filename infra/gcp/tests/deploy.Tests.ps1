$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path (Split-Path -Parent $here) "deploy.ps1")

Describe "Cynux production release orchestration" {
    It "accepts CLI progress on stderr when the command succeeds" {
        $output = Invoke-Checked python @("-c", "import sys; print('progress', file=sys.stderr); print('complete')")
        ($output -join " ") | Should Match "complete"
    }

    It "still fails when a native command returns a nonzero exit code" {
        { Invoke-Checked python @("-c", "import sys; sys.exit(7)") } | Should Throw
    }
    It "requires an explicit immutable tag to skip a rebuild" {
        { Resolve-ReleaseImageTag -GitSha ("a" * 40) -SkipBuild } | Should Throw
        Resolve-ReleaseImageTag -GitSha ("b" * 40) -ExistingImageTag "abc123-dirty-456" -SkipBuild | Should Be "abc123-dirty-456"
        { Resolve-ReleaseImageTag -GitSha ("b" * 40) -ExistingImageTag "latest" -SkipBuild } | Should Throw
    }
    It "prefers the repository-local Google Cloud CLI when available" {
        $repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $here))
        $portable = Join-Path $repoRoot ".tools\gcloud\google-cloud-sdk\bin\gcloud.cmd"

        Resolve-CynuxCli -Name "gcloud" -RepoRoot $repoRoot `
            -PathExists { param($Path) $Path -eq $portable } `
            -CommandLookup { param($Name) throw "PATH lookup must not run" } | Should Be $portable
    }

    It "exposes isolated application-default credentials to Terraform" {
        $savedConfig = $env:CLOUDSDK_CONFIG
        $savedCredentials = $env:GOOGLE_APPLICATION_CREDENTIALS
        try {
            $env:CLOUDSDK_CONFIG = $null
            $env:GOOGLE_APPLICATION_CREDENTIALS = $null
            $configDir = Join-Path $TestDrive ".tools\gcloud-config"
            $null = New-Item -ItemType Directory -Path $configDir -Force
            $adc = Join-Path $configDir "application_default_credentials.json"
            Set-Content -LiteralPath $adc -Value '{}'

            Initialize-CynuxGcloudEnvironment -RepoRoot $TestDrive

            $env:GOOGLE_APPLICATION_CREDENTIALS | Should Be $adc
        }
        finally {
            $env:CLOUDSDK_CONFIG = $savedConfig
            $env:GOOGLE_APPLICATION_CREDENTIALS = $savedCredentials
        }
    }

    It "keeps the irreversible release stages in the required order" {
        $seen = [System.Collections.Generic.List[string]]::new()
        Invoke-ReleasePipeline -RunStage { param($Stage) $seen.Add($Stage) | Out-Null }

        ($seen -join ",") | Should Be (
            "preflight,billing-budget,terraform-plan,apply-approval,artifact-foundation,terraform-replan,build-push," +
            "terraform-apply,migration,private-host-bootstrap,secret-check,cloud-run-readiness," +
            "firebase-deploy,smoke-tests"
        )
    }

    It "creates only the image repository before the build and then replans" {
        $deploy = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "deploy.ps1")
        $deploy | Should Match '-target=google_artifact_registry_repository\.cynux'
        $deploy | Should Match '"terraform-replan"'
    }

    It "refreshes the worker release on every deployment" {
        $deploy = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "deploy.ps1")
        $compute = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "terraform\compute.tf")
        $refresh = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "scripts\refresh-worker.sh")

        $deploy | Should Match 'compute", "scp", \$workerRefresh'
        $deploy | Should Match 'sudo bash /tmp/cynux-worker-refresh\.sh'
        $compute | Should Match 'cynux-backend-image'
        $compute | Should Match 'cynux-multi-agent-worker-concurrency'
        $refresh | Should Match 'CYNUX_AGENT__WORKER_MAX_CONCURRENCY'
        $refresh | Should Match 'CYNUX_AGENT__TASK_LEASE_SECONDS'
        $refresh | Should Match 'systemctl restart cynux-worker\.service'
    }

    It "uses the stable account-currency budget guardrail name" {
        $deploy = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "deploy.ps1")
        $verify = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "verify.ps1")

        $deploy | Should Match "Cynux production credit guardrail"
        $verify | Should Match "Cynux production credit guardrail"
    }

    It "does not deploy Firebase Hosting when migration fails" {
        $seen = [System.Collections.Generic.List[string]]::new()
        $threw = $false
        try {
            Invoke-ReleasePipeline -RunStage {
                param($Stage)
                $seen.Add($Stage) | Out-Null
                if ($Stage -eq "migration") { throw "migration failed" }
            }
        }
        catch { $threw = $true }

        $threw | Should Be $true
        $seen.Contains("firebase-deploy") | Should Be $false
    }

    It "reuses the same immutable image tag for the same source snapshot" {
        $first = Resolve-ImageTag -GitSha ("a" * 40) -DirtyFingerprint "tree-hash" -AllowDirtySnapshot
        $second = Resolve-ImageTag -GitSha ("a" * 40) -DirtyFingerprint "tree-hash" -AllowDirtySnapshot

        $first | Should Be $second
        $first | Should Be "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dirty-tree-hash"
    }

    It "refuses a dirty source snapshot without the explicit override" {
        $threw = $false
        try { $null = Resolve-ImageTag -GitSha ("b" * 40) -DirtyFingerprint "dirty" }
        catch { $threw = $true }
        $threw | Should Be $true
    }

    It "writes only approved non-secret deployment fields" {
        $path = "$TestDrive\deployment.json"
        Write-DeploymentRecord -Path $path -Values @{
            project_id = "cynux-test"
            image_tag = "abc1234"
            firebase_url = "https://cynux-test.web.app"
            api_service_uri = "https://api.example"
            web_service_uri = "https://web.example"
            database_password = "must-not-leak"
        }
        $content = Get-Content -Raw -LiteralPath $path
        $content | Should Not Match "must-not-leak"
        $content | Should Match "cynux-test.web.app"
    }

    It "verifies connected transports" {
        $verify = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "verify.ps1")

        $verify | Should Match "ClientWebSocket"
        $verify | Should Match 'storage", "cp"'
        $verify | Should Match 'wss://cynux-api-\$projectNumber\.\$region\.run\.app'
        $verify | Should Match "systemctl is-active cynux-worker"
        $verify | Should Match "/ws/agent/runs/"
        $verify | Should Match "CYNUX_AGENT__WORKER_MAX_CONCURRENCY"
        $verify | Should Match 'grep -q \^CYNUX_AGENT__TASK_LEASE_SECONDS='
        $verify | Should Not Match "sudo sh -c.*CYNUX_FEATURES__MULTI_AGENT"
        $verify | Should Match 'networkInterfaces\[0\].networkIP'
    }

    It "keeps private hosts running by default and makes cleanup explicit" {
        $deploy = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "deploy.ps1")
        $compute = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "terraform\compute.tf")

        $deploy | Should Match '\[switch\]\$StopPrivateHostsAfterDeploy'
        $deploy | Should Match 'if \(\$StopPrivateHostsAfterDeploy -and \$releaseState\.PrivateHostsStarted\)'
        ([regex]::Matches($compute, 'desired_status\s*=\s*"RUNNING"')).Count | Should Be 2
    }

    It "keeps local deployment state and verification artifacts out of git" {
        $repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $here))
        $ignore = Get-Content -Raw -LiteralPath (Join-Path $repoRoot ".gitignore")
        $ignore | Should Match "/infra/gcp/\.deployment\.env"
        $ignore | Should Match "/infra/gcp/\.last-deployment\.json"
        $ignore | Should Match "/infra/gcp/\.verification\.json"
        $ignore | Should Match "/infra/gcp/\.production\.tfplan"
    }
}
