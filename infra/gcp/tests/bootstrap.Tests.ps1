$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path (Split-Path -Parent $here) "bootstrap.ps1")

Describe "Cynux GCP bootstrap" {
    It "refuses an explicitly requested project id that already exists" {
        $threw = $false
        try {
            $null = Resolve-CynuxProjectId -RequestedProjectId "cynux-taken" `
                -DeploymentFile "$TestDrive\missing.env" `
                -ProjectExists { param($Candidate) return $true }
        }
        catch { $threw = $true }
        $threw | Should Be $true
    }

    It "refuses a closed billing account" {
        $threw = $false
        try {
            Assert-OpenBillingAccount -BillingAccountId "000000-000000-000000" `
                -Describe { param($AccountId) return "False" }
        }
        catch { $threw = $true }
        $threw | Should Be $true
    }

    It "orders billing and the budget before infrastructure APIs" {
        $plan = Invoke-CynuxBootstrap -BillingAccountId "000000-000000-000000" -DryRun `
            -DeploymentFile "$TestDrive\ordering.env" -FirebaseRc "$TestDrive\firebaserc" `
            -ProjectExists { param($Candidate) return $false } `
            -OpenAccounts { return @("000000-000000-000000") } `
            -AssertBilling { param($AccountId) }

        ($plan.IndexOf("billing-link") -lt $plan.IndexOf("budget-create")) | Should Be $true
        ($plan.IndexOf("budget-create") -lt $plan.IndexOf("application-apis-enable")) | Should Be $true
    }

    It "reuses the recorded project id on a resumed bootstrap" {
        Set-Content -LiteralPath "$TestDrive\deployment.env" -Value "CYNUX_GCP_PROJECT_ID=cynux-recorded"
        Resolve-CynuxProjectId -DeploymentFile "$TestDrive\deployment.env" `
            -ProjectExists { param($Candidate) return $true } | Should Be "cynux-recorded"
    }

    It "does not place credential values in its dry-run output" {
        $output = (Invoke-CynuxBootstrap -BillingAccountId "000000-000000-000000" -DryRun `
            -DeploymentFile "$TestDrive\credentials.env" -FirebaseRc "$TestDrive\firebaserc" `
            -ProjectExists { param($Candidate) return $false } `
            -OpenAccounts { return @("000000-000000-000000") } `
            -AssertBilling { param($AccountId) }) -join "\n"

        $output | Should Not Match "ya29\."
        $output | Should Not Match "PRIVATE KEY"
        $output | Should Not Match "api[_-]?key="
    }
}
