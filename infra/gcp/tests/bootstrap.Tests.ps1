$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path (Split-Path -Parent $here) "bootstrap.ps1")

Describe "Cynux GCP bootstrap" {
    It "uses a valid budget amount for the billing account currency" {
        Get-CynuxBudgetAmount -CurrencyCode "USD" | Should Be "300USD"
        Get-CynuxBudgetAmount -CurrencyCode "INR" | Should Be "28500INR"
    }

    It "filters the budget by project id as required by the current CLI" {
        $source = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "bootstrap.ps1")
        $source | Should Match '--filter-projects=projects/\$resolved'
        $source | Should Not Match '--filter-projects=projects/\$projectNumber'
    }

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

    It "writes the resolved Firebase alias before invoking Firebase CLI" {
        $source = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "bootstrap.ps1")
        $aliasWrite = $source.IndexOf('Set-FirebaseProjectAlias -Path $FirebaseRc -ResolvedProjectId $resolved')
        $firebaseLookup = $source.IndexOf('$firebaseProjects = (Invoke-Firebase')

        $aliasWrite | Should BeGreaterThan -1
        $firebaseLookup | Should BeGreaterThan $aliasWrite
    }

    It "checkpoints the project before linking billing so interrupted bootstraps resume safely" {
        $source = Get-Content -Raw -LiteralPath (Join-Path (Split-Path -Parent $here) "bootstrap.ps1")
        $checkpoint = $source.IndexOf('Write-DeploymentConfig -Path $DeploymentFile')
        $billingLink = $source.IndexOf('"billing", "projects", "link"')

        $checkpoint | Should BeGreaterThan -1
        $billingLink | Should BeGreaterThan $checkpoint
    }
}
