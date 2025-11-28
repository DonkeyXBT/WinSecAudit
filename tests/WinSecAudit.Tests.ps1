BeforeAll {
    $ModulePath = Join-Path $PSScriptRoot '..' 'WinSecAudit.psm1'
}

Describe 'WinSecAudit Module' {
    Context 'Module Loading' {
        It 'Should import without errors' {
            { Import-Module $ModulePath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Should export Invoke-WinSecAudit function' {
            Import-Module $ModulePath -Force
            Get-Command Invoke-WinSecAudit -Module WinSecAudit | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Function Availability' {
        BeforeAll {
            Import-Module $ModulePath -Force
        }

        It 'Should have Test-LocalSecurityPolicy function' {
            Get-Command Test-LocalSecurityPolicy -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should have Test-FirewallConfig function' {
            Get-Command Test-FirewallConfig -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should have Export-AuditReport function' {
            Get-Command Export-AuditReport -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Security Check Helpers' {
    Context 'Finding Object Structure' {
        It 'Should create valid finding object' {
            $finding = [PSCustomObject]@{
                Check = 'Test Check'
                Severity = 'High'
                Status = 'Failed'
                Description = 'Test description'
                Details = 'Test details'
                Remediation = 'Test remediation'
                Reference = 'Test reference'
            }

            $finding.Check | Should -Be 'Test Check'
            $finding.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Info', 'Passed')
            $finding.Status | Should -BeIn @('Failed', 'Warning', 'Passed', 'Info')
        }
    }
}
