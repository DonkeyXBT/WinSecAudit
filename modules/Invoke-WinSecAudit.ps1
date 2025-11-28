function Invoke-WinSecAudit {
    <#
    .SYNOPSIS
        Runs a comprehensive security audit on Windows Server.
    .DESCRIPTION
        Performs security checks across multiple categories including:
        - Active Directory configuration
        - Local security policies
        - Firewall rules
        - Service configurations
        - User account security
        - Network settings
        - Audit policies
        - Scheduled tasks
        - Running processes
    .PARAMETER Categories
        Specific audit categories to run. Default is all categories.
    .PARAMETER OutputPath
        Path to save the audit report. Default is .\reports\
    .PARAMETER Format
        Output format: HTML, JSON, or CSV. Default is HTML.
    .PARAMETER Baseline
        Path to baseline configuration for comparison.
    .EXAMPLE
        Invoke-WinSecAudit -Categories @('AD', 'Firewall', 'Users')
    .EXAMPLE
        Invoke-WinSecAudit -Format JSON -OutputPath C:\Audits
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('All', 'AD', 'LocalPolicy', 'Firewall', 'Services', 'Registry',
                     'Users', 'Network', 'AuditPolicy', 'Processes', 'Tasks')]
        [string[]]$Categories = @('All'),

        [string]$OutputPath = (Join-Path $script:ModuleRoot "reports"),

        [ValidateSet('HTML', 'JSON', 'CSV')]
        [string]$Format = 'HTML',

        [string]$Baseline,

        [switch]$Quick,

        [switch]$Verbose
    )

    begin {
        $startTime = Get-Date
        $results = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            AuditTime = $startTime
            Categories = @{}
            Summary = @{
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
                Info = 0
                Passed = 0
            }
        }

        Write-Host "`n" -NoNewline
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "   WinSecAudit - Security Audit Tool   " -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "`nStarting security audit on: $($env:COMPUTERNAME)" -ForegroundColor Yellow
        Write-Host "Time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))`n" -ForegroundColor Gray
    }

    process {
        $categoriesToRun = if ($Categories -contains 'All') {
            @('AD', 'LocalPolicy', 'Firewall', 'Services', 'Registry',
              'Users', 'Network', 'AuditPolicy', 'Processes', 'Tasks')
        } else {
            $Categories
        }

        foreach ($category in $categoriesToRun) {
            Write-Host "[$category] " -ForegroundColor Cyan -NoNewline
            Write-Host "Running audit..." -ForegroundColor White

            $categoryResults = switch ($category) {
                'AD' {
                    if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
                        Test-ADSecurityConfig -Quick:$Quick
                    } else {
                        @{ Status = 'Skipped'; Reason = 'AD PowerShell module not available' }
                    }
                }
                'LocalPolicy' { Test-LocalSecurityPolicy -Quick:$Quick }
                'Firewall' { Test-FirewallConfig -Quick:$Quick }
                'Services' { Test-ServiceSecurity -Quick:$Quick }
                'Registry' { Test-RegistrySecurity -Quick:$Quick }
                'Users' { Test-UserAccountSecurity -Quick:$Quick }
                'Network' { Test-NetworkSecurity -Quick:$Quick }
                'AuditPolicy' { Test-AuditPolicy -Quick:$Quick }
                'Processes' { Get-SuspiciousProcesses -Quick:$Quick }
                'Tasks' { Get-ScheduledTaskAudit -Quick:$Quick }
            }

            $results.Categories[$category] = $categoryResults

            # Update summary counts
            if ($categoryResults.Findings) {
                foreach ($finding in $categoryResults.Findings) {
                    switch ($finding.Severity) {
                        'Critical' { $results.Summary.Critical++ }
                        'High' { $results.Summary.High++ }
                        'Medium' { $results.Summary.Medium++ }
                        'Low' { $results.Summary.Low++ }
                        'Info' { $results.Summary.Info++ }
                        'Passed' { $results.Summary.Passed++ }
                    }
                }
            }
        }

        # Compare with baseline if provided
        if ($Baseline -and (Test-Path $Baseline)) {
            Write-Host "`n[Baseline] " -ForegroundColor Cyan -NoNewline
            Write-Host "Comparing with baseline configuration..." -ForegroundColor White
            $results | Add-Member -NotePropertyName 'BaselineComparison' -NotePropertyValue (
                Compare-SecurityBaseline -Current $results -BaselinePath $Baseline
            )
        }
    }

    end {
        $endTime = Get-Date
        $duration = $endTime - $startTime

        $results | Add-Member -NotePropertyName 'Duration' -NotePropertyValue $duration

        # Display summary
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "            AUDIT SUMMARY              " -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan

        Write-Host "`nFindings by Severity:" -ForegroundColor Yellow
        Write-Host "  Critical: " -NoNewline; Write-Host $results.Summary.Critical -ForegroundColor Red
        Write-Host "  High:     " -NoNewline; Write-Host $results.Summary.High -ForegroundColor DarkRed
        Write-Host "  Medium:   " -NoNewline; Write-Host $results.Summary.Medium -ForegroundColor Yellow
        Write-Host "  Low:      " -NoNewline; Write-Host $results.Summary.Low -ForegroundColor DarkYellow
        Write-Host "  Info:     " -NoNewline; Write-Host $results.Summary.Info -ForegroundColor Cyan
        Write-Host "  Passed:   " -NoNewline; Write-Host $results.Summary.Passed -ForegroundColor Green

        Write-Host "`nDuration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Gray

        # Export report
        $reportFile = Export-AuditReport -Results $results -OutputPath $OutputPath -Format $Format
        Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green

        return $results
    }
}
