function Export-AuditReport {
    <#
    .SYNOPSIS
        Exports audit results to various formats.
    .DESCRIPTION
        Generates formatted reports from audit results:
        - HTML with interactive elements
        - JSON for automation
        - CSV for spreadsheet analysis
    .PARAMETER Results
        The audit results object from Invoke-WinSecAudit
    .PARAMETER OutputPath
        Directory to save the report
    .PARAMETER Format
        Output format: HTML, JSON, or CSV
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Results,

        [string]$OutputPath = '.\reports',

        [ValidateSet('HTML', 'JSON', 'CSV')]
        [string]$Format = 'HTML'
    )

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $computerName = $Results.ComputerName

    switch ($Format) {
        'HTML' {
            $reportFile = Join-Path $OutputPath "WinSecAudit_${computerName}_${timestamp}.html"

            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WinSecAudit Report - $computerName</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
            --passed: #28a745;
        }
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .header h1 { margin: 0 0 10px 0; }
        .header .meta { opacity: 0.8; font-size: 14px; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-card .count {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .summary-card.critical .count { color: var(--critical); }
        .summary-card.high .count { color: var(--high); }
        .summary-card.medium .count { color: var(--medium); }
        .summary-card.low .count { color: var(--low); }
        .summary-card.info .count { color: var(--info); }
        .summary-card.passed .count { color: var(--passed); }
        .category {
            background: white;
            border-radius: 10px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .category-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .category-header:hover { background: #e9ecef; }
        .category-header h2 { margin: 0; font-size: 18px; }
        .category-content { padding: 0; display: none; }
        .category.open .category-content { display: block; }
        .finding {
            padding: 15px 20px;
            border-bottom: 1px solid #f0f0f0;
        }
        .finding:last-child { border-bottom: none; }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .finding-title { font-weight: 600; }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }
        .severity-badge.critical { background: var(--critical); }
        .severity-badge.high { background: var(--high); }
        .severity-badge.medium { background: var(--medium); color: #333; }
        .severity-badge.low { background: var(--low); }
        .severity-badge.info { background: var(--info); }
        .severity-badge.passed { background: var(--passed); }
        .finding-details {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
            margin: 10px 0;
        }
        .finding-remediation {
            color: #0056b3;
            font-size: 14px;
        }
        .finding-reference {
            color: #6c757d;
            font-size: 12px;
            margin-top: 5px;
        }
        .toggle-icon { transition: transform 0.2s; }
        .category.open .toggle-icon { transform: rotate(180deg); }
        .no-findings { padding: 20px; color: #6c757d; text-align: center; }
        @media print {
            .category-content { display: block !important; }
            .toggle-icon { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WinSecAudit Security Report</h1>
            <div class="meta">
                <strong>Computer:</strong> $computerName |
                <strong>Domain:</strong> $($Results.Domain) |
                <strong>Scan Time:</strong> $($Results.AuditTime.ToString('yyyy-MM-dd HH:mm:ss')) |
                <strong>Duration:</strong> $($Results.Duration.TotalSeconds.ToString('F2'))s
            </div>
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <div class="count">$($Results.Summary.Critical)</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">$($Results.Summary.High)</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">$($Results.Summary.Medium)</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">$($Results.Summary.Low)</div>
                <div>Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">$($Results.Summary.Info)</div>
                <div>Info</div>
            </div>
            <div class="summary-card passed">
                <div class="count">$($Results.Summary.Passed)</div>
                <div>Passed</div>
            </div>
        </div>

"@

            foreach ($category in $Results.Categories.GetEnumerator()) {
                $categoryName = $category.Key
                $categoryData = $category.Value

                $html += @"
        <div class="category open">
            <div class="category-header" onclick="this.parentElement.classList.toggle('open')">
                <h2>$categoryName</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="category-content">
"@

                if ($categoryData.Findings -and $categoryData.Findings.Count -gt 0) {
                    foreach ($finding in $categoryData.Findings) {
                        $severityClass = $finding.Severity.ToLower()
                        $html += @"
                <div class="finding">
                    <div class="finding-header">
                        <span class="finding-title">$($finding.Check)</span>
                        <span class="severity-badge $severityClass">$($finding.Severity.ToUpper())</span>
                    </div>
                    <div>$($finding.Description)</div>
                    $(if ($finding.Details) { "<div class='finding-details'><strong>Details:</strong> $($finding.Details)</div>" })
                    $(if ($finding.Remediation) { "<div class='finding-remediation'><strong>Remediation:</strong> $($finding.Remediation)</div>" })
                    $(if ($finding.Reference) { "<div class='finding-reference'>Reference: $($finding.Reference)</div>" })
                </div>
"@
                    }
                }
                else {
                    $html += '<div class="no-findings">No findings in this category</div>'
                }

                $html += @"
            </div>
        </div>
"@
            }

            $html += @"
    </div>
    <script>
        // Auto-collapse passed categories
        document.querySelectorAll('.category').forEach(cat => {
            const findings = cat.querySelectorAll('.severity-badge:not(.passed)');
            if (findings.length === 0) {
                cat.classList.remove('open');
            }
        });
    </script>
</body>
</html>
"@

            $html | Out-File -FilePath $reportFile -Encoding UTF8
        }

        'JSON' {
            $reportFile = Join-Path $OutputPath "WinSecAudit_${computerName}_${timestamp}.json"
            $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile -Encoding UTF8
        }

        'CSV' {
            $reportFile = Join-Path $OutputPath "WinSecAudit_${computerName}_${timestamp}.csv"

            $csvData = @()
            foreach ($category in $Results.Categories.GetEnumerator()) {
                if ($category.Value.Findings) {
                    foreach ($finding in $category.Value.Findings) {
                        $csvData += [PSCustomObject]@{
                            Category = $category.Key
                            Check = $finding.Check
                            Severity = $finding.Severity
                            Status = $finding.Status
                            Description = $finding.Description
                            Details = $finding.Details
                            Remediation = $finding.Remediation
                            Reference = $finding.Reference
                        }
                    }
                }
            }

            $csvData | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8
        }
    }

    return $reportFile
}
