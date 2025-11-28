function Get-ScheduledTaskAudit {
    <#
    .SYNOPSIS
        Audits scheduled tasks for security issues.
    .DESCRIPTION
        Analyzes scheduled tasks for potential security concerns:
        - Tasks running as SYSTEM
        - Tasks with suspicious actions
        - Tasks created recently
        - Tasks running from temp directories
        - Tasks with encoded commands
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting scheduled task audit..."

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }

    if (-not $tasks) {
        return @{
            Status = 'Error'
            Message = 'Unable to query scheduled tasks'
            Findings = @()
        }
    }

    # Suspicious patterns in task actions
    $suspiciousPatterns = @(
        'powershell.*-enc',
        'powershell.*-e\s+[A-Za-z0-9+/=]{20,}',
        'powershell.*downloadstring',
        'powershell.*webclient',
        'powershell.*iex',
        'cmd.*/c.*http',
        'certutil.*-urlcache',
        'bitsadmin.*transfer',
        'mshta.*http',
        'regsvr32.*/s.*/n.*/u',
        'rundll32.*javascript',
        'wscript.*http',
        'cscript.*http'
    )

    foreach ($task in $tasks) {
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $principal = $task.Principal
            $actions = $task.Actions

            # Check 1: Tasks running as SYSTEM from non-standard locations
            if ($principal.UserId -eq 'SYSTEM' -or $principal.UserId -eq 'S-1-5-18') {
                foreach ($action in $actions) {
                    $execute = $action.Execute

                    if ($execute -and
                        $execute -notlike '*\Windows\*' -and
                        $execute -notlike '*\Program Files*' -and
                        $execute -notlike '*\ProgramData\Microsoft\*') {

                        $findings += [PSCustomObject]@{
                            Check = "SYSTEM Task Non-Standard Location"
                            Severity = 'High'
                            Status = 'Warning'
                            Description = "Task '$($task.TaskName)' runs as SYSTEM from non-standard location"
                            Details = "Path: $($task.TaskPath), Execute: $execute"
                            Remediation = 'Review task legitimacy and source'
                            Reference = 'MITRE ATT&CK T1053.005'
                        }
                    }
                }
            }

            # Check 2: Suspicious action patterns
            foreach ($action in $actions) {
                $actionString = "$($action.Execute) $($action.Arguments)"

                foreach ($pattern in $suspiciousPatterns) {
                    if ($actionString -match $pattern) {
                        $findings += [PSCustomObject]@{
                            Check = "Suspicious Task Action"
                            Severity = 'Critical'
                            Status = 'Failed'
                            Description = "Task '$($task.TaskName)' has suspicious action pattern"
                            Details = "Pattern matched: $pattern"
                            Remediation = 'Investigate task immediately - possible malware persistence'
                            Reference = 'MITRE ATT&CK T1053.005'
                        }
                        break
                    }
                }
            }

            # Check 3: Recently created tasks (last 7 days)
            if (-not $Quick -and $taskInfo.LastTaskResult -ne $null) {
                $taskXml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

                if ($taskXml -match '<Date>(\d{4}-\d{2}-\d{2})') {
                    $createDate = [DateTime]::Parse($Matches[1])
                    $daysSinceCreation = ((Get-Date) - $createDate).TotalDays

                    if ($daysSinceCreation -lt 7) {
                        $findings += [PSCustomObject]@{
                            Check = "Recently Created Task"
                            Severity = 'Low'
                            Status = 'Info'
                            Description = "Task '$($task.TaskName)' was created recently"
                            Details = "Created: $($createDate.ToString('yyyy-MM-dd')), Days ago: $([int]$daysSinceCreation)"
                            Remediation = 'Verify new task is legitimate'
                            Reference = 'Security monitoring'
                        }
                    }
                }
            }

            # Check 4: Tasks running from temp directories
            foreach ($action in $actions) {
                $execute = $action.Execute

                if ($execute -like '*\Temp\*' -or
                    $execute -like '*\tmp\*' -or
                    $execute -like '*\AppData\Local\Temp\*') {

                    $findings += [PSCustomObject]@{
                        Check = "Task Running from Temp"
                        Severity = 'High'
                        Status = 'Failed'
                        Description = "Task '$($task.TaskName)' runs from temporary directory"
                        Details = "Execute: $execute"
                        Remediation = 'Tasks should not run from temporary directories'
                        Reference = 'MITRE ATT&CK T1053.005'
                    }
                }
            }

            # Check 5: Hidden tasks (tasks in root that look suspicious)
            if ($task.TaskPath -eq '\' -and
                $task.TaskName -notmatch '^(Microsoft|User_Feed_Synchronization|CreateExplorerShellUnelevatedTask)') {

                $isBuiltin = $false
                $builtinTasks = @('MicrosoftEdge*', 'GoogleUpdate*', 'Adobe*', 'CCleaner*', 'OneDrive*')

                foreach ($builtin in $builtinTasks) {
                    if ($task.TaskName -like $builtin) {
                        $isBuiltin = $true
                        break
                    }
                }

                if (-not $isBuiltin) {
                    $findings += [PSCustomObject]@{
                        Check = "Task in Root Folder"
                        Severity = 'Low'
                        Status = 'Info'
                        Description = "Non-standard task in root folder: $($task.TaskName)"
                        Details = "Author: $($task.Author), State: $($task.State)"
                        Remediation = 'Review task for legitimacy'
                        Reference = 'Task organization best practices'
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error processing task $($task.TaskName): $_"
        }
    }

    # Check 6: Count of SYSTEM tasks
    $systemTasks = $tasks | Where-Object { $_.Principal.UserId -eq 'SYSTEM' -or $_.Principal.UserId -eq 'S-1-5-18' }
    if ($systemTasks.Count -gt 50) {
        $findings += [PSCustomObject]@{
            Check = 'High Number of SYSTEM Tasks'
            Severity = 'Info'
            Status = 'Info'
            Description = "$($systemTasks.Count) scheduled tasks run as SYSTEM"
            Details = 'Large number of SYSTEM tasks increases attack surface'
            Remediation = 'Review and remove unnecessary SYSTEM tasks'
            Reference = 'Principle of least privilege'
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
