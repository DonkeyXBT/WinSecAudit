function Get-SuspiciousProcesses {
    <#
    .SYNOPSIS
        Identifies potentially suspicious running processes.
    .DESCRIPTION
        Scans running processes for indicators of compromise:
        - Processes running from unusual locations
        - Known malicious process names
        - Processes with suspicious parent relationships
        - Encoded PowerShell commands
        - Processes masquerading as system processes
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting suspicious process analysis..."

    $processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue

    if (-not $processes) {
        $processes = Get-Process -ErrorAction SilentlyContinue
    }

    # Known suspicious process names (common malware/hacking tools)
    $suspiciousNames = @(
        'mimikatz', 'mimi', 'sekurlsa', 'procdump', 'lazagne',
        'rubeus', 'kerberoast', 'bloodhound', 'sharphound',
        'psexec', 'psexesvc', 'crackmapexec', 'nc', 'ncat', 'netcat',
        'powercat', 'empire', 'metasploit', 'cobaltstrike', 'beacon',
        'winpeas', 'linpeas', 'chisel', 'plink', 'ngrok'
    )

    # System processes that should run from specific locations
    $systemProcesses = @{
        'csrss' = 'C:\Windows\System32'
        'smss' = 'C:\Windows\System32'
        'svchost' = 'C:\Windows\System32'
        'services' = 'C:\Windows\System32'
        'lsass' = 'C:\Windows\System32'
        'winlogon' = 'C:\Windows\System32'
        'explorer' = 'C:\Windows'
        'taskhostw' = 'C:\Windows\System32'
        'dwm' = 'C:\Windows\System32'
    }

    # Suspicious locations
    $suspiciousLocations = @(
        '\Users\*\AppData\Local\Temp\',
        '\Users\*\Downloads\',
        '\ProgramData\',
        '\Windows\Temp\',
        '\Recycle',
        '\Users\Public\'
    )

    foreach ($proc in $processes) {
        try {
            $path = $proc.Path
            $name = $proc.ProcessName.ToLower()

            if (-not $path) { continue }

            # Check 1: Known suspicious process names
            foreach ($suspicious in $suspiciousNames) {
                if ($name -like "*$suspicious*") {
                    $findings += [PSCustomObject]@{
                        Check = "Suspicious Process - $($proc.ProcessName)"
                        Severity = 'Critical'
                        Status = 'Failed'
                        Description = "Potentially malicious process detected: $($proc.ProcessName)"
                        Details = "PID: $($proc.Id), Path: $path, User: $($proc.UserName)"
                        Remediation = 'Investigate process immediately and consider terminating if malicious'
                        Reference = 'Threat hunting'
                    }
                    break
                }
            }

            # Check 2: System process running from wrong location
            $expectedPath = $systemProcesses[$name]
            if ($expectedPath -and $path -notlike "$expectedPath*") {
                $findings += [PSCustomObject]@{
                    Check = "System Process Location - $($proc.ProcessName)"
                    Severity = 'Critical'
                    Status = 'Failed'
                    Description = "System process running from unexpected location"
                    Details = "Expected: $expectedPath, Actual: $path"
                    Remediation = 'Investigate - possible process masquerading or malware'
                    Reference = 'MITRE ATT&CK T1036'
                }
            }

            # Check 3: Processes running from suspicious locations
            if (-not $Quick) {
                foreach ($location in $suspiciousLocations) {
                    if ($path -like "*$location*") {
                        $findings += [PSCustomObject]@{
                            Check = "Process in Suspicious Location"
                            Severity = 'Medium'
                            Status = 'Warning'
                            Description = "Process running from potentially suspicious location"
                            Details = "Process: $($proc.ProcessName), Path: $path, PID: $($proc.Id)"
                            Remediation = 'Review process legitimacy and source'
                            Reference = 'Defense evasion indicator'
                        }
                        break
                    }
                }
            }
        }
        catch {
            # Unable to get process details
        }
    }

    # Check 4: PowerShell with encoded commands
    $psProcesses = $processes | Where-Object { $_.ProcessName -like '*powershell*' -or $_.ProcessName -like '*pwsh*' }

    foreach ($ps in $psProcesses) {
        try {
            $wmi = Get-WmiObject Win32_Process -Filter "ProcessId = $($ps.Id)" -ErrorAction SilentlyContinue
            $cmdLine = $wmi.CommandLine

            if ($cmdLine -match '-e[ncodedcommand]*\s+[A-Za-z0-9+/=]{50,}' -or $cmdLine -match '-enc\s+[A-Za-z0-9+/=]{50,}') {
                $findings += [PSCustomObject]@{
                    Check = 'Encoded PowerShell Command'
                    Severity = 'High'
                    Status = 'Warning'
                    Description = 'PowerShell running with encoded command'
                    Details = "PID: $($ps.Id), User: $($ps.UserName)"
                    Remediation = 'Decode and analyze the command for malicious content'
                    Reference = 'MITRE ATT&CK T1059.001'
                }
            }

            # Check for bypass flags
            if ($cmdLine -match '-ExecutionPolicy\s+(Bypass|Unrestricted)' -or $cmdLine -match '-ep\s+(bypass|unrestricted)') {
                $findings += [PSCustomObject]@{
                    Check = 'PowerShell Execution Policy Bypass'
                    Severity = 'Medium'
                    Status = 'Warning'
                    Description = 'PowerShell running with execution policy bypass'
                    Details = "PID: $($ps.Id), Command: $($cmdLine.Substring(0, [Math]::Min(100, $cmdLine.Length)))..."
                    Remediation = 'Review if bypass is legitimate or investigate for malicious activity'
                    Reference = 'MITRE ATT&CK T1059.001'
                }
            }
        }
        catch {
            # Unable to get command line
        }
    }

    # Check 5: Multiple instances of single-instance processes
    $singleInstance = @('lsass', 'csrss', 'smss', 'services', 'wininit')
    foreach ($procName in $singleInstance) {
        $instances = $processes | Where-Object { $_.ProcessName.ToLower() -eq $procName }
        # csrss and smss can have 2 instances
        $maxAllowed = if ($procName -in @('csrss', 'smss')) { 2 } else { 1 }

        if ($instances.Count -gt $maxAllowed) {
            $findings += [PSCustomObject]@{
                Check = "Multiple $procName Instances"
                Severity = 'Critical'
                Status = 'Failed'
                Description = "Multiple instances of $procName detected ($($instances.Count))"
                Details = "PIDs: $(($instances | Select-Object -ExpandProperty Id) -join ', ')"
                Remediation = 'Investigate - possible process injection or malware'
                Reference = 'MITRE ATT&CK T1055'
            }
        }
    }

    # Check 6: Unsigned running executables (if available)
    if (-not $Quick) {
        $unsigned = @()
        foreach ($proc in ($processes | Select-Object -First 50)) {
            if ($proc.Path -and (Test-Path $proc.Path -ErrorAction SilentlyContinue)) {
                try {
                    $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
                    if ($sig.Status -ne 'Valid' -and $proc.Path -notlike '*\Windows\*') {
                        $unsigned += $proc
                    }
                }
                catch { }
            }
        }

        if ($unsigned.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Check = 'Unsigned Executables Running'
                Severity = 'Low'
                Status = 'Info'
                Description = "$($unsigned.Count) unsigned non-system executables running"
                Details = ($unsigned | Select-Object -First 5 -ExpandProperty ProcessName) -join ', '
                Remediation = 'Review unsigned executables for legitimacy'
                Reference = 'Code signing best practices'
            }
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
