function Test-ServiceSecurity {
    <#
    .SYNOPSIS
        Audits Windows Service security configuration.
    .DESCRIPTION
        Checks for insecure service configurations:
        - Services running as LocalSystem unnecessarily
        - Unquoted service paths
        - Weak service permissions
        - Dangerous services enabled
        - Services with writable executables
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting service security audit..."

    $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue

    if (-not $services) {
        return @{
            Status = 'Error'
            Message = 'Unable to query services'
            Findings = @()
        }
    }

    # Dangerous services that should be disabled
    $dangerousServices = @(
        @{ Name = 'RemoteRegistry'; Description = 'Remote Registry service' },
        @{ Name = 'Telnet'; Description = 'Telnet service' },
        @{ Name = 'SNMP'; Description = 'Simple Network Management Protocol' },
        @{ Name = 'SSDPSRV'; Description = 'SSDP Discovery' },
        @{ Name = 'upnphost'; Description = 'UPnP Device Host' },
        @{ Name = 'WinHttpAutoProxySvc'; Description = 'WinHTTP Web Proxy Auto-Discovery' },
        @{ Name = 'Fax'; Description = 'Fax service' },
        @{ Name = 'lltdsvc'; Description = 'Link-Layer Topology Discovery Mapper' },
        @{ Name = 'MSiSCSI'; Description = 'Microsoft iSCSI Initiator Service' },
        @{ Name = 'SNMPTRAP'; Description = 'SNMP Trap' }
    )

    # Check 1: Dangerous Services Enabled
    foreach ($dangerous in $dangerousServices) {
        $service = $services | Where-Object { $_.Name -eq $dangerous.Name -and $_.State -eq 'Running' }
        if ($service) {
            $findings += [PSCustomObject]@{
                Check = "Dangerous Service Running - $($dangerous.Name)"
                Severity = 'Medium'
                Status = 'Failed'
                Description = "$($dangerous.Description) is running"
                Details = "Service: $($service.DisplayName), State: $($service.State)"
                Remediation = "Disable service if not needed: Stop-Service -Name '$($dangerous.Name)'; Set-Service -Name '$($dangerous.Name)' -StartupType Disabled"
                Reference = 'CIS Benchmark: 5.x'
            }
        }
    }

    # Check 2: Unquoted Service Paths
    $unquotedPaths = $services | Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -match '\s' -and
        $_.PathName -notmatch '^[a-zA-Z]:\\Windows\\' # Exclude system paths
    }

    foreach ($service in $unquotedPaths) {
        $findings += [PSCustomObject]@{
            Check = "Unquoted Service Path - $($service.Name)"
            Severity = 'High'
            Status = 'Failed'
            Description = "Service '$($service.DisplayName)' has an unquoted path with spaces"
            Details = "Path: $($service.PathName)"
            Remediation = 'Quote the service path in the registry or reinstall the software'
            Reference = 'CVE-2013-1609'
        }
    }

    # Check 3: Services Running as LocalSystem (non-Microsoft)
    if (-not $Quick) {
        $localSystemServices = $services | Where-Object {
            $_.StartName -eq 'LocalSystem' -and
            $_.State -eq 'Running' -and
            $_.PathName -notmatch 'Windows\\System32|Windows\\SysWOW64'
        }

        if ($localSystemServices.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Check = 'Non-System Services Running as LocalSystem'
                Severity = 'Medium'
                Status = 'Warning'
                Description = "$($localSystemServices.Count) non-system services running as LocalSystem"
                Details = ($localSystemServices | Select-Object -First 5 -ExpandProperty DisplayName) -join ', '
                Remediation = 'Review services and configure to run with least privilege accounts'
                Reference = 'Principle of least privilege'
            }
        }
    }

    # Check 4: Check for writable service executables
    if (-not $Quick) {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $writableServices = @()

        foreach ($service in $services | Where-Object { $_.PathName }) {
            $exePath = $service.PathName -replace '^"([^"]+)".*', '$1'
            $exePath = $exePath -replace '\s+-.*$', ''

            if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                try {
                    $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                    $writeRules = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                        $_.IdentityReference -match 'Users|Everyone|Authenticated Users'
                    }

                    if ($writeRules) {
                        $writableServices += $service
                    }
                }
                catch {
                    # Unable to check ACL
                }
            }
        }

        if ($writableServices.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Check = 'Writable Service Executables'
                Severity = 'Critical'
                Status = 'Failed'
                Description = "$($writableServices.Count) services have writable executables"
                Details = ($writableServices | Select-Object -First 5 -ExpandProperty DisplayName) -join ', '
                Remediation = 'Remove write permissions for non-admin users on service executables'
                Reference = 'Privilege Escalation Vector'
            }
        }
    }

    # Check 5: Windows Defender Service
    $defenderService = $services | Where-Object { $_.Name -eq 'WinDefend' }
    if ($defenderService -and $defenderService.State -ne 'Running') {
        $findings += [PSCustomObject]@{
            Check = 'Windows Defender Service'
            Severity = 'High'
            Status = 'Failed'
            Description = 'Windows Defender service is not running'
            Details = "State: $($defenderService.State)"
            Remediation = 'Start and enable Windows Defender service'
            Reference = 'CIS Benchmark: 18.9.77.x'
        }
    }

    # Check 6: Windows Update Service
    $wuauService = $services | Where-Object { $_.Name -eq 'wuauserv' }
    if ($wuauService -and $wuauService.StartMode -eq 'Disabled') {
        $findings += [PSCustomObject]@{
            Check = 'Windows Update Service'
            Severity = 'High'
            Status = 'Failed'
            Description = 'Windows Update service is disabled'
            Details = "StartMode: $($wuauService.StartMode)"
            Remediation = 'Enable Windows Update service for security patches'
            Reference = 'CIS Benchmark: 5.29'
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
