# WinSecAudit

[![.NET](https://img.shields.io/badge/.NET-9.0-512BD4.svg)](https://dotnet.microsoft.com/)
[![WinUI](https://img.shields.io/badge/WinUI-3.0-0078D4.svg)](https://docs.microsoft.com/en-us/windows/apps/winui/)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS-Aligned-orange.svg)](https://www.cisecurity.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)

A comprehensive Windows security auditing toolkit featuring both a modern WinUI 3 desktop application and PowerShell modules. WinSecAudit helps security professionals identify misconfigurations, vulnerabilities, and compliance gaps against industry standards like CIS Benchmarks and DISA STIGs.

![Windows 10](https://img.shields.io/badge/Windows%2010-0078D6?logo=windows10&logoColor=white)
![Windows 11](https://img.shields.io/badge/Windows%2011-0078D4?logo=windows11&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%2B-blue)

---

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
  - [Desktop Application](#desktop-application-winui-3)
  - [PowerShell Module](#powershell-module)
- [Usage](#usage)
  - [Desktop Application](#using-the-desktop-application)
  - [PowerShell](#using-powershell)
- [Security Categories](#security-categories)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Desktop Application (WinUI 3)
- Modern, native Windows 11 design language
- Real-time scanning progress with live findings
- Interactive dashboard with security score
- Category-based scanning with detailed results
- Export reports to HTML, JSON, CSV, and PDF
- Baseline comparison for compliance tracking
- One-click remediation suggestions
- Dark/Light theme support

### PowerShell Module
- Scriptable security audits for automation
- Integration with CI/CD pipelines
- SIEM-compatible JSON output
- Scheduled task support
- Remote scanning capabilities
- Customizable check modules

### Security Coverage
| Category | Description | Checks |
|----------|-------------|--------|
| Active Directory | Delegation, privileged groups, stale accounts, LDAP signing | 12 |
| Local Security Policy | Password policies, account lockout, user rights | 15 |
| Windows Firewall | Profile status, rules, logging configuration | 10 |
| Windows Services | Unquoted paths, dangerous services, permissions | 8 |
| Registry Security | SMB signing, LLMNR, WDigest, UAC, LSA protection | 12 |
| User Accounts | Password settings, administrators, inactive accounts | 10 |
| Network Security | Open ports, shares, IPv6, WPAD, DNS configuration | 8 |
| Audit Policy | Windows auditing, PowerShell logging, command line | 10 |
| Running Processes | Suspicious processes, encoded commands, anomalies | 6 |
| Scheduled Tasks | Persistence mechanisms, SYSTEM tasks, suspicious actions | 5 |

---

## Screenshots

*Desktop application screenshots coming soon*

---

## Installation

### Desktop Application (WinUI 3)

#### Prerequisites
- Windows 10 version 1809 or later / Windows 11
- [.NET 9.0 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Windows App SDK Runtime](https://docs.microsoft.com/en-us/windows/apps/windows-app-sdk/downloads)
- Administrator privileges

#### Option 1: Download Release
1. Go to the [Releases page](https://github.com/DonkeyXBT/WinSecAudit/releases)
2. Download the latest release
3. Extract and run as Administrator

#### Option 2: Build from Source (Windows only)
Requires [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) installed on Windows.

```powershell
# Clone the repository
git clone https://github.com/DonkeyXBT/WinSecAudit.git
cd WinSecAudit

# Build the application
dotnet build WinSecAudit.App/WinSecAudit.App.csproj -c Release

# Run the application (as Administrator)
dotnet run --project WinSecAudit.App/WinSecAudit.App.csproj
```

### PowerShell Module

#### Option 1: Direct Import
```powershell
# Clone the repository
git clone https://github.com/DonkeyXBT/WinSecAudit.git

# Import the module
Import-Module .\WinSecAudit\WinSecAudit.psm1
```

#### Option 2: Install to Modules Path
```powershell
# Clone and copy to PowerShell modules directory
git clone https://github.com/DonkeyXBT/WinSecAudit.git
Copy-Item -Path .\WinSecAudit -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\" -Recurse

# Import (auto-loads from modules path)
Import-Module WinSecAudit
```

---

## Usage

### Using the Desktop Application

#### Quick Scan
1. Launch WinSecAudit as Administrator
2. Click **Quick Scan** in the navigation menu
3. Click **Start Quick Scan**
4. Review findings in the results panel
5. Click any finding for detailed remediation steps

#### Full Audit
1. Click **Full Audit** in the navigation menu
2. Select categories to include (all selected by default)
3. Click **Start Full Audit**
4. Monitor progress in real-time
5. Export results when complete

#### Category-Specific Scans
Navigate to any category page (Firewall, Registry, Services, etc.) to run targeted scans for that specific area.

#### Working with Baselines
1. Go to **Baselines** page
2. Click **Create Baseline** to capture current configuration
3. Run future audits with baseline comparison enabled
4. View compliance percentage against your baseline

#### Exporting Reports
1. Complete a scan
2. Click **Export** button
3. Choose format: HTML, JSON, CSV, or PDF
4. Select save location

### Using PowerShell

#### Basic Commands

```powershell
# Run a complete security audit
Invoke-WinSecAudit

# Run a quick scan (faster, fewer checks)
Invoke-WinSecAudit -Quick

# Scan specific categories only
Invoke-WinSecAudit -Categories @('Firewall', 'Registry', 'Users')

# Export results to JSON
Invoke-WinSecAudit -Format JSON -OutputPath C:\Reports

# Export results to HTML report
Invoke-WinSecAudit -Format HTML -OutputPath C:\Reports

# Export results to CSV
Invoke-WinSecAudit -Format CSV -OutputPath C:\Reports
```

#### Working with Baselines

```powershell
# Create a security baseline from current configuration
Get-SecurityBaseline -OutputPath C:\Baselines

# Run audit comparing against a baseline
Invoke-WinSecAudit -Baseline C:\Baselines\Baseline_SERVER01.json
```

#### Running Individual Checks

```powershell
# Test Active Directory security
Test-ADSecurityConfig

# Test local security policies
Test-LocalSecurityPolicy

# Test firewall configuration
Test-FirewallConfig

# Test registry hardening settings
Test-RegistrySecurity

# Test service security
Test-ServiceSecurity

# Test user account security
Test-UserAccountSecurity

# Test network security
Test-NetworkSecurity

# Test audit policy configuration
Test-AuditPolicy

# Get suspicious processes
Get-SuspiciousProcesses

# Audit scheduled tasks
Get-ScheduledTaskAudit
```

#### Automation Examples

```powershell
# Scheduled daily audit with email report
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument @"
    Import-Module WinSecAudit
    Invoke-WinSecAudit -Format HTML -OutputPath C:\Reports
    Send-MailMessage -To admin@company.com -Subject 'Daily Security Audit' -Attachments (Get-ChildItem C:\Reports\*.html | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
"@
Register-ScheduledTask -TaskName "WinSecAudit-Daily" -Trigger $trigger -Action $action -RunLevel Highest
```

```powershell
# Integration with monitoring (JSON to SIEM)
$results = Invoke-WinSecAudit -Format JSON
$criticalFindings = $results | Where-Object { $_.Severity -eq 'Critical' }
if ($criticalFindings) {
    # Send to SIEM or alerting system
    Invoke-RestMethod -Uri "https://siem.company.com/api/alerts" -Method Post -Body ($criticalFindings | ConvertTo-Json)
}
```

---

## Security Categories

### Active Directory
- Unconstrained Kerberos delegation
- Privileged group membership (Domain Admins, Enterprise Admins)
- Stale computer and user accounts
- LDAP signing and channel binding
- AdminSDHolder permissions

### Local Security Policy
- Minimum password length (14+ characters recommended)
- Password complexity requirements
- Account lockout threshold and duration
- User rights assignments
- Security options hardening

### Windows Firewall
- Profile status (Domain, Private, Public)
- Default inbound/outbound actions
- High-risk port exposure (RDP, SMB, WinRM)
- Firewall logging configuration

### Windows Services
- Unquoted service paths (privilege escalation)
- Services running as SYSTEM unnecessarily
- Dangerous services (Telnet, SNMP, RemoteRegistry)
- Service binary permissions

### Registry Security
- SMB server and client signing
- LLMNR and NetBIOS disabled
- WDigest credential caching
- LSA protection (RunAsPPL)
- UAC configuration
- Cached logons count

### User Accounts
- Local administrator enumeration
- Users with non-expiring passwords
- Inactive user accounts
- Guest account status
- Password last set dates

### Network Security
- Open listening ports
- Network shares and permissions
- IPv6 configuration
- WPAD (Web Proxy Auto-Discovery)
- DNS client settings

### Audit Policy
- Advanced audit policy configuration
- PowerShell script block logging
- Module logging
- Command line process auditing
- Security event log settings

### Running Processes
- Multiple LSASS instances
- Processes from unusual locations
- PowerShell with encoded commands
- Suspicious command line arguments

### Scheduled Tasks
- Tasks running as SYSTEM
- Tasks with encoded PowerShell
- Tasks in non-standard locations
- Persistence indicators

---

## Project Structure

```
WinSecAudit/
├── WinSecAudit.App/           # WinUI 3 Desktop Application
│   ├── Assets/                # Application icons and images
│   ├── Controls/              # Custom UI controls
│   ├── Helpers/               # Utility classes
│   ├── Models/                # Data models
│   │   ├── AuditResult.cs     # Audit result container
│   │   ├── Baseline.cs        # Security baseline model
│   │   ├── Finding.cs         # Individual finding model
│   │   └── SecurityCategory.cs # Category definitions
│   ├── Services/              # Business logic
│   │   ├── Scanners/          # Security scanner implementations
│   │   │   ├── ActiveDirectoryScanner.cs
│   │   │   ├── AuditPolicyScanner.cs
│   │   │   ├── FirewallScanner.cs
│   │   │   ├── LocalPolicyScanner.cs
│   │   │   ├── NetworkScanner.cs
│   │   │   ├── ProcessScanner.cs
│   │   │   ├── RegistryScanner.cs
│   │   │   ├── ScheduledTaskScanner.cs
│   │   │   ├── ServiceScanner.cs
│   │   │   └── UserAccountScanner.cs
│   │   ├── IAuditService.cs   # Audit service interface
│   │   └── ISecurityScanner.cs # Scanner interface
│   ├── Styles/                # XAML styles and themes
│   ├── ViewModels/            # MVVM ViewModels
│   └── Views/Pages/           # XAML pages
│       ├── DashboardPage.xaml
│       ├── QuickScanPage.xaml
│       ├── FullAuditPage.xaml
│       ├── SettingsPage.xaml
│       └── [Category]Page.xaml
├── modules/                   # PowerShell modules
│   ├── Invoke-WinSecAudit.ps1
│   ├── Test-ADSecurityConfig.ps1
│   ├── Test-LocalSecurityPolicy.ps1
│   ├── Test-FirewallConfig.ps1
│   ├── Test-ServiceSecurity.ps1
│   ├── Test-RegistrySecurity.ps1
│   ├── Test-UserAccountSecurity.ps1
│   ├── Test-NetworkSecurity.ps1
│   ├── Test-AuditPolicy.ps1
│   ├── Get-SuspiciousProcesses.ps1
│   ├── Get-ScheduledTaskAudit.ps1
│   ├── Export-AuditReport.ps1
│   └── Get-SecurityBaseline.ps1
├── remediation/               # Remediation scripts
│   ├── Disable-LegacyProtocols.ps1
│   └── Harden-SMB.ps1
├── examples/                  # Usage examples
│   ├── Quick-Audit.ps1
│   └── Scheduled-Audit.ps1
├── config/                    # Configuration files
├── tests/                     # Test files
├── docs/                      # Documentation
└── WinSecAudit.psm1          # PowerShell module manifest
```

---

## Requirements

### Desktop Application
| Requirement | Minimum |
|------------|---------|
| Operating System | Windows 10 1809+ / Windows 11 |
| .NET Runtime | 9.0 |
| Windows App SDK | 1.4+ |
| RAM | 4 GB |
| Privileges | Administrator |

### PowerShell Module
| Requirement | Minimum |
|------------|---------|
| Operating System | Windows Server 2016+ / Windows 10+ |
| PowerShell | 5.1 |
| Privileges | Administrator |
| AD Module | Required for AD checks (optional) |

---

## Compliance Frameworks

WinSecAudit checks are mapped to industry security frameworks:

### CIS Benchmarks
- Microsoft Windows 10 Enterprise
- Microsoft Windows 11 Enterprise
- Microsoft Windows Server 2016/2019/2022

### DISA STIGs
- Windows 10 STIG
- Windows 11 STIG
- Windows Server 2016/2019/2022 STIG

### MITRE ATT&CK
| Technique | Description | Detection |
|-----------|-------------|-----------|
| T1053.005 | Scheduled Task/Job | Suspicious task detection |
| T1055 | Process Injection | Multiple LSASS detection |
| T1036 | Masquerading | System process validation |
| T1059.001 | PowerShell | Encoded command detection |
| T1557.001 | LLMNR/NBT-NS | Protocol configuration |
| T1078 | Valid Accounts | Stale account detection |
| T1110 | Brute Force | Lockout policy validation |

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Ways to Contribute
- Report bugs and security issues
- Suggest new security checks
- Improve documentation
- Add support for additional frameworks
- Create integrations with other tools

### Development Setup
```powershell
# Clone the repository
git clone https://github.com/DonkeyXBT/WinSecAudit.git
cd WinSecAudit

# Install .NET SDK 9.0
winget install Microsoft.DotNet.SDK.9

# Restore dependencies
dotnet restore WinSecAudit.App/WinSecAudit.App.csproj

# Build
dotnet build WinSecAudit.App/WinSecAudit.App.csproj

# Run tests
Invoke-Pester ./tests/
```

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is provided for legitimate security assessment purposes only. Users are responsible for ensuring they have proper authorization before running security audits. The authors are not responsible for any misuse or damage caused by this tool.

---

## Acknowledgments

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) - Security configuration guidance
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat intelligence framework
- [DISA STIGs](https://public.cyber.mil/stigs/) - Security technical implementation guides
- [Harden-Windows-Security](https://github.com/HotCakeX/Harden-Windows-Security) - Inspiration for WinUI design
- Microsoft Security Documentation
