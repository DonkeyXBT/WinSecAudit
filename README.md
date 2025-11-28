# WinSecAudit

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%2B-blue.svg)](https://www.microsoft.com/en-us/windows-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS-Compliant-orange.svg)](https://www.cisecurity.org/)

A comprehensive PowerShell-based security auditing framework for Windows Server environments. WinSecAudit helps security professionals, system administrators, and compliance teams identify security misconfigurations, vulnerabilities, and deviations from security best practices.

## Features

- **Active Directory Security** - Audit Kerberos delegation, privileged groups, stale accounts, LDAP signing
- **Local Security Policy** - Password policies, account lockout, user rights assignments
- **Firewall Configuration** - Profile status, high-risk ports, logging configuration
- **Service Security** - Unquoted paths, dangerous services, privilege escalation vectors
- **Registry Hardening** - SMB signing, LLMNR, WDigest, UAC, LSA protection
- **User Account Audit** - Password settings, inactive accounts, administrator enumeration
- **Network Security** - Open ports, shares, IPv6, DNS configuration
- **Audit Policy** - Windows audit settings, PowerShell logging, command line auditing
- **Process Analysis** - Suspicious processes, encoded commands, unusual locations
- **Scheduled Tasks** - Persistence mechanisms, suspicious actions, SYSTEM tasks

## Quick Start

### Installation

```powershell
# Clone the repository
git clone https://github.com/YOUR_USERNAME/WinSecAudit.git

# Import the module
Import-Module .\WinSecAudit\WinSecAudit.psm1

# Or install from PowerShell Gallery (coming soon)
# Install-Module -Name WinSecAudit
```

### Basic Usage

```powershell
# Run a full security audit
Invoke-WinSecAudit

# Run specific categories only
Invoke-WinSecAudit -Categories @('AD', 'Firewall', 'Users')

# Quick scan (skip time-consuming checks)
Invoke-WinSecAudit -Quick

# Export to different formats
Invoke-WinSecAudit -Format JSON -OutputPath C:\Reports
Invoke-WinSecAudit -Format CSV -OutputPath C:\Reports
```

### Generate Security Baseline

```powershell
# Create a baseline configuration
Get-SecurityBaseline -OutputPath C:\Baselines

# Run audit and compare against baseline
Invoke-WinSecAudit -Baseline C:\Baselines\Baseline_SERVER01_20240101.json
```

## Requirements

- Windows Server 2016, 2019, 2022, or Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges
- Active Directory module (for AD checks - optional)

## Output Formats

### HTML Report
Interactive HTML report with:
- Executive summary with finding counts
- Collapsible category sections
- Color-coded severity indicators
- Detailed remediation guidance

### JSON Export
Machine-readable format for:
- Integration with SIEM systems
- Automated compliance checking
- Custom dashboard creation

### CSV Export
Spreadsheet-compatible format for:
- Manual review and filtering
- Compliance documentation
- Trend analysis

## Security Checks Reference

### CIS Benchmark Alignment

WinSecAudit checks are aligned with the CIS Microsoft Windows Server Benchmark:

| Category | Checks | CIS Reference |
|----------|--------|---------------|
| Password Policy | Minimum length, complexity, history | 1.1.x |
| Account Lockout | Threshold, duration, reset | 1.2.x |
| User Rights | Dangerous assignments | 2.2.x |
| Security Options | Various hardening settings | 2.3.x |
| Audit Policy | Logon, account management, etc. | 17.x |
| Advanced Audit | PowerShell, command line | 18.9.x |

### MITRE ATT&CK Coverage

| Technique ID | Description | Checks |
|--------------|-------------|--------|
| T1053.005 | Scheduled Task/Job | Suspicious task detection |
| T1055 | Process Injection | Multiple lsass instances |
| T1036 | Masquerading | System process locations |
| T1059.001 | PowerShell | Encoded commands, bypass flags |
| T1557.001 | LLMNR/NBT-NS | Protocol configuration |

## Extending WinSecAudit

### Adding Custom Checks

Create a new `.ps1` file in the `modules` directory:

```powershell
function Test-CustomCheck {
    [CmdletBinding()]
    param([switch]$Quick)

    $findings = @()

    # Your custom check logic here
    $findings += [PSCustomObject]@{
        Check = 'Custom Check Name'
        Severity = 'High'  # Critical, High, Medium, Low, Info
        Status = 'Failed'  # Failed, Warning, Passed, Info
        Description = 'What was found'
        Details = 'Additional context'
        Remediation = 'How to fix'
        Reference = 'CIS Benchmark x.x.x'
    }

    return @{
        Status = 'Completed'
        Findings = $findings
    }
}
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### Ways to Contribute

- Report bugs and security issues
- Suggest new security checks
- Improve documentation
- Add support for additional Windows versions
- Create integrations with other tools

## Roadmap

- [ ] PowerShell Gallery publication
- [ ] Integration with Microsoft Defender for Endpoint
- [ ] Azure AD security checks
- [ ] Scheduled scanning with email reports
- [ ] Web-based dashboard
- [ ] Remediation automation scripts
- [ ] Multi-server scanning support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for legitimate security assessment purposes only. Users are responsible for ensuring they have proper authorization before running security audits. The authors are not responsible for any misuse or damage caused by this tool.

## Acknowledgments

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) for security configuration guidance
- [MITRE ATT&CK](https://attack.mitre.org/) for threat intelligence framework
- Microsoft Security Documentation
- The security community for continuous feedback

---

Made with security in mind
