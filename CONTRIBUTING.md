# Contributing to WinSecAudit

Thank you for your interest in contributing to WinSecAudit! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](../../issues)
2. If not, create a new issue with:
   - Clear title describing the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Windows version and PowerShell version
   - Any error messages or screenshots

### Suggesting New Security Checks

1. Open an issue with the `enhancement` label
2. Include:
   - Description of the security check
   - Why it's important (CVE, CIS reference, etc.)
   - How to detect the issue
   - Remediation steps

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Test your changes on Windows Server
5. Commit with clear messages: `git commit -m "Add check for XYZ vulnerability"`
6. Push to your fork: `git push origin feature/your-feature-name`
7. Open a Pull Request

## Development Guidelines

### Code Style

- Use 4 spaces for indentation
- Follow PowerShell best practices
- Include comment-based help for functions
- Use approved PowerShell verbs

### Security Check Format

All security checks should return findings in this format:

```powershell
[PSCustomObject]@{
    Check = 'Check Name'           # Short name of the check
    Severity = 'High'              # Critical, High, Medium, Low, Info, Passed
    Status = 'Failed'              # Failed, Warning, Passed, Info
    Description = 'What was found' # Clear description
    Details = 'Technical details'  # Specific findings
    Remediation = 'How to fix'     # Clear remediation steps
    Reference = 'CIS 1.2.3'        # Standard reference
}
```

### Testing

- Test on Windows Server 2016, 2019, and 2022 if possible
- Test with and without Active Directory
- Test with `-Quick` parameter
- Verify HTML, JSON, and CSV output

## Questions?

Open an issue with the `question` label or start a discussion.

Thank you for helping make Windows servers more secure!
