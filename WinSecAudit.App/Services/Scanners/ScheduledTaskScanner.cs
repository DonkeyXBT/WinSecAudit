using System.Text.RegularExpressions;
using WinSecAudit.Models;
using Microsoft.Win32.TaskScheduler;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans scheduled tasks for security issues.
/// </summary>
public class ScheduledTaskScanner : SecurityScannerBase
{
    public override string CategoryId => "Tasks";
    public override string Name => "Scheduled Tasks";

    private static readonly string[] SuspiciousPatterns = new[]
    {
        @"powershell.*-enc",
        @"powershell.*downloadstring",
        @"powershell.*webclient",
        @"powershell.*iex",
        @"cmd.*/c.*http",
        @"certutil.*-urlcache",
        @"bitsadmin.*transfer",
        @"mshta.*http",
        @"regsvr32.*/s.*/n.*/u",
        @"rundll32.*javascript"
    };

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            try
            {
                using var taskService = new TaskService();
                var tasks = GetAllTasks(taskService.RootFolder);
                var systemTaskCount = 0;

                foreach (var task in tasks)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (task.State == TaskState.Disabled)
                        continue;

                    var userId = task.Definition.Principal.UserId ?? "";
                    var isSystem = userId.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                                   userId == "S-1-5-18";

                    if (isSystem)
                        systemTaskCount++;

                    foreach (var action in task.Definition.Actions)
                    {
                        if (action is ExecAction execAction)
                        {
                            var actionString = $"{execAction.Path} {execAction.Arguments}";

                            // Check for suspicious patterns
                            foreach (var pattern in SuspiciousPatterns)
                            {
                                if (Regex.IsMatch(actionString, pattern, RegexOptions.IgnoreCase))
                                {
                                    findings.Add(CreateFailedFinding(
                                        "Suspicious Task Action",
                                        Severity.Critical,
                                        $"Task '{task.Name}' has suspicious action pattern",
                                        $"Pattern matched: {pattern}",
                                        "Investigate task immediately - possible malware persistence",
                                        "MITRE ATT&CK T1053.005"));
                                    break;
                                }
                            }

                            // Check SYSTEM tasks from non-standard locations
                            if (isSystem && !string.IsNullOrEmpty(execAction.Path))
                            {
                                var path = execAction.Path;
                                if (!path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) &&
                                    !path.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase) &&
                                    !path.StartsWith(@"""C:\Windows\", StringComparison.OrdinalIgnoreCase) &&
                                    !path.StartsWith(@"""C:\Program Files", StringComparison.OrdinalIgnoreCase))
                                {
                                    findings.Add(new Finding
                                    {
                                        Check = "SYSTEM Task Non-Standard Location",
                                        Severity = Severity.High,
                                        Status = FindingStatus.Warning,
                                        Category = CategoryId,
                                        Description = $"Task '{task.Name}' runs as SYSTEM from non-standard location",
                                        Details = $"Path: {path}",
                                        Remediation = "Review task legitimacy and source",
                                        MitreId = "T1053.005"
                                    });
                                }
                            }

                            // Check tasks running from temp directories
                            if (execAction.Path?.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) == true ||
                                execAction.Path?.Contains(@"\tmp\", StringComparison.OrdinalIgnoreCase) == true)
                            {
                                findings.Add(CreateFailedFinding(
                                    "Task Running from Temp",
                                    Severity.High,
                                    $"Task '{task.Name}' runs from temporary directory",
                                    $"Execute: {execAction.Path}",
                                    "Tasks should not run from temporary directories",
                                    "MITRE ATT&CK T1053.005"));
                            }
                        }
                    }
                }

                // Report on SYSTEM task count
                if (systemTaskCount > 50)
                {
                    findings.Add(new Finding
                    {
                        Check = "High Number of SYSTEM Tasks",
                        Severity = Severity.Info,
                        Status = FindingStatus.Passed,
                        Category = CategoryId,
                        Description = $"{systemTaskCount} scheduled tasks run as SYSTEM",
                        Remediation = "Review and remove unnecessary SYSTEM tasks"
                    });
                }

                if (findings.Count == 0)
                {
                    findings.Add(CreatePassedFinding(
                        "Scheduled Task Analysis",
                        "No suspicious scheduled tasks detected"));
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Check = "Scheduled Task Scan",
                    Severity = Severity.Info,
                    Status = FindingStatus.Error,
                    Description = "Failed to scan scheduled tasks",
                    Details = ex.Message
                });
            }
        }, cancellationToken);

        return findings;
    }

    private IEnumerable<Task> GetAllTasks(TaskFolder folder)
    {
        foreach (var task in folder.Tasks)
        {
            yield return task;
        }

        foreach (var subFolder in folder.SubFolders)
        {
            foreach (var task in GetAllTasks(subFolder))
            {
                yield return task;
            }
        }
    }
}
