using System.Collections.Generic;
using WinSecAudit.Models;
namespace WinSecAudit.Services;
public class BaselineService
{
    private readonly Dictionary<string, Baseline> _baselines = new()
    {
        ["CIS"] = new Baseline { Name = "CIS Windows Server 2022 Benchmark", Version = "1.0.0", Description = "Center for Internet Security hardening guidelines", CheckCount = 275 },
        ["STIG"] = new Baseline { Name = "DISA Windows Server 2022 STIG", Version = "V1R1", Description = "Defense Information Systems Agency security requirements", CheckCount = 312 },
        ["MS"] = new Baseline { Name = "Microsoft Security Baseline", Version = "2022", Description = "Microsoft recommended security configuration", CheckCount = 198 }
    };
    public IEnumerable<Baseline> GetAvailableBaselines() => _baselines.Values;
    public Baseline? GetBaseline(string id) => _baselines.TryGetValue(id, out var b) ? b : null;
    public BaselineComparisonResult Compare(AuditResult audit, string baselineId)
    {
        var baseline = GetBaseline(baselineId);
        if (baseline == null) return new BaselineComparisonResult { CompliancePercentage = 0 };
        var passed = audit.Findings.Count(f => f.Severity == Severity.Info);
        return new BaselineComparisonResult { BaselineName = baseline.Name, TotalChecks = baseline.CheckCount, PassedChecks = passed, CompliancePercentage = (double)passed / baseline.CheckCount * 100 };
    }
}
public class BaselineComparisonResult { public string BaselineName { get; set; } = ""; public int TotalChecks { get; set; } public int PassedChecks { get; set; } public double CompliancePercentage { get; set; } }
