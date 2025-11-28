using System.Text; using System.Text.Json;
using WinSecAudit.Models;
namespace WinSecAudit.Services;
public class ReportExporter
{
    public string ExportToHtml(AuditResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><title>WinSecAudit Report</title>");
        sb.AppendLine("<style>body{font-family:Segoe UI,sans-serif;margin:40px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#0078d4;color:white}.critical{color:#d13438}.high{color:#ff8c00}.medium{color:#ffc83d}.low{color:#107c10}</style></head><body>");
        sb.AppendLine($"<h1>Security Audit Report</h1><p>Generated: {result.Timestamp}</p>");
        sb.AppendLine($"<p>Critical: {result.CriticalCount} | High: {result.HighCount} | Medium: {result.MediumCount} | Low: {result.LowCount}</p>");
        sb.AppendLine("<table><tr><th>Category</th><th>Check</th><th>Severity</th><th>Description</th></tr>");
        foreach (var f in result.Findings)
            sb.AppendLine($"<tr><td>{f.Category}</td><td>{f.CheckName}</td><td class='{f.Severity.ToString().ToLower()}'>{f.Severity}</td><td>{f.Description}</td></tr>");
        sb.AppendLine("</table></body></html>");
        return sb.ToString();
    }
    public string ExportToJson(AuditResult result) => JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    public string ExportToCsv(AuditResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Category,CheckName,Severity,Description,Remediation");
        foreach (var f in result.Findings) sb.AppendLine($"\"{f.Category}\",\"{f.CheckName}\",\"{f.Severity}\",\"{f.Description}\",\"{f.Remediation}\"");
        return sb.ToString();
    }
}
