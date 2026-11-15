using System.Text;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Export;

/// <summary>
/// Export file names and CSV text, shared by every History Parser page so the main window and the
/// tampering page can never drift apart on what goes into a saved file.
/// </summary>
public static class ReportFiles
{
    /// <summary>
    /// The suggested file name for an export of <paramref name="scan"/>. With private details hidden the
    /// computer name stays out of the file name too.
    /// </summary>
    public static string DefaultName(ScanResult scan, bool privateHidden, string suffix, string ext) => privateHidden
        ? $"HistoryParser-{scan.StartedUtc.ToLocalTime():yyyyMMdd-HHmm}{suffix}-private-hidden.{ext}"
        : $"HistoryParser-{scan.Machine.ComputerName}-{scan.StartedUtc.ToLocalTime():yyyyMMdd-HHmm}{suffix}.{ext}";

    /// <summary>A whole CSV file: the header line, then one line per row.</summary>
    public static string Csv(IEnumerable<string?> header, IEnumerable<IEnumerable<string?>> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", header.Select(CsvCell)));
        foreach (var row in rows) sb.AppendLine(string.Join(",", row.Select(CsvCell)));
        return sb.ToString();
    }

    /// <summary>One CSV cell, quoted when it holds a comma, quote or line break.</summary>
    public static string CsvCell(string? s)
    {
        s ??= "";
        // Leading = + - @ would be run as a formula by Excel; prefix a quote so the cell stays text.
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@') s = "'" + s;
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }
}
