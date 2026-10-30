using System.Text;
using HistoryParser.Core.Bypass;

namespace HistoryParser.Core.Export;

/// <summary>
/// One HTML page for one scan: the execution report, then the tampering and bypass report under it. Both parts are
/// built in memory and joined - no temporary files, which would themselves show up as traces on the PC.
/// </summary>
public static class CombinedExport
{
    public static void WriteHtml(BypassReport r, string path, bool includeWindowsFiles = false) =>
        File.WriteAllText(path, RenderHtml(r, includeWindowsFiles), Encoding.UTF8);

    public static string RenderHtml(BypassReport r, bool includeWindowsFiles = false)
    {
        string history = HtmlExporter.Render(r.History, includeWindowsFiles);
        string tamper = BypassExport.RenderHtml(r);
        const string Open = "<body><main>", Close = "</main></body></html>";
        int bodyAt = tamper.IndexOf(Open, StringComparison.Ordinal), endAt = tamper.LastIndexOf(Close, StringComparison.Ordinal);
        int styleAt = tamper.IndexOf("<style>", StringComparison.Ordinal), styleEnd = tamper.IndexOf("</style>", StringComparison.Ordinal);
        int closeAt = history.LastIndexOf(Close, StringComparison.Ordinal), headStyleEnd = history.IndexOf("</style>", StringComparison.Ordinal);
        if (bodyAt < 0 || endAt < 0 || closeAt < 0 || styleAt < 0 || styleEnd < 0 || headStyleEnd < 0) return history + tamper;
        var sb = new StringBuilder(history.Length + tamper.Length + 256);
        sb.Append(history, 0, headStyleEnd);
        sb.Append(tamper, styleAt + "<style>".Length, styleEnd - styleAt - "<style>".Length); // the tampering part's own styles
        sb.Append(history, headStyleEnd, closeAt - headStyleEnd);
        sb.Append("<hr style=\"border:0;border-top:1px solid #262c36;margin:40px 0\">");
        sb.Append(tamper, bodyAt + Open.Length, endAt - bodyAt - Open.Length);
        sb.Append(Close);
        return sb.ToString();
    }
}
