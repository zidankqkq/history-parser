using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Export;

public static class JsonExporter
{
    static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static void Write(ScanResult result, string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(result, Options), Encoding.UTF8);

    public static void Write(Bypass.BypassReport report, string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(report, Options), Encoding.UTF8);

    public static Bypass.BypassReport ReadBypass(string path) =>
        JsonSerializer.Deserialize<Bypass.BypassReport>(File.ReadAllText(path), Options)
        ?? throw new InvalidDataException("The file does not contain a History Parser report.");

    /// <summary>Opens a report saved on another machine, so staff can review it in the GUI.</summary>
    public static ScanResult Read(string path) =>
        JsonSerializer.Deserialize<ScanResult>(File.ReadAllText(path), Options)
        ?? throw new InvalidDataException("The file does not contain an History Parser report.");
}

/// <summary>Single self-contained HTML file (inline CSS/JS, no external requests) for sharing with staff.</summary>
public static class HtmlExporter
{
    public static void Write(ScanResult r, string path, bool includeWindowsFiles = false) =>
        File.WriteAllText(path, Render(r, includeWindowsFiles), Encoding.UTF8);

    /// <summary>The whole report as one HTML page.</summary>
    public static string Render(ScanResult r, bool includeWindowsFiles = false)
    {
        var sb = new StringBuilder(1 << 20);
        string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        string T(DateTime? t) => t is { } v ? v.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "";

        sb.Append("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>History Parser report</title><style>
:root{--bg:#0f1115;--card:#161a21;--line:#262c36;--text:#e6e8eb;--sub:#9aa3af;--high:#ff5d5d;--med:#ffb547;--low:#4da3ff;--ok:#3dd68c;--acc:#8b7bff}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
main{max-width:1400px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px;color:var(--acc)}
.sub{color:var(--sub)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.big{font-size:26px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{cursor:pointer;color:var(--sub);font-weight:600;position:sticky;top:0;background:#1c212a}
.High{color:var(--high)}.Medium{color:var(--med)}.Low{color:var(--low)}.Info{color:var(--sub)}.Ok{color:var(--ok)}.Warning{color:var(--med)}.Bad{color:var(--high)}.Unknown{color:var(--sub)}
.wrap{overflow-x:auto}input{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 10px;width:280px;max-width:100%}
</style></head><body><main>
""");
        sb.Append($"<h1>History Parser report — {E(r.Machine.ComputerName)}</h1>");
        sb.Append($"<div class=sub>{E(r.Machine.OsVersion)} · user {E(r.Machine.UserName)} · scanned {T(r.StartedUtc)} ({E(r.Machine.TimeZone)}) · " +
                  $"boot {T(r.Machine.BootTimeUtc)} · elevated: {(r.Machine.IsElevated ? "yes" : "NO")} · HistoryParser {E(r.Machine.ToolVersion)}</div>");
        sb.Append("<p class=sub>Findings are leads to investigate, not verdicts. All times are shown in the scanned machine's local time.</p>");

        sb.Append("<div class=grid>");
        foreach (var sev in new[] { Severity.High, Severity.Medium, Severity.Low })
            sb.Append($"<div class=card><div class=sub>{sev} findings</div><div class='big {sev}'>{r.Findings.Count(f => f.Severity == sev)}</div></div>");
        sb.Append($"<div class=card><div class=sub>Files</div><div class=big>{r.Files.Count(f => !f.IsWindowsFile)}</div></div>");
        sb.Append($"<div class=card><div class=sub>Deleted / missing</div><div class=big>{r.Files.Count(f => !f.IsWindowsFile && f.Status is FileStatus.Deleted or FileStatus.InRecycleBin or FileStatus.Renamed or FileStatus.Missing)}</div></div>");
        sb.Append($"<div class=card><div class=sub>Clock changes</div><div class=big>{r.ClockChanges.Count}</div></div></div>");

        sb.Append("<h2>Integrity checks</h2><div class=wrap><table><tr><th>Area</th><th>Check</th><th>State</th><th>Detail</th></tr>");
        foreach (var c in r.Checks)
            sb.Append($"<tr><td>{E(c.Area)}</td><td>{E(c.Name)}</td><td class={c.State}>{c.State}</td><td>{E(c.Detail)}</td></tr>");
        sb.Append("</table></div>");

        sb.Append("<h2>Findings</h2><div class=wrap><table class=sortable><tr><th>Severity</th><th>Category</th><th>Title</th><th>Time</th><th>Detail</th><th>Path</th></tr>");
        foreach (var f in r.Findings)
            sb.Append($"<tr><td class={f.Severity}>{f.Severity}</td><td>{Display.Category(f.Category)}</td><td>{E(f.Title)}</td><td>{T(f.TimeUtc)}</td><td>{E(f.Detail)}</td><td>{E(f.Path)}</td></tr>");
        sb.Append("</table></div>");

        sb.Append("<h2>Files</h2><input placeholder='Filter files…' oninput=\"filt(this,'files')\"><div class=wrap><table id=files class=sortable><tr><th>Flag</th><th>Name</th><th>Type</th><th>Last run</th><th>Runs</th><th>Sources</th><th>Status</th><th>Signature</th><th>SHA-256</th><th>Path</th></tr>");
        foreach (var f in r.Files.Where(f => includeWindowsFiles || !f.IsWindowsFile))
            sb.Append($"<tr><td class={f.MaxSeverity}>{f.MaxSeverity}</td><td>{E(f.Name)}</td><td>{Display.Type(f.Type)}</td><td>{T(f.LastExecutionUtc)}</td><td>{f.RunCount}</td>" +
                      $"<td>{E(string.Join(", ", f.Sources.Select(Display.Source)))}</td><td>{Display.Status(f.Status)}<div class=sub>{E(f.StatusDetail)}</div></td><td>{Display.Signature(f.Signature)}<div class=sub>{E(f.Signer)}</div></td>" +
                      $"<td class=sub>{E(f.Sha256)}</td><td>{E(f.Path)}</td></tr>");
        sb.Append("</table></div>");

        if (r.Commands.Count > 0)
        {
            sb.Append("<h2>Command history</h2><input placeholder='Filter commands…' oninput=\"filt(this,'cmds')\"><div class=wrap><table id=cmds class=sortable><tr><th>Flag</th><th>Time</th><th>Source</th><th>User</th><th>Command</th></tr>");
            foreach (var c in r.Commands)
                sb.Append($"<tr><td class=Medium>{E(c.Suspicion)}</td><td>{T(c.TimeUtc)}</td><td>{E(c.Source)}</td><td>{E(c.User)}</td>" +
                          $"<td style=\"font-family:Consolas,monospace\">{E(c.Command)}</td></tr>");
            sb.Append("</table></div>");
        }

        if (r.Folders.Count > 0)
        {
            sb.Append("<h2>Folders opened (ShellBags)</h2><input placeholder='Filter folders…' oninput=\"filt(this,'folders')\"><div class=wrap><table id=folders class=sortable>" +
                      "<tr><th>Last activity</th><th>Opened</th><th>State</th><th>What</th><th>User</th><th>Folder</th></tr>");
            foreach (var f in r.Folders)
                sb.Append($"<tr><td>{T(f.LastActivityUtc)}</td><td>{T(f.OpenedUtc)}</td><td class={(f.Exists == false ? "Medium" : "sub")}>{f.State}</td>" +
                          $"<td>{E(f.What)}</td><td>{E(f.User)}</td><td>{E(f.Path)}</td></tr>");
            sb.Append("</table></div>");
        }

        if (r.ClockChanges.Count > 0)
        {
            sb.Append("<h2>Clock changes</h2><div class=wrap><table><tr><th>Source</th><th>From</th><th>To</th><th>Detail</th></tr>");
            foreach (var c in r.ClockChanges)
                sb.Append($"<tr><td>{E(c.Source)}</td><td>{T(c.OldTimeUtc)}</td><td>{T(c.NewTimeUtc)}</td><td>{E(c.Detail)}</td></tr>");
            sb.Append("</table></div>");
        }

        sb.Append("<h2>Sources</h2><div class=wrap><table><tr><th>Source</th><th>Result</th><th>Items</th><th>Time</th></tr>");
        foreach (var s in r.Sources)
            sb.Append($"<tr><td>{E(s.Name)}</td><td class={(s.Success ? "Ok" : "Bad")}>{E(s.Message)}</td><td>{s.Items}</td><td>{s.Duration.TotalSeconds:0.0}s</td></tr>");
        sb.Append("</table></div>");

        sb.Append("""
<script>
function filt(i,id){const q=i.value.toLowerCase();for(const tr of document.getElementById(id).rows){if(tr.rowIndex==0)continue;tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none'}}
for(const t of document.querySelectorAll('table.sortable')){t.rows[0].querySelectorAll('th').forEach((th,i)=>th.onclick=()=>{const rows=[...t.rows].slice(1);const asc=th.dataset.asc=th.dataset.asc!=='1'?'1':'0';rows.sort((a,b)=>a.cells[i].textContent.localeCompare(b.cells[i].textContent,undefined,{numeric:true})*(asc==='1'?1:-1));rows.forEach(r=>t.tBodies[0].appendChild(r))})}
</script></main></body></html>
""");
        return sb.ToString();
    }
}
