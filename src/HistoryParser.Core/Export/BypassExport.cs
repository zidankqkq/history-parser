using System.Net;
using System.Reflection;
using System.Text;
using HistoryParser.Core.Bypass;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Export;

/// <summary>Self-contained HTML report and private-details redaction for the tampering half of the scan.</summary>
public static class BypassExport
{
    public static void WriteHtml(BypassReport r, string path) => File.WriteAllText(path, RenderHtml(r), Encoding.UTF8);

    /// <summary>The tampering report as one HTML page.</summary>
    public static string RenderHtml(BypassReport r)
    {
        var sb = new StringBuilder(1 << 20);
        string E(object? s) => WebUtility.HtmlEncode(s?.ToString() ?? "");
        string T(DateTime? t) => t is { } v ? v.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "";
        var m = r.History.Machine;

        sb.Append("""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tampering report</title><style>
:root{--bg:#0f1115;--card:#161a21;--line:#262c36;--text:#e6e8eb;--sub:#9aa3af;--high:#ff5d5d;--med:#ffb547;--low:#4da3ff;--ok:#3dd68c;--acc:#8b7bff}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
main{max-width:1400px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px;color:var(--acc)}
.sub{color:var(--sub)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.big{font-size:26px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{cursor:pointer;color:var(--sub);background:#1c212a}.High,.Bad,.True{color:var(--high)}.Medium,.Warning{color:var(--med)}.Low{color:var(--low)}.Ok{color:var(--ok)}
.wrap{overflow-x:auto}
</style></head><body><main>
""");
        sb.Append($"<h1 id=\"tampering\">Tampering &amp; bypasses — {E(m.ComputerName)}</h1>");
        sb.Append($"<div class=sub>{E(m.OsVersion)} · user {E(m.UserName)} · scanned {T(r.History.StartedUtc)} ({E(m.TimeZone)}) · boot {T(m.BootTimeUtc)} · " +
                  $"elevated: {(m.IsElevated ? "yes" : "NO")}{(r.PrivateDetailsHidden ? " · private details hidden" : "")}</div>");
        sb.Append("<p class=sub>Findings are leads to investigate, not verdicts. Times are the scanned machine's local time.</p><div class=grid>");
        foreach (var sev in new[] { Severity.High, Severity.Medium, Severity.Low })
            sb.Append($"<div class=card><div class=sub>{sev}</div><div class='big {sev}'>{r.Findings.Count(f => f.Severity == sev)}</div></div>");
        sb.Append($"<div class=card><div class=sub>USB devices</div><div class=big>{r.UsbDevices.Count}</div></div>");
        sb.Append($"<div class=card><div class=sub>Deleted log records</div><div class=big>{r.RecordGaps.Sum(g => g.Missing)}</div></div></div>");

        sb.Append("<h2>Findings</h2><div class=wrap><table class=sortable><tr><th>Severity</th><th>Category</th><th>Title</th><th>Time</th><th>Detail</th></tr>");
        foreach (var f in r.Findings)
            sb.Append($"<tr><td class={f.Severity}>{f.Severity}</td><td>{E(Display.Category(f.Category))}</td><td>{E(f.Title)}</td><td>{T(f.TimeUtc)}</td><td>{E(f.Detail)}</td></tr>");
        sb.Append("</table></div>");

        Table(sb, "Event logs", r.Logs);
        Table(sb, "Deleted event records", r.RecordGaps);
        Table(sb, "Services", r.Services);
        Table(sb, "Service history", r.ServiceEvents);
        Table(sb, "USB devices", r.UsbDevices);
        Table(sb, "USB connections", r.UsbEvents);
        Table(sb, "Flagged program arguments", r.Arguments.Where(a => a.Flagged));
        Table(sb, "Evidence files", r.Artifacts);
        Table(sb, "Microsoft Defender changes", r.Defender.Where(d => d.Suspicious));
        Table(sb, "Flagged drivers", r.Drivers.Where(d => d.Flagged));
        Table(sb, "Boot, hardware and injection routes", r.Routes.Where(x => x.State != CheckState.Ok || x.Area is "Boot" or "Hardware"));
        Table(sb, "Scheduled tasks (flagged or new)", r.Tasks.Where(t => t.Flagged || t.Note.Length > 0));
        Table(sb, "Software installs and removals", r.Software.Where(s => s.Flagged || s.Action == "Uninstalled"));
        Table(sb, "Clock changes", r.History.ClockChanges);
        Table(sb, "Integrity checks", r.History.Checks);

        sb.Append("""
<script>
for(const t of document.querySelectorAll('table.sortable')){t.rows[0].querySelectorAll('th').forEach((th,i)=>th.onclick=()=>{const rows=[...t.rows].slice(1);const asc=th.dataset.asc=th.dataset.asc!=='1'?'1':'0';rows.sort((a,b)=>a.cells[i].textContent.localeCompare(b.cells[i].textContent,undefined,{numeric:true})*(asc==='1'?1:-1));rows.forEach(r=>t.tBodies[0].appendChild(r))})}
</script></main></body></html>
""");
        return sb.ToString();
    }

    /// <summary>Generic table from a list of records: one column per simple public property.</summary>
    static void Table<T>(StringBuilder sb, string title, IEnumerable<T> rows)
    {
        var list = rows.ToList();
        if (list.Count == 0) return;
        var props = typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType.IsPrimitive || p.PropertyType.IsEnum || p.PropertyType == typeof(string) ||
                        Nullable.GetUnderlyingType(p.PropertyType) is { } u && (u.IsPrimitive || u == typeof(DateTime)) ||
                        p.PropertyType == typeof(DateTime) || p.PropertyType == typeof(TimeSpan))
            .ToList();
        sb.Append($"<h2>{WebUtility.HtmlEncode(title)} ({list.Count})</h2><div class=wrap><table class=sortable><tr>");
        foreach (var p in props) sb.Append($"<th>{WebUtility.HtmlEncode(Header(p.Name))}</th>");
        sb.Append("</tr>");
        foreach (var row in list)
        {
            sb.Append("<tr>");
            foreach (var p in props)
            {
                var v = p.GetValue(row);
                string text = v switch
                {
                    DateTime t => t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                    long l when p.Name.EndsWith("Bytes", StringComparison.Ordinal) => $"{l / 1024:N0} KB",
                    _ => v?.ToString() ?? "",
                };
                sb.Append($"<td class=\"{(v is CheckState or bool ? v : "")}\">{WebUtility.HtmlEncode(text)}</td>");
            }
            sb.Append("</tr>");
        }
        sb.Append("</table></div>");
    }

    /// <summary>"LastConnectedUtc" → "Last connected".</summary>
    public static string Header(string name)
    {
        var n = name.EndsWith("Utc", StringComparison.Ordinal) ? name[..^3] : name;
        var sb = new StringBuilder();
        for (int i = 0; i < n.Length; i++)
        {
            if (i > 0 && char.IsUpper(n[i]) && !char.IsUpper(n[i - 1])) sb.Append(' ');
            sb.Append(i == 0 ? n[i] : char.ToLowerInvariant(n[i]));
        }
        return sb.ToString();
    }

    /// <summary>Same rules as <see cref="Redactor"/>, applied to every tampering table.</summary>
    public static BypassReport Redact(BypassReport r)
    {
        var history = Redactor.Redact(r.History);
        var clean = Redactor.CreateCleaner(r.History);
        string C(string s) => clean(s);
        return new BypassReport
        {
            History = history,
            Findings = r.Findings.Select(f => f with { Title = C(f.Title), Detail = C(f.Detail), Path = f.Path == null ? null : C(f.Path) }).ToList(),
            Logs = r.Logs.Select(l => l with { Note = C(l.Note) }).ToList(),
            RecordGaps = r.RecordGaps,
            Services = r.Services.Select(s => s with { Note = C(s.Note) }).ToList(),
            ServiceEvents = r.ServiceEvents,
            UsbDevices = r.UsbDevices,
            UsbEvents = r.UsbEvents,
            Arguments = r.Arguments.Where(a => a.Flagged).Select(a => a with { CommandLine = C(a.CommandLine), Source = C(a.Source) }).ToList(),
            Drivers = r.Drivers.Select(d => d with { Path = C(d.Path) }).ToList(),
            Tasks = r.Tasks.Select(t => t with { Command = C(t.Command), Name = C(t.Name) }).ToList(),
            Software = r.Software,
            Artifacts = r.Artifacts.Select(a => a with { Path = C(a.Path), Detail = C(a.Detail) }).ToList(),
            Defender = r.Defender.Select(d => d with { NewValue = C(d.NewValue), OldValue = C(d.OldValue) }).ToList(),
            Routes = r.Routes.Select(x => x with { Item = C(x.Item), Value = C(x.Value), Detail = C(x.Detail), Path = x.Area == "Hardware" ? "" : C(x.Path) }).ToList(), // hardware paths are device serials
            Sources = r.Sources.Select(s => s with { Message = C(s.Message) }).ToList(),
            PrivateDetailsHidden = true,
        };
    }
}
