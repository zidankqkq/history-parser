using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HistoryParser.Core.Models;

namespace RatChecker.Core;

/// <summary>Finding the files to check, and saving the results.</summary>
public static class RatFiles
{
    const int MaxFilesPerFolder = 5000;

    /// <summary>
    /// Every mods folder on this PC that a launcher uses: each launcher's own folder is searched for any folder named "mods"
    /// (instances, profiles and per-version folders each keep one), plus custom game folders set in the official launcher
    /// and the instance folder Prism / PolyMC / MultiMC were pointed at.
    /// </summary>
    public static List<string> ModFolders()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var found = new List<string>();
        void Add(string dir) { if (Directory.Exists(dir) && !found.Contains(dir, StringComparer.OrdinalIgnoreCase)) found.Add(dir); }
        void Search(string root)
        {
            if (!Directory.Exists(root)) return;
            Add(Path.Combine(root, "mods"));
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(root, "mods", new EnumerationOptions
                         { RecurseSubdirectories = true, MaxRecursionDepth = 6, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
                    Add(dir);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }

        var roots = new List<string>
        {
            Path.Combine(appData, ".minecraft"), Path.Combine(appData, "ModrinthApp"), Path.Combine(appData, "com.modrinth.theseus"),
            Path.Combine(appData, "PrismLauncher"), Path.Combine(appData, "PolyMC"), Path.Combine(appData, "MultiMC"),
            Path.Combine(appData, "gdlauncher_next"), Path.Combine(appData, "gdlauncher_carbon"), Path.Combine(appData, "ATLauncher"),
            Path.Combine(appData, ".tlauncher"), Path.Combine(appData, ".technic"), Path.Combine(appData, ".feather"),
            Path.Combine(user, "curseforge", "minecraft", "Instances"), Path.Combine(user, ".lunarclient"), Path.Combine(user, "ATLauncher"),
        };
        roots.AddRange(LauncherGameDirs(Path.Combine(appData, ".minecraft", "launcher_profiles.json")));
        foreach (var (launcher, cfg) in new[] { ("PrismLauncher", "prismlauncher.cfg"), ("PolyMC", "polymc.cfg"), ("MultiMC", "multimc.cfg") })
            if (InstanceDir(Path.Combine(appData, launcher), cfg) is { } dir) roots.Add(dir);
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase)) Search(root);
        return found;
    }

    /// <summary>Custom game folders ("gameDir") of the official launcher's installations.</summary>
    internal static List<string> LauncherGameDirs(string profilesJson)
    {
        var dirs = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(profilesJson));
            if (doc.RootElement.TryGetProperty("profiles", out var profiles) && profiles.ValueKind == JsonValueKind.Object)
                foreach (var p in profiles.EnumerateObject())
                    if (p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty("gameDir", out var dir) &&
                        dir.ValueKind == JsonValueKind.String && dir.GetString() is { Length: > 0 } d)
                        dirs.Add(Environment.ExpandEnvironmentVariables(d));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { }
        return dirs;
    }

    /// <summary>Where a MultiMC-style launcher keeps its instances ("InstanceDir=" in its config, relative to the launcher's folder).</summary>
    internal static string? InstanceDir(string launcherDir, string cfgName)
    {
        try
        {
            var line = File.ReadLines(Path.Combine(launcherDir, cfgName)).FirstOrDefault(l => l.StartsWith("InstanceDir=", StringComparison.OrdinalIgnoreCase));
            var value = line?["InstanceDir=".Length..].Trim();
            return string.IsNullOrEmpty(value) ? null : Path.GetFullPath(Path.Combine(launcherDir, value));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
    }

    static readonly System.Text.RegularExpressions.Regex ListedPath = new(
        @"(?:[A-Za-z]:\\|\\Device\\HarddiskVolume\d+\\)[^""|<>*?\r\n\t]+",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// The file paths in a list someone exported: one per line (paths.txt, Everything's .txt export), Everything's .efu / .csv
    /// export (the Filename column comes first, quoted), or any other tool's output with a path somewhere on each line.
    /// Device paths (\Device\HarddiskVolume3\...) are turned into drive letters by <paramref name="normalize"/>.
    /// </summary>
    public static List<string> ReadPathList(IEnumerable<string> lines, Func<string, string>? normalize = null)
    {
        var paths = new List<string>();
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            string? path = null;
            if (line.StartsWith('"') && line.IndexOf('"', 1) is var end and > 1) path = line[1..end];
            if (path == null || ListedPath.Match(path) is not { Success: true, Index: 0 })
                path = ListedPath.Match(line) is { Success: true } m ? m.Value : null;
            if (path == null) continue;
            path = path.Trim().TrimEnd(',', ';', ' ');
            if (normalize != null) path = normalize(path);
            // Unquoted CSV ("C:\a.exe,1234,...") runs into the next field: cut it there when only the shorter path is a file.
            if (!File.Exists(path) && !Directory.Exists(path) && path.IndexOf(',') is var comma and > 3 && File.Exists(path[..comma])) path = path[..comma];
            paths.Add(path);
        }
        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Expands folders into the files worth checking; single files are always kept.</summary>
    public static List<string> Expand(IEnumerable<string> paths, List<string> notes)
    {
        var files = new List<string>();
        foreach (var p in paths)
        {
            if (File.Exists(p)) { files.Add(p); continue; }
            if (!Directory.Exists(p)) continue;
            int n = 0;
            try
            {
                foreach (var f in Directory.EnumerateFiles(p, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 6 }))
                {
                    if (!RatScanner.ScanExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)) continue;
                    if (++n > MaxFilesPerFolder) { notes.Add($"{p}: more than {MaxFilesPerFolder} files; the rest were skipped."); break; }
                    files.Add(f);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { notes.Add($"{p}: {e.Message}"); }
        }
        return files.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    public static void WriteJson(IEnumerable<RatFileReport> reports, string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(reports.Select(r => new
        {
            r.Path, r.Name, r.Kind, r.Size, r.Sha256, r.Signature, r.Signer, r.ModInfo, Verdict = r.Verdict.ToString(), r.VerdictText, CheatVerdict = r.CheatVerdict.ToString(), r.CheatVerdictText, r.Error, r.Notes,
            Signs = r.Signs.OrderByDescending(s => s.Severity).Select(s => new { s.Severity, Category = RatDisplay.Category(s.Category), s.Title, s.Why, s.Evidence, s.Where }),
        }), Json));

    public static void WriteHtml(IReadOnlyList<RatFileReport> reports, string path)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var sb = new StringBuilder();
        sb.Append("<!doctype html><meta charset=utf-8><title>Program Checker report</title><style>")
          .Append("body{font:14px Segoe UI,sans-serif;background:#111318;color:#e6e8ee;margin:24px}h1{font-size:20px}")
          .Append(".f{background:#1a1d24;border-radius:10px;padding:14px 18px;margin:12px 0}.m{color:#9aa1b0;font-size:12px}")
          .Append(".High{color:#ff6b6b}.Medium{color:#f0b54a}.Low{color:#8fb3ff}.Dangerous{color:#ff6b6b}.Suspicious{color:#f0b54a}.Clean{color:#5fd38d}.Cheat{color:#ff6b6b}.Possible{color:#f0b54a}.None{color:#5fd38d}")
          .Append("code{background:#0d0f13;padding:1px 5px;border-radius:4px;word-break:break-all}td{vertical-align:top;padding:4px 8px}</style>")
          .Append($"<h1>Program Checker report</h1><p class=m>{reports.Count} file(s), {DateTime.Now:yyyy-MM-dd HH:mm}. Files were only read, never run. A clean result is not a guarantee — see the limits in the app's Help.</p>");
        foreach (var r in reports.OrderByDescending(r => r.Verdict).ThenByDescending(r => r.CheatVerdict))
        {
            sb.Append($"<div class=f><b>{E(r.Name)}</b> — malware: <span class={r.Verdict}>{E(r.VerdictText)}</span> · cheat: <span class={r.CheatVerdict}>{E(r.CheatVerdictText)}</span>")
              .Append($"<div class=m>{E(r.Path)}<br>{E(r.Kind)}{(r.ModInfo != null ? " · " + E(r.ModInfo) : "")} · {r.Size:N0} bytes · SHA-256 {E(r.Sha256)}</div>");
            if (r.Error != null) sb.Append($"<p class=m>Could not read: {E(r.Error)}</p>");
            if (r.Signs.Count > 0)
            {
                sb.Append("<table>");
                foreach (var s in r.Signs.OrderByDescending(s => s.Severity))
                    sb.Append($"<tr><td class={s.Severity}>{s.Severity}</td><td><b>{E(s.Title)}</b> <span class=m>({E(RatDisplay.Category(s.Category))})</span><br>{E(s.Why)}<br><code>{E(s.Evidence)}</code> <span class=m>in {E(s.Where)}</span></td></tr>");
                sb.Append("</table>");
            }
            sb.Append("</div>");
        }
        File.WriteAllText(path, sb.ToString());
    }
}
