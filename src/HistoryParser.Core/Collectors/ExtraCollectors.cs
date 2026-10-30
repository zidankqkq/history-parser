using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Amcache.hve: Windows' inventory of program files it has seen (usually because they ran), with full
/// path, SHA-1 and publisher. Survives Prefetch being cleared. Windows keeps the hive locked, so it is
/// read cluster by cluster from the volume (administrator only) and parsed in memory.
/// </summary>
public sealed class AmcacheCollector : ICollector
{
    public string Name => "Amcache";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"AppCompat\Programs\Amcache.hve");
        if (!File.Exists(path))
        {
            ctx.Check("Amcache", "Amcache.hve", CheckState.Bad, "Missing. Windows normally keeps this file, so it was most likely deleted.");
            return 0;
        }
        var hive = new Parsers.RegistryHive(LockedFile.Read(path));
        var files = hive.Root.Path(@"Root\InventoryApplicationFile");
        if (files == null)
        {
            ctx.Check("Amcache", "Amcache.hve", CheckState.Warning, "No InventoryApplicationFile key (older Windows layout); not read.");
            return 0;
        }
        int items = 0;
        DateTime? newest = null;
        foreach (var key in files.Subkeys())
        {
            ct.ThrowIfCancellationRequested();
            var v = key.Values();
            if (v.GetValueOrDefault("LowerCaseLongPath") is not string lower || lower.Length < 3) continue;
            string sha1 = v.GetValueOrDefault("FileId") is string id && id.Length == 44 ? id[4..] : "";
            string publisher = v.GetValueOrDefault("Publisher") as string ?? "";
            string product = v.GetValueOrDefault("ProductName") as string ?? "";
            if (key.LastWriteUtc > newest || newest == null) newest = key.LastWriteUtc;
            ctx.Add(new Evidence
            {
                Source = EvidenceSource.Amcache, Kind = EvidenceKind.Presence, Path = ctx.Paths.Normalize(lower), TimeUtc = key.LastWriteUtc,
                Origin = "Amcache.hve",
                Detail = "Recorded by Windows (usually when it ran or was installed)" +
                         (sha1.Length > 0 ? $"; SHA-1 {sha1}" : "") +
                         (publisher.Length > 0 ? $"; publisher {publisher}" : "") + (product.Length > 0 ? $"; product {product}" : ""),
            });
            items++;
        }
        ctx.Check("Amcache", "Amcache.hve", items > 0 ? CheckState.Ok : CheckState.Warning,
            $"{items:N0} program files recorded, newest entry {Util.When.L(newest)}. Windows writes some entries a while after the run, so the very latest may be missing.");
        return items;
    }
}

/// <summary>Reads a file Windows keeps open exclusively, straight from its clusters on the volume. Read-only.</summary>
internal static class LockedFile
{
    public static byte[] Read(string path)
    {
        try { return SafeFile.ReadAllBytesShared(path, 256 * 1024 * 1024); }
        catch (IOException) { } // locked by Windows: fall through to the raw read

        long length = new FileInfo(path).Length;
        string root = Path.GetPathRoot(path)!;
        if (!GetDiskFreeSpace(root, out uint spc, out uint bps, out _, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
        long cluster = (long)spc * bps;

        using var file = CreateFile(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (file.IsInvalid) throw new UnauthorizedAccessException($"Cannot open {Path.GetFileName(path)} (run as administrator).");
        var extents = Extents(file);

        using var volume = CreateFile($@"\\.\{root.TrimEnd('\\')}", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (volume.IsInvalid) throw new UnauthorizedAccessException("Cannot open the volume (run as administrator).");

        var data = new byte[(length + cluster - 1) / cluster * cluster];
        long vcn = 0;
        foreach (var (nextVcn, lcn) in extents)
        {
            long count = nextVcn - vcn;
            long bytes = Math.Min(count * cluster, data.Length - vcn * cluster);
            if (bytes <= 0) break;
            if (lcn >= 0) // -1 = sparse run, already zero
            {
                int read = RandomAccess.Read(volume, data.AsSpan((int)(vcn * cluster), (int)bytes), lcn * cluster);
                if (read != bytes) throw new IOException("Short read from the volume.");
            }
            vcn = nextVcn;
        }
        return data.AsSpan(0, (int)length).ToArray();
    }

    static List<(long NextVcn, long Lcn)> Extents(SafeFileHandle file)
    {
        var result = new List<(long, long)>();
        var input = new byte[8];
        var output = new byte[64 * 1024];
        long start = 0;
        while (true)
        {
            BitConverter.GetBytes(start).CopyTo(input, 0);
            bool ok = DeviceIoControl(file, FSCTL_GET_RETRIEVAL_POINTERS, input, input.Length, output, output.Length, out int returned, IntPtr.Zero);
            int err = ok ? 0 : Marshal.GetLastWin32Error();
            if (!ok && err != ERROR_MORE_DATA) throw new Win32Exception(err);
            int count = BitConverter.ToInt32(output, 0);
            for (int i = 0; i < count && 16 + i * 16 + 16 <= returned; i++)
                result.Add((BitConverter.ToInt64(output, 16 + i * 16), BitConverter.ToInt64(output, 24 + i * 16)));
            if (ok || count == 0) return result;
            start = result[^1].Item1;
        }
    }
}

/// <summary>
/// Shortcuts Windows creates in each user's Recent folder whenever a file is opened from Explorer or a
/// file dialog: full target path, first opened (shortcut created) and last opened (shortcut written).
/// A target that is gone now is a deleted file that was opened.
/// </summary>
public sealed class RecentShortcutCollector : ICollector
{
    public string Name => "Recent shortcuts";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var profile in JavaUsageCollector.UserProfiles())
        {
            string dir = Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Recent");
            if (!Directory.Exists(dir)) continue;
            string user = Path.GetFileName(profile);
            IEnumerable<string> links;
            try { links = Directory.EnumerateFiles(dir, "*.lnk"); }
            catch (UnauthorizedAccessException) { continue; }
            foreach (var lnk in links)
            {
                ct.ThrowIfCancellationRequested();
                ShellLinkInfo? info;
                try { info = ShellLink.Parse(SafeFile.ReadAllBytesShared(lnk, 1024 * 1024)); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException) { continue; }
                if (info == null) continue;
                var target = ctx.Paths.Normalize(info.TargetPath);
                if (FileTypes.FromPath(target) == FileType.Other && !target.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                    !target.EndsWith(".rar", StringComparison.OrdinalIgnoreCase) && !target.EndsWith(".7z", StringComparison.OrdinalIgnoreCase)) continue;
                var fi = new FileInfo(lnk);
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.RecentShortcut, Kind = EvidenceKind.Presence, Path = target, TimeUtc = fi.LastWriteTimeUtc,
                    Origin = user,
                    Detail = $"Opened by {user}: first {Util.When.L(fi.CreationTimeUtc)}, last {Util.When.L(fi.LastWriteTimeUtc)} (Recent\\{fi.Name})" +
                             (info.TargetModifiedUtc is { } m ? $"; the file was dated {Util.When.L(m)}, {info.TargetSize:N0} bytes then" : ""),
                });
                items++;
            }
        }
        return items;
    }
}

/// <summary>
/// Jump Lists: every application's list of items it opened (Explorer's own list holds files and programs opened from
/// it), with when each was last opened and how often. They are separate from the Recent folder and survive clearing
/// it. A program or jar in a Jump List was launched from there; any other file was opened.
/// </summary>
public sealed class JumpListCollector : ICollector
{
    public string Name => "Jump lists";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var profile in JavaUsageCollector.UserProfiles())
        {
            string dir = Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations");
            if (!Directory.Exists(dir)) continue;
            string user = Path.GetFileName(profile);
            IEnumerable<string> lists;
            try { lists = Directory.EnumerateFiles(dir, "*.automaticDestinations-ms"); }
            catch (UnauthorizedAccessException) { continue; }
            foreach (var file in lists)
            {
                ct.ThrowIfCancellationRequested();
                List<Parsers.JumpListEntry> entries;
                try { entries = Parsers.JumpList.Parse(SafeFile.ReadAllBytesShared(file, 32 * 1024 * 1024)); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or IndexOutOfRangeException) { continue; }
                foreach (var e in entries)
                {
                    // Files only: Jump Lists also hold folders, settings pages and app links (ms-settings:, odopen://).
                    if (e.Path.Length < 4 || !(e.Path[1] == ':' && e.Path[2] == '\\' || e.Path.StartsWith(@"\\", StringComparison.Ordinal))) continue;
                    var target = ctx.Paths.Normalize(e.Path);
                    var type = FileTypes.FromPath(target);
                    bool archive = target.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) || target.EndsWith(".rar", StringComparison.OrdinalIgnoreCase) ||
                                   target.EndsWith(".7z", StringComparison.OrdinalIgnoreCase);
                    if (type == FileType.Other && !archive) continue;
                    var when = e.LastOpenedUtc ?? new FileInfo(file).LastWriteTimeUtc;
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.JumpList,
                        Kind = type is FileType.Exe or FileType.Jar or FileType.Script ? EvidenceKind.Execution : EvidenceKind.Presence,
                        Path = target, TimeUtc = when, Origin = user,
                        Detail = $"Opened by {user}{(e.OpenCount is int n and > 0 ? $" {n} time(s)" : "")}, last {Util.When.L(when)}" +
                                 (e.Pinned ? ", pinned" : "") + $" (Jump List {Path.GetFileName(file)[..16]})" +
                                 (e.Link?.TargetModifiedUtc is { } m ? $"; the file was dated {Util.When.L(m)}, {e.Link.TargetSize:N0} bytes then" : ""),
                    });
                    items++;
                }
            }
        }
        return items;
    }
}

/// <summary>
/// Explorer's per-user program records: taskbar launches and window switches (FeatureUsage), the
/// Program Compatibility Assistant's list of programs run, and compatibility settings on programs.
/// </summary>
public sealed class ExplorerUsageCollector : ICollector
{
    public string Name => "Taskbar & compatibility records";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var sid in WinApi.LoadedUserSids())
        {
            string user = WinApi.SidToName(sid);
            items += Values(ctx, Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
                EvidenceSource.FeatureUsage, EvidenceKind.Execution, user, (n, v) => $"Started from the taskbar {v} time(s) by {user}");
            items += Values(ctx, Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
                EvidenceSource.FeatureUsage, EvidenceKind.Execution, user, (n, v) => $"Its window was switched to {v} time(s) by {user}");
            items += Values(ctx, Registry.Users, $@"{sid}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
                EvidenceSource.CompatAssistant, EvidenceKind.Execution, user, (n, v) => $"Run by {user} (Program Compatibility Assistant record)");
            items += Values(ctx, Registry.Users, $@"{sid}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
                EvidenceSource.CompatAssistant, EvidenceKind.Presence, user, (n, v) => $"Compatibility settings for {user}: {v}");
        }
        items += Values(ctx, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
            EvidenceSource.CompatAssistant, EvidenceKind.Presence, "All users", (n, v) => $"Compatibility settings for all users: {v}");
        return items;
    }

    static int Values(ScanContext ctx, RegistryKey root, string path, EvidenceSource source, EvidenceKind kind, string owner,
        Func<string, object?, string> detail)
    {
        RegistryKey? key;
        try { key = root.OpenSubKey(path); }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { return 0; }
        if (key == null) return 0;
        using (key)
        {
            DateTime? changed = WinApi.GetKeyLastWriteUtc(key);
            int items = 0;
            foreach (var name in key.GetValueNames())
            {
                var p = ctx.Paths.Normalize(name);
                if (p.Length < 4 || p[1] != ':' || FileTypes.FromPath(p) == FileType.Other) continue; // app IDs, not paths
                var value = key.GetValue(name);
                ctx.Add(new Evidence
                {
                    Source = source, Kind = kind, Path = p, Origin = owner,
                    RunCount = value is int count && source == EvidenceSource.FeatureUsage ? count : null,
                    Detail = detail(name, value is byte[] ? "(binary)" : value) + $" — list last changed {Util.When.L(changed)}",
                });
                items++;
            }
            return items;
        }
    }
}

/// <summary>
/// Programs that crashed or hung (Application log 1000 / 1002 and Windows Error Reporting files) — a
/// crash proves the program ran, and the report lists the DLL it crashed in or every module it had
/// loaded. Java's own crash logs (hs_err_pid*.log) list every native library loaded into the game.
/// </summary>
public sealed class CrashReportCollector : ICollector
{
    public string Name => "Crash reports";

    public int Collect(ScanContext ctx, CancellationToken ct) => Events(ctx, ct) + WerFiles(ctx, ct) + JavaCrashLogs(ctx, ct);

    static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    static int Events(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        var query = new EventLogQuery("Application", PathType.LogName,
            "*[System[(Provider[@Name='Application Error'] and EventID=1000) or (Provider[@Name='Application Hang'] and EventID=1002)]]")
            { ReverseDirection = true };
        try
        {
            using var reader = new EventLogReader(query);
            for (var r = reader.ReadEvent(); r != null && items < 4000; r = reader.ReadEvent())
            {
                using (r)
                {
                    ct.ThrowIfCancellationRequested();
                    if (r.TimeCreated is not { } local) continue;
                    var data = XDocument.Parse(r.ToXml()).Descendants(Ns + "Data").Select(d => d.Value).ToList();
                    // 1000: ..., [10] application path, [11] faulting module path. 1002: [0] name, ... path follows later.
                    string? app = data.FirstOrDefault(d => d.Contains(":\\") && d.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
                    if (app == null) continue;
                    var t = local.ToUniversalTime();
                    bool hang = r.Id == 1002;
                    string? module = !hang && data.Count > 11 && data[11].Contains(":\\") ? ctx.Paths.Normalize(data[11]) : null;
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.CrashReport, Kind = EvidenceKind.Execution, Path = ctx.Paths.Normalize(app), TimeUtc = t,
                        Origin = $"Application/{r.Id}",
                        Detail = hang ? "Stopped responding (so it was running)" : $"Crashed (so it was running)" + (module != null ? $" in {Path.GetFileName(module)}" : ""),
                    });
                    items++;
                    if (module != null && !FileTypes.IsWindowsFile(module) && !module.Equals(ctx.Paths.Normalize(app), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.Add(new Evidence
                        {
                            Source = EvidenceSource.CrashReport, Kind = EvidenceKind.LoadedModule, Path = module, TimeUtc = t, Origin = Path.GetFileName(app),
                            Detail = $"Loaded in {Path.GetFileName(app)} when it crashed (the crash happened inside this file)",
                        });
                        items++;
                    }
                }
            }
        }
        catch (EventLogException) { }
        return items;
    }

    static int WerFiles(ScanContext ctx, CancellationToken ct)
    {
        var roots = new List<string> { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\WER") };
        roots.AddRange(JavaUsageCollector.UserProfiles().Select(p => Path.Combine(p, @"AppData\Local\Microsoft\Windows\WER")));
        int items = 0;
        foreach (var root in roots)
        {
            foreach (var sub in new[] { "ReportArchive", "ReportQueue" })
            {
                string dir = Path.Combine(root, sub);
                if (!Directory.Exists(dir)) continue;
                IEnumerable<string> reports;
                try { reports = Directory.EnumerateFiles(dir, "Report.wer", SearchOption.AllDirectories).Take(1000).ToList(); }
                catch (Exception e) when (e is UnauthorizedAccessException or IOException) { continue; }
                foreach (var file in reports)
                {
                    ct.ThrowIfCancellationRequested();
                    string text;
                    try { text = TextDecoding.Decode(SafeFile.ReadAllBytesShared(file, 4 * 1024 * 1024)); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { continue; }
                    items += ParseWer(ctx, text, file);
                }
            }
        }
        return items;
    }

    internal static int ParseWer(ScanContext ctx, string text, string file)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var modules = new List<string>();
        foreach (var line in text.Split('\n'))
        {
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            string key = line[..eq].Trim(), value = line[(eq + 1)..].Trim();
            if (key.StartsWith("LoadedModule[", StringComparison.OrdinalIgnoreCase)) modules.Add(value);
            else fields.TryAdd(key, value);
        }
        if (!fields.TryGetValue("AppPath", out var app) || !app.Contains(":\\")) return 0;
        DateTime? t = fields.TryGetValue("EventTime", out var et) && long.TryParse(et, out var ft) ? FileTime.ToUtc(ft) : null;
        string kind = fields.GetValueOrDefault("EventType") ?? "error report";
        app = ctx.Paths.Normalize(app);
        ctx.Add(new Evidence
        {
            Source = EvidenceSource.CrashReport, Kind = EvidenceKind.Execution, Path = app, TimeUtc = t, Origin = Path.GetFileName(Path.GetDirectoryName(file)),
            Detail = $"Windows Error Reporting ({kind}) — it was running then",
        });
        int items = 1;
        foreach (var m in modules.Select(ctx.Paths.Normalize).Where(m => m.Contains(":\\") && !FileTypes.IsWindowsFile(m) &&
                                                                         !m.Equals(app, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ctx.Add(new Evidence
            {
                Source = EvidenceSource.CrashReport, Kind = EvidenceKind.LoadedModule, Path = m, TimeUtc = t, Origin = Path.GetFileName(app),
                Detail = $"Loaded in {Path.GetFileName(app)} when Windows Error Reporting captured it ({kind})",
            });
            items++;
        }
        return items;
    }

    static readonly Regex HsErrLibrary = new(@"^0x[0-9a-f]+\s+-\s+0x[0-9a-f]+\s+(?<path>[A-Za-z]:\\.+\.dll)\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    /// <summary>hs_err_pid*.log in the game folders and the user's home: every DLL the JVM had loaded when it crashed.</summary>
    static int JavaCrashLogs(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var profile in JavaUsageCollector.UserProfiles())
        {
            foreach (var dir in new[] { profile, Path.Combine(profile, @"AppData\Roaming\.minecraft"), Path.Combine(profile, @"AppData\Roaming\.minecraft\crash-reports") })
            {
                if (!Directory.Exists(dir)) continue;
                string[] logs;
                try { logs = Directory.GetFiles(dir, "hs_err_pid*.log"); }
                catch (Exception e) when (e is UnauthorizedAccessException or IOException) { continue; }
                foreach (var log in logs.Take(50))
                {
                    ct.ThrowIfCancellationRequested();
                    string text;
                    try { text = File.ReadAllText(log); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
                    var t = File.GetLastWriteTimeUtc(log);
                    foreach (Match m in HsErrLibrary.Matches(text))
                    {
                        var p = ctx.Paths.Normalize(m.Groups["path"].Value.Trim());
                        if (FileTypes.IsWindowsFile(p)) continue;
                        ctx.Add(new Evidence
                        {
                            Source = EvidenceSource.CrashReport, Kind = EvidenceKind.LoadedModule, Path = p, TimeUtc = t, Origin = Path.GetFileName(log),
                            Detail = $"Loaded into Java when it crashed ({Path.GetFileName(log)})",
                        });
                        items++;
                    }
                }
            }
        }
        return items;
    }
}

/// <summary>Microsoft Defender's detection history (1116 detected, 1117 action taken): what it caught, where and when.</summary>
public sealed class DefenderDetectionCollector : ICollector
{
    public string Name => "Defender detections";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, "*[System[(EventID=1116 or EventID=1117)]]")
            { ReverseDirection = true };
        using var reader = new EventLogReader(query);
        for (var r = reader.ReadEvent(); r != null && items < 2000; r = reader.ReadEvent())
        {
            using (r)
            {
                ct.ThrowIfCancellationRequested();
                if (r.TimeCreated is not { } local) continue;
                var data = XDocument.Parse(r.ToXml()).Descendants().Where(d => d.Name.LocalName == "Data")
                    .ToDictionary(d => (string?)d.Attribute("Name") ?? "", d => d.Value, StringComparer.OrdinalIgnoreCase);
                string threat = data.GetValueOrDefault("Threat Name") ?? "unknown threat";
                string action = data.GetValueOrDefault("Action Name") ?? "";
                var t = local.ToUniversalTime();
                foreach (var target in DetectionPaths(data.GetValueOrDefault("Path") ?? ""))
                {
                    var p = ctx.Paths.Normalize(target);
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.Defender, Kind = EvidenceKind.Presence, Path = p, TimeUtc = t, Origin = $"Defender/{r.Id}",
                        Detail = r.Id == 1116 ? $"Defender detected {threat}" : $"Defender acted on {threat}: {action}",
                    });
                    items++;
                    // Context, never proof: Defender's machine-learning verdicts (Wacatac, "!ml") routinely hit harmless
                    // unsigned tools — screenshare tools included — so a detection alone stays Low, and only for programs.
                    if (r.Id == 1116 && FileTypes.FromPath(p) != FileType.Other && seen.Add(p + "|" + threat))
                        ctx.Flag(Severity.Low, FindingCategory.Defender, $"Defender detected {threat}",
                            $"Microsoft Defender flagged {p} as {threat} at {Util.When.L(t)}. Cheats and injectors are often detected, but so are many " +
                            "harmless unsigned tools (especially \"!ml\" / Wacatac verdicts), so check what the file is before judging.", p, t);
                }
            }
        }
        return items;
    }

    /// <summary>"file:_C:\x\y.exe; process:_pid:12,ProcessStart:1" → C:\x\y.exe; also "containerfile:_" entries.</summary>
    internal static IEnumerable<string> DetectionPaths(string raw) =>
        raw.Split(';').Select(s => s.Trim())
            .Where(s => s.StartsWith("file:_", StringComparison.OrdinalIgnoreCase) || s.StartsWith("containerfile:_", StringComparison.OrdinalIgnoreCase))
            .Select(s => s[(s.IndexOf('_') + 1)..].Split("->")[0].Trim())
            .Where(s => s.Length > 3 && s[1] == ':')
            .Distinct(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Where a file was downloaded from: the Zone.Identifier stream browsers attach to downloads.</summary>
public static class DownloadOrigin
{
    public static void Annotate(IEnumerable<FileRecord> files)
    {
        foreach (var r in files)
        {
            if (r.Status != FileStatus.Exists || r.IsWindowsFile || r.Type == FileType.Other) continue;
            string text;
            try { text = File.ReadAllText(r.Path + ":Zone.Identifier"); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException) { continue; }
            r.DownloadedFrom = Parse(text);
        }
    }

    internal static string? Parse(string text)
    {
        string? Field(string name) => Regex.Match(text, $@"^{name}=(.+)$", RegexOptions.Multiline | RegexOptions.IgnoreCase) is { Success: true } m
            ? m.Groups[1].Value.Trim() : null;
        var host = Field("HostUrl");
        var referrer = Field("ReferrerUrl");
        if (host == null && referrer == null) return Field("ZoneId") is "3" ? "the internet (no address recorded)" : null;
        return host != null && referrer != null && referrer != host ? $"{host} (via {referrer})" : host ?? referrer;
    }
}

/// <summary>
/// Windows' privacy access records (CapabilityAccessManager): every desktop program that used the camera, microphone,
/// location or screen capture, by full path, with the start and stop time of its last use. The record stays after the
/// program is deleted, so it is also a run-time source for programs Prefetch and BAM no longer show.
/// </summary>
public sealed class CapabilityAccessCollector : ICollector
{
    const string Store = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    static readonly Dictionary<string, string> Uses = new(StringComparer.OrdinalIgnoreCase)
    {
        ["webcam"] = "used the camera",
        ["microphone"] = "used the microphone",
        ["location"] = "asked for the location",
        ["graphicsCaptureProgrammatic"] = "captured the screen",
        ["graphicsCaptureWithoutBorder"] = "captured the screen without the capture border",
    };

    public string Name => "Privacy access records";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = Read(ctx, Registry.LocalMachine, Store.Replace("Software", "SOFTWARE"), "All users");
        foreach (var sid in WinApi.LoadedUserSids())
            items += Read(ctx, Registry.Users, $@"{sid}\{Store}", WinApi.SidToName(sid));
        return items;
    }

    static int Read(ScanContext ctx, RegistryKey root, string path, string owner)
    {
        RegistryKey? store;
        try { store = root.OpenSubKey(path); }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { return 0; }
        if (store == null) return 0;
        int items = 0;
        using (store)
            foreach (var (capability, what) in Uses)
            {
                RegistryKey? apps;
                try { apps = store.OpenSubKey($@"{capability}\NonPackaged"); }
                catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { continue; }
                if (apps == null) continue;
                using (apps)
                    foreach (var name in apps.GetSubKeyNames())
                    {
                        // Subkey names are the program path with '\' written as '#'.
                        var p = ctx.Paths.Normalize(name.Replace('#', '\\'));
                        if (p.Length < 4 || p[1] != ':') continue;
                        using var app = apps.OpenSubKey(name);
                        DateTime? start = FileTime(app?.GetValue("LastUsedTimeStart")), stop = FileTime(app?.GetValue("LastUsedTimeStop"));
                        ctx.Add(new Evidence
                        {
                            Source = EvidenceSource.CapabilityAccess, Kind = EvidenceKind.Execution, Path = p, TimeUtc = start, Origin = owner,
                            Detail = $"Last {what} from {Util.When.L(start)} to {Util.When.L(stop)} ({owner})",
                        });
                        items++;
                    }
            }
        return items;
    }

    static DateTime? FileTime(object? value) =>
        value is long ft && ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(ft) : null;
}
