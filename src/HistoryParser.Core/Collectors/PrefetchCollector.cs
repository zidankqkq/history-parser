using HistoryParser.Core.Models;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// C:\Windows\Prefetch. Each .pf holds the last 8 run times and run count of one executable,
/// plus every file it loaded in its first seconds — which is how jars launched through
/// javaw.exe and injected DLLs become visible.
/// </summary>
public sealed class PrefetchCollector : ICollector
{
    public string Name => "Prefetch";

    static readonly HashSet<string> LoadedExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".jar", ".ahk", ".py", ".pyw", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd" };

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(dir))
        {
            ctx.Check("Prefetch", "Prefetch folder", CheckState.Bad, "The Prefetch folder does not exist.");
            ctx.PrefetchFileCount = 0;
            return 0;
        }

        var files = Directory.GetFiles(dir, "*.pf");
        ctx.PrefetchFileCount = files.Length;
        int items = 0, ownReads = 0, recycleRecords = 0;
        var unreadable = new List<string>();
        DateTime? newestWrite = null, oldestWrite = null;

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fi = new FileInfo(file);
            var written = fi.LastWriteTimeUtc;
            if (newestWrite == null || written > newestWrite) newestWrite = written;
            if (oldestWrite == null || written < oldestWrite) oldestWrite = written;

            PrefetchInfo pf;
            try { pf = PrefetchParser.Parse(SafeFile.ReadAllBytesShared(file)); }
            catch (Exception e) when (e is FormatException or IOException or InvalidDataException or OverflowException)
            {
                unreadable.Add(fi.Name);
                continue;
            }

            string exePath = ResolveExecutablePath(pf, ctx.Paths);
            var lastRun = pf.RunTimesUtc.Count > 0 ? pf.RunTimesUtc[0] : (DateTime?)null;

            for (int i = 0; i < pf.RunTimesUtc.Count; i++)
            {
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.Prefetch, Kind = EvidenceKind.Execution, Path = exePath,
                    TimeUtc = pf.RunTimesUtc[i], RunCount = pf.RunCount, Origin = fi.Name,
                    Detail = i == 0
                        ? $"Last run (run count {pf.RunCount}, {fi.Name})"
                        : $"Earlier run #{i + 1} of the {pf.RunTimesUtc.Count} kept ({fi.Name})",
                });
                items++;
            }

            var exeKey = PathNormalizer.Key(exePath);
            bool java = pf.ExecutableName.Equals("JAVAW.EXE", StringComparison.OrdinalIgnoreCase) ||
                        pf.ExecutableName.Equals("JAVA.EXE", StringComparison.OrdinalIgnoreCase);
            // A verified copy of this suite only reads files (that is how it checks them): what it touched during a scan is
            // not something the player ran. Its own run is still recorded above. Trusted by exact hash only, never by name.
            bool suite = pf.FileNames.Count > 0 && Analysis.SelfTraces.Classify(exePath) == Analysis.SelfTraces.Match.Yes;
            if (suite) ownReads += pf.FileNames.Count(n => LoadedExtensions.Contains(Path.GetExtension(n)));
            foreach (var name in suite ? [] : pf.FileNames)
            {
                var ext = Path.GetExtension(name);
                // Java does not care what a jar is called: one renamed to .png still runs. Every other file Java opened
                // outside Windows is checked by its content.
                if (java && !LoadedExtensions.Contains(ext) && DisguisedJar(ctx, ctx.Paths.Normalize(name), pf.ExecutableName, fi.Name, lastRun))
                {
                    items++;
                    continue;
                }
                // Programs, libraries and jars, plus scripts run by an interpreter (AutoHotkey, Python,
                // PowerShell, Windows Script Host, mshta): the script itself never shows up as a program.
                if (!LoadedExtensions.Contains(ext)) continue;
                var p = ctx.Paths.Normalize(name);
                bool script = FileTypes.FromPath(p) == FileType.Script;
                // Interpreters load their own library scripts by the hundred; keep only the user's.
                if (script && (FileTypes.IsWindowsFile(p) || p.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) ||
                               p.Contains(@"\Lib\", StringComparison.OrdinalIgnoreCase) || p.Contains("site-packages", StringComparison.OrdinalIgnoreCase) ||
                               p.Contains(@"\Programs\Python", StringComparison.OrdinalIgnoreCase))) continue;
                if (PathNormalizer.Key(p) == exeKey) continue;
                // The Recycle Bin's info records keep the deleted file's extension ($IAB12CD.jar), and Explorer and scanners read
                // them all. They are bookkeeping, not programs - unless Java opened one, or the file there is not such a record.
                if (!java && IsRecycleBinRecord(p)) { recycleRecords++; continue; }
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.Prefetch, Kind = EvidenceKind.LoadedModule, Path = p, TimeUtc = lastRun,
                    Origin = pf.ExecutableName,
                    Detail = $"Listed in {fi.Name}: loaded by {pf.ExecutableName} during one of its runs (time shown is its latest run)",
                });
                items++;
            }

            // Windows rewrites the .pf a few seconds after each launch, so the file can never
            // be older than the last run it records.
            if (lastRun is { } lr && written < lr - ctx.Options.Tolerance)
            {
                ctx.Flag(Severity.High, FindingCategory.ClockTampering, "Prefetch file is older than its own last run",
                    $"{fi.Name} was last written {Util.When.L(written)} but records a run at {Util.When.L(lr)}. Either the clock was moved " +
                    "back after that run or the file was edited/copied in.", exePath, lr);
            }
        }

        ReportHealth(ctx, files.Length, unreadable, newestWrite, oldestWrite);
        if (ownReads + recycleRecords > 0)
            ctx.Check("Prefetch", "Files read, not run", CheckState.Ok,
                (ownReads > 0 ? $"{ownReads:N0} files this suite read during an earlier scan are not counted as loaded. " : "") +
                (recycleRecords > 0 ? $"{recycleRecords:N0} Recycle Bin info records ($I…) read by other programs are not counted as programs." : ""));
        return items;
    }

    /// <summary>
    /// A Recycle Bin info record: a $I… file in a $Recycle.Bin folder whose content is the record for a deleted item with the
    /// same extension. A file that is gone (the bin was emptied or the item restored) went with its item. Anything else named
    /// like one - a jar, an unreadable file - is not taken on trust.
    /// </summary>
    internal static bool IsRecycleBinRecord(string path)
    {
        if (!path.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(path).StartsWith("$I", StringComparison.OrdinalIgnoreCase)) return false;
        if (!File.Exists(path)) return true;
        try
        {
            var entry = RecycleBinParser.Parse(SafeFile.ReadAllBytesShared(path, 1 << 16));
            return string.Equals(Path.GetExtension(entry.OriginalPath), Path.GetExtension(path), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception e) when (e is FormatException or IOException or UnauthorizedAccessException or OverflowException or ArgumentException or IndexOutOfRangeException)
        {
            return false;
        }
    }

    /// <summary>
    /// A file Java opened that is really a jar under another name: recorded as a jar (so it is listed with the jars) and
    /// flagged. Files in Windows' folder or with a normal Java-code name are not opened; a deleted file cannot be checked.
    /// </summary>
    static bool DisguisedJar(ScanContext ctx, string path, string loader, string pfName, DateTime? lastRun)
    {
        if (path.StartsWith('[') || FileTypes.IsWindowsFile(path) || FileTypes.IsJavaContainerName(path) || !File.Exists(path)) return false;
        if (!FileTypes.IsJavaArchive(path)) return false;
        string ext = Path.GetExtension(path);
        ctx.Add(new Evidence
        {
            Source = EvidenceSource.Prefetch, Kind = EvidenceKind.LoadedModule, Path = path, TimeUtc = lastRun, Origin = loader,
            ActualType = FileType.Jar,
            Detail = $"Listed in {pfName}: opened by {loader}; its content is a Java archive although its name ends in \"{ext}\"",
        });
        bool harmless = FileTypes.LooksHarmless(path);
        ctx.Flag(harmless ? Severity.High : Severity.Medium, FindingCategory.AntiForensics,
            ext.Length > 0 ? $"Java ran a jar renamed to {ext}" : "Java ran a jar with no file extension",
            $"{Path.GetFileName(path)} holds compiled Java classes, but its name {(ext.Length > 0 ? $"ends in \"{ext}\"" : "has no extension")}. " +
            $"{loader} opened it ({pfName}). Java runs a jar whatever it is called, so renaming one keeps it out of jar lists and searches" +
            (harmless ? " - no normal program names its code like a picture or a document." : "; a few launchers store their files without the usual name, so check where it came from."),
            path, lastRun);
        return true;
    }

    static void ReportHealth(ScanContext ctx, int count, List<string> unreadable, DateTime? newest, DateTime? oldest)
    {
        var state = count switch { 0 => CheckState.Bad, < 40 => CheckState.Warning, _ => CheckState.Ok };
        ctx.Check("Prefetch", "Prefetch files present", state,
            count == 0
                ? "No .pf files. Prefetch is disabled or the folder was emptied."
                : $"{count} files, written between {Util.When.L(oldest)} and {Util.When.L(newest)}." +
                  (count < 40 ? " Unusually few — the folder may have been cleared recently." : ""));

        bool uptimeLong = ctx.NowUtc - ctx.BootUtc > TimeSpan.FromMinutes(15);
        if (count > 0 && uptimeLong && newest < ctx.BootUtc)
            ctx.Check("Prefetch", "Prefetch updated since boot", CheckState.Bad,
                $"Newest .pf was written {Util.When.L(newest)}, before the last boot ({Util.When.L(ctx.BootUtc)}). Prefetch is not recording.");
        else if (count > 0)
            ctx.Check("Prefetch", "Prefetch updated since boot", CheckState.Ok, $"Newest .pf written {Util.When.L(newest)}.");

        if (unreadable.Count > 0)
        {
            ctx.Check("Prefetch", "Prefetch files readable", CheckState.Warning,
                $"{unreadable.Count} file(s) could not be parsed: {string.Join(", ", unreadable.Take(10))}");
            // A crash or power cut mid-write leaves a truncated .pf, so this alone is weak.
            ctx.Flag(unreadable.Count >= 5 ? Severity.Medium : Severity.Low, FindingCategory.AntiForensics, "Corrupt prefetch files",
                $"{unreadable.Count} prefetch file(s) are not valid (zeroed, truncated or edited): " +
                string.Join(", ", unreadable.Take(20)) + ". A crash or power loss while Windows was writing can also leave a broken file.");
        }
    }

    /// <summary>The .pf only names the exe (max 29 chars); its full path is among the loaded files.</summary>
    internal static string ResolveExecutablePath(PrefetchInfo pf, PathNormalizer paths)
    {
        string exe = pf.ExecutableName;
        string? best = null;
        foreach (var name in pf.FileNames)
        {
            int slash = name.LastIndexOf('\\');
            var file = slash >= 0 ? name[(slash + 1)..] : name;
            bool match = file.Equals(exe, StringComparison.OrdinalIgnoreCase) ||
                         (exe.Length >= 29 && file.StartsWith(exe, StringComparison.OrdinalIgnoreCase));
            if (!match) continue;
            best = name;
            if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) break;
        }
        return best != null ? paths.Normalize(best) : exe;
    }
}
