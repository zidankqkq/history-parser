using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Collectors;

/// <summary>Windows 11 22H2+ Program Compatibility Assistant launch records (UTC).</summary>
public sealed class PcaCollector : ICollector
{
    public string Name => "PCA (Windows 11)";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"appcompat\pca");
        if (!Directory.Exists(dir)) return 0;
        int items = 0;

        string launch = Path.Combine(dir, "PcaAppLaunchDic.txt");
        if (File.Exists(launch))
        {
            foreach (var e in PcaParser.ParseLaunchDic(TextDecoding.Decode(SafeFile.ReadAllBytesShared(launch))))
            {
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.Pca, Kind = EvidenceKind.Execution, Path = ctx.Paths.Normalize(e.Path),
                    TimeUtc = e.TimeUtc, Origin = "PcaAppLaunchDic.txt", Detail = "Last launch (PcaAppLaunchDic)",
                });
                items++;
            }
            ctx.Check("PCA", "PCA launch log", CheckState.Ok,
                $"PcaAppLaunchDic.txt last written {Util.When.L(File.GetLastWriteTimeUtc(launch))}.");
        }

        foreach (var name in new[] { "PcaGeneralDb0.txt", "PcaGeneralDb1.txt" })
        {
            ct.ThrowIfCancellationRequested();
            string file = Path.Combine(dir, name);
            if (!File.Exists(file)) continue;
            foreach (var e in PcaParser.ParseGeneralDb(TextDecoding.Decode(SafeFile.ReadAllBytesShared(file))))
            {
                // GeneralDb rows are compatibility events (crashes, installer detection ...) logged
                // while the program ran — proof it ran, but not a launch time to compare with Prefetch.
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.Pca, Kind = EvidenceKind.Presence, Path = ctx.Paths.Normalize(e.Path),
                    TimeUtc = e.TimeUtc, Origin = name, Detail = $"PCA compatibility event ({name}): {e.Extra}",
                });
                items++;
            }
        }
        return items;
    }
}

/// <summary>%USERPROFILE%\.oracle_jre_usage: one file per Java runtime, touched whenever it is used.</summary>
public sealed class JavaUsageCollector : ICollector
{
    public string Name => "Java usage (.oracle_jre_usage)";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var profile in UserProfiles())
        {
            string dir = Path.Combine(profile, ".oracle_jre_usage");
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.GetFiles(dir, "*.timestamp"))
            {
                ct.ThrowIfCancellationRequested();
                string[] lines;
                try { lines = TextDecoding.Decode(SafeFile.ReadAllBytesShared(file, 1 << 16)).Split('\n'); }
                catch (IOException) { continue; }
                var javaHome = lines.FirstOrDefault()?.Trim() ?? "";
                if (javaHome.Length == 0) continue;
                var javaw = Path.Combine(javaHome, "bin", "javaw.exe");
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.JavaUsage, Kind = EvidenceKind.Execution, Path = ctx.Paths.Normalize(javaw),
                    TimeUtc = File.GetLastWriteTimeUtc(file), Origin = Path.GetFileName(profile),
                    Detail = $"Java runtime {javaHome} last used (from {Path.GetFileName(file)}); " +
                             $"recorded value: {string.Join(" ", lines.Skip(1).Select(l => l.Trim()).Where(l => l.Length > 0))}",
                });
                items++;
            }
        }
        return items;
    }

    internal static IEnumerable<string> UserProfiles()
    {
        string root = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users";
        try { return Directory.GetDirectories(root); }
        catch (UnauthorizedAccessException) { return [Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)]; }
    }
}

/// <summary>$Recycle.Bin on every fixed drive: original path and deletion time of recycled files.</summary>
public sealed class RecycleBinCollector : ICollector
{
    public string Name => "Recycle Bin";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
        {
            string bin = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
            if (!Directory.Exists(bin)) continue;
            foreach (var sidDir in Directory.GetDirectories(bin))
            {
                string[] infoFiles;
                try { infoFiles = Directory.GetFiles(sidDir, "$I*"); }
                catch (UnauthorizedAccessException) { continue; }

                var dirInfo = new DirectoryInfo(sidDir);
                string user = WinApi.SidToName(dirInfo.Name);
                if (infoFiles.Length == 0 && ctx.NowUtc - dirInfo.LastWriteTimeUtc < TimeSpan.FromHours(2))
                {
                    ctx.Check("Recycle Bin", $"Recycle Bin ({drive.Name}, {user})", CheckState.Warning,
                        $"Empty, last changed {Util.When.L(dirInfo.LastWriteTimeUtc)} — it was emptied recently.");
                }

                foreach (var info in infoFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    RecycleBinEntry entry;
                    try { entry = RecycleBinParser.Parse(SafeFile.ReadAllBytesShared(info, 1 << 16)); }
                    catch (Exception e) when (e is FormatException or IOException or OverflowException) { continue; }
                    string rName = "$R" + Path.GetFileName(info)[2..];
                    bool contentPresent = File.Exists(Path.Combine(sidDir, rName)) || Directory.Exists(Path.Combine(sidDir, rName));
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.RecycleBin, Kind = EvidenceKind.Recycled,
                        Path = ctx.Paths.Normalize(entry.OriginalPath), TimeUtc = entry.DeletedUtc, Origin = user,
                        Detail = $"Moved to Recycle Bin by {user}; {entry.Size:N0} bytes; stored as {rName}" +
                                 (contentPresent ? "" : " (content already removed)"),
                    });
                    items++;
                }
            }
        }
        return items;
    }
}
