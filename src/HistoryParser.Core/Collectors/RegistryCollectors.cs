using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Background Activity Moderator (and its desktop sibling DAM): last execution time of every
/// executable, per user, recorded by a kernel driver — including programs started by other programs.
/// </summary>
public sealed class BamCollector : ICollector
{
    public string Name => "BAM / DAM";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        bool anyKey = false;
        foreach (var (service, source) in new[] { ("bam", EvidenceSource.Bam), ("dam", EvidenceSource.Dam) })
        {
            foreach (var sub in new[] { $@"SYSTEM\CurrentControlSet\Services\{service}\State\UserSettings",
                                        $@"SYSTEM\CurrentControlSet\Services\{service}\UserSettings" })
            {
                using var root = Registry.LocalMachine.OpenSubKey(sub);
                if (root == null) continue;
                anyKey = true;
                foreach (var sid in root.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var userKey = root.OpenSubKey(sid);
                    if (userKey == null) continue;
                    string user = WinApi.SidToName(sid);
                    DateTime? newest = null;
                    foreach (var valueName in userKey.GetValueNames())
                    {
                        if (valueName is "Version" or "SequenceNumber") continue;
                        if (!valueName.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) continue;
                        if (userKey.GetValue(valueName) is not byte[] data) continue;
                        var time = BamParser.Parse(data);
                        if (time > newest || newest == null) newest = time;
                        ctx.Add(new Evidence
                        {
                            Source = source, Kind = time.HasValue ? EvidenceKind.Execution : EvidenceKind.Presence,
                            Path = ctx.Paths.Normalize(valueName), TimeUtc = time, Origin = user,
                            Detail = $"Last execution for {user}",
                        });
                        items++;
                    }

                    // Deleting a value updates the key's write time; normally it equals the newest entry.
                    var keyWritten = WinApi.GetKeyLastWriteUtc(userKey);
                    if (source == EvidenceSource.Bam && keyWritten is { } kw && newest is { } nw &&
                        kw - nw > TimeSpan.FromMinutes(10) && kw > ctx.BootUtc.AddMinutes(5))
                    {
                        ctx.Flag(Severity.Low, FindingCategory.AntiForensics, "BAM key changed after its newest entry",
                            $"The BAM key for {user} was modified at {Util.When.L(kw)}, but its newest entry is from {Util.When.L(nw)}. " +
                            "Entries may have been deleted (BAM also prunes entries older than 7 days at boot).",
                            timeUtc: kw);
                    }
                }
            }
        }
        if (!anyKey)
            ctx.Check("BAM", "BAM registry data", CheckState.Warning, "No BAM UserSettings key found.");
        return items;
    }
}

/// <summary>UserAssist: programs and shortcuts launched through Explorer, with run counts (ROT13 names).</summary>
public sealed class UserAssistCollector : ICollector
{
    public string Name => "UserAssist";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var sid in WinApi.LoadedUserSids())
        {
            using var ua = Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua == null) continue;
            string user = WinApi.SidToName(sid);
            foreach (var guid in ua.GetSubKeyNames())
            {
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count == null) continue;
                foreach (var valueName in count.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    if (count.GetValue(valueName) is not byte[] data) continue;
                    var entry = UserAssistParser.Parse(valueName, data);
                    if (entry == null || !entry.Path.Contains('\\')) continue;
                    var path = ctx.Paths.Normalize(entry.Path);
                    if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        !path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) &&
                        !path.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.UserAssist,
                        Kind = entry.LastRunUtc.HasValue ? EvidenceKind.Execution : EvidenceKind.Presence,
                        Path = path, TimeUtc = entry.LastRunUtc, RunCount = entry.RunCount, Origin = user,
                        Detail = $"Launched via Explorer by {user}, run count {entry.RunCount}",
                    });
                    items++;
                }
            }
        }
        return items;
    }
}

/// <summary>
/// ShimCache / AppCompatCache. On Windows 10+ an entry proves the file existed and was looked at
/// by the loader; it does not prove execution. It also stores the file's last-modified time.
/// </summary>
public sealed class ShimCacheCollector : ICollector
{
    public string Name => "ShimCache";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
        if (key?.GetValue("AppCompatCache") is not byte[] data) return 0;
        int items = 0;
        foreach (var e in ShimCacheParser.Parse(data))
        {
            ct.ThrowIfCancellationRequested();
            ctx.Add(new Evidence
            {
                Source = EvidenceSource.ShimCache, Kind = EvidenceKind.Presence, Path = ctx.Paths.Normalize(e.Path),
                FileModifiedUtc = e.LastModifiedUtc,
                Detail = $"Cache position #{e.Position + 1}, file last-modified {Util.When.L(e.LastModifiedUtc)} (written to the registry at shutdown)",
            });
            items++;
        }
        return items;
    }
}

/// <summary>MuiCache: friendly names of programs a user has run (no timestamp).</summary>
public sealed class MuiCacheCollector : ICollector
{
    public string Name => "MuiCache";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var sid in WinApi.LoadedUserSids())
        {
            using var key = Registry.Users.OpenSubKey(
                $@"{sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
            if (key == null) continue;
            string user = WinApi.SidToName(sid);
            foreach (var valueName in key.GetValueNames())
            {
                int dot = valueName.LastIndexOf('.');
                if (dot <= 0) continue;
                var path = valueName[..dot];
                if (!path.Contains(":\\") || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.MuiCache, Kind = EvidenceKind.Presence, Path = ctx.Paths.Normalize(path),
                    Origin = user, Detail = $"Run by {user} at some point: \"{key.GetValue(valueName)}\"",
                });
                items++;
            }
        }
        return items;
    }
}
