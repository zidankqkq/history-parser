using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;
using RegistryHive = HistoryParser.Core.Parsers.RegistryHive;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// BAM entries that were deleted, read back from the SYSTEM registry file on disk (administrator only: Windows keeps
/// the file locked, so it is read from the volume like Amcache.hve).
/// <para>
/// Two things in that file outlive a deletion. The file is only brought up to date now and then, so an entry deleted
/// since is still in it as an ordinary value while the registry itself no longer has it. And once the file has caught
/// up, the deleted value's bytes stay in freed space until that space is used again.
/// </para>
/// </summary>
public sealed class BamDeletedCollector : ICollector
{
    public string Name => "BAM deleted entries";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\config\SYSTEM");
        RegistryHive hive;
        try { hive = new RegistryHive(LockedFile.Read(path)); }
        catch (UnauthorizedAccessException)
        {
            // Said here as well as in the source list: "no deleted entries" must never be read into a file nobody opened.
            ctx.Check("BAM", "Deleted BAM entries", CheckState.Unknown, "The registry file could not be read - run as administrator to look for deleted entries.");
            throw;
        }

        var found = BamRecovery.Find(hive, BamRecovery.LiveHas, ctx.NowUtc, ctx.BootUtc, device => OnDisk(ctx.Paths.Normalize(device)), ct);
        foreach (var e in found.Deleted)
        {
            string? user = e.Sid != null ? WinApi.SidToName(e.Sid) : null;
            ctx.Add(new Evidence
            {
                Source = e.Service == "dam" ? EvidenceSource.Dam : EvidenceSource.Bam, Kind = EvidenceKind.Execution,
                Path = ctx.Paths.Normalize(e.DevicePath), TimeUtc = e.TimeUtc, Origin = user ?? "user not recoverable",
                Detail = BamRecovery.Mark + (e.FromFreeSpace ? BamRecovery.FromFreeSpace : BamRecovery.FromStaleFile) +
                         (user != null ? $": last execution for {user}" : ": last execution (whose entry it was cannot be recovered)"),
            });
        }

        bool thisBoot = found.Deleted.Any(e => e.TimeUtc >= ctx.BootUtc);
        int n = found.Deleted.Count;
        ctx.Check("BAM", "Deleted BAM entries", n == 0 ? CheckState.Ok : thisBoot ? CheckState.Bad : CheckState.Warning,
            $"Registry file read: {found.OnDisk:N0} entries in it, {found.FreeCells:N0} freed cells ({found.FreeBytes / 1024:N0} KB) searched. " +
            (n == 0 ? "No deleted entry that Windows' own clean-up does not explain." : $"{n} deleted entr{(n == 1 ? "y" : "ies")} recovered that Windows' own clean-up does not explain.") +
            (found.Old > 0 ? $" {found.Old} older than 7 days, which Windows removes itself." : "") +
            (found.ProgramGone > 0 ? $" {found.ProgramGone} of programs that were gone before the last boot, which Windows removes itself too." : "") +
            (found.ListedAgain > 0 ? $" {found.ListedAgain} of programs BAM lists now, not counted." : ""));
        return n;
    }

    /// <summary>Is the file there now? False for a path on a drive that is not connected: then nothing can be said for it.</summary>
    static bool OnDisk(string path)
    {
        if (!(path.Length > 3 && path[1] == ':') && !Volumes.IsVolumePath(path)) return false;
        try { return File.Exists(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return false; }
    }
}

/// <summary>Finds deleted BAM / DAM entries in a SYSTEM registry file. No disk or registry access of its own, so it can be tested on any hive.</summary>
public static class BamRecovery
{
    /// <summary>Starts the detail of every recovered entry; <see cref="IsDeleted"/> goes by it.</summary>
    public const string Mark = "Deleted BAM entry";
    internal const string FromFreeSpace = ", read from freed space in the registry file";
    internal const string FromStaleFile = ", still in the registry file on disk but gone from the registry";

    public static bool IsDeleted(Evidence e) =>
        e.Source is EvidenceSource.Bam or EvidenceSource.Dam && e.Detail.StartsWith(Mark, StringComparison.Ordinal);

    /// <summary>How the entry was recovered, for a sentence: "read from freed space in the registry file".</summary>
    public static string How(Evidence e) => e.Detail.Contains(FromFreeSpace, StringComparison.Ordinal) ? FromFreeSpace[2..] : FromStaleFile[2..];

    /// <summary>
    /// What Windows removes from BAM by itself, when it starts: entries of programs not run for 7 days, and entries of
    /// programs whose file is gone. An entry is reported only when neither can be the reason:
    /// <list type="bullet">
    /// <item>it is from a run since the last boot - no start-up has happened since to clean anything; or</item>
    /// <item>it is younger than 7 days and its program's file is still on disk.</item>
    /// </list>
    /// </summary>
    public static readonly TimeSpan CleanUpAge = TimeSpan.FromDays(7);

    static readonly DateTime Earliest = new(2015, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    static readonly string[] Services = ["bam", "dam"];
    static readonly string[] Layouts = [@"State\UserSettings", "UserSettings"];

    /// <param name="Sid">Whose entry it was; null for one read from freed space, which no longer says.</param>
    public sealed record Entry(string Service, string? Sid, string DevicePath, DateTime TimeUtc, bool FromFreeSpace);

    /// <param name="Old">Deleted entries older than <see cref="CleanUpAge"/>: Windows' own clean-up explains them.</param>
    /// <param name="ProgramGone">Deleted entries from before the last boot whose program is not on disk: Windows drops those when it starts.</param>
    /// <param name="ListedAgain">Freed entries of programs BAM lists now. Not reported: nothing shows the old entry was removed by a person.</param>
    public sealed record Result(List<Entry> Deleted, int Old, int ProgramGone, int ListedAgain, int OnDisk, int FreeCells, long FreeBytes);

    /// <summary>Is the entry in the registry now? Service and SID are null for an entry whose key is not known: then any key counts.</summary>
    public delegate bool LiveLookup(string? service, string? sid, string name);

    /// <param name="fileExists">Whether the program an entry names (a device path) is on disk now.</param>
    public static Result Find(RegistryHive hive, LiveLookup liveHas, DateTime nowUtc, DateTime bootUtc, Func<string, bool> fileExists,
        CancellationToken ct = default)
    {
        var deleted = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        int old = 0, gone = 0, again = 0, onDisk = 0;

        void Judge(Entry e)
        {
            if (nowUtc - e.TimeUtc >= CleanUpAge) { old++; return; }
            if (e.TimeUtc < bootUtc && !fileExists(e.DevicePath)) { gone++; return; }
            if (!deleted.TryGetValue(e.DevicePath, out var seen) || e.TimeUtc > seen.TimeUtc) deleted[e.DevicePath] = e;
        }

        // 1. Entries the file still holds as ordinary values. The registry is checked for each one at this moment, after
        //    the file was read: the registry is never behind its file, so one that is missing was deleted.
        string set = CurrentControlSet(hive);
        var inFile = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in Services)
            foreach (var layout in Layouts)
            {
                if (hive.Root.Path($@"{set}\Services\{service}\{layout}") is not { } users) continue;
                foreach (var user in users.Subkeys())
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (var (name, value) in user.Values())
                    {
                        if (!IsEntryName(name) || value is not byte[] data || TimeOf(data, nowUtc) is not { } time) continue;
                        onDisk++;
                        if (liveHas(service, user.Name, name)) continue;
                        inFile.Add(name);
                        Judge(new Entry(service, user.Name, name, time, false));
                    }
                }
            }

        // 2. Entries in freed space. A freed value no longer says which key it was under, so it is told by its shape: a
        //    device path for a name and a small binary value that starts with a believable time.
        var freed = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in hive.FreedValues(IsEntryName))
        {
            ct.ThrowIfCancellationRequested();
            if (v.Type != 3 || TimeOf(v.Data, nowUtc) is not { } time) continue;
            if (!freed.TryGetValue(v.Name, out var seen) || time > seen) freed[v.Name] = time;
        }
        foreach (var (name, time) in freed)
        {
            if (inFile.Contains(name)) continue;
            if (liveHas(null, null, name)) { again++; continue; }
            Judge(new Entry("bam", null, name, time, true));
        }

        return new Result(deleted.Values.OrderByDescending(e => e.TimeUtc).ToList(), old, gone, again, onDisk, hive.FreeSpace.Cells, hive.FreeSpace.Bytes);
    }

    static bool IsEntryName(string name) => name.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) && name.Length > 12;

    /// <summary>
    /// The entry's time, or null when the bytes are not a BAM value: the wrong size, or a time no BAM entry could carry
    /// (which is what a freed value's data looks like once its cell has been used for something else).
    /// </summary>
    static DateTime? TimeOf(byte[] data, DateTime nowUtc)
    {
        if (data.Length is < 8 or > 64) return null;
        return FileTime.ToUtc(BitConverter.ToInt64(data, 0)) is { } t && t >= Earliest && t <= nowUtc.AddDays(1) ? t : null;
    }

    /// <summary>The control set Windows is running from, as the Select key names it.</summary>
    static string CurrentControlSet(RegistryHive hive)
    {
        var current = hive.Root.Subkey("Select")?.Values().GetValueOrDefault("Current");
        return current is uint n and > 0 and < 1000 ? $"ControlSet{n:D3}" : "ControlSet001";
    }

    /// <summary>The registry as it is now.</summary>
    internal static bool LiveHas(string? service, string? sid, string name)
    {
        foreach (var s in service != null ? [service] : Services)
            foreach (var layout in Layouts)
            {
                using var users = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{s}\{layout}");
                if (users == null) continue;
                foreach (var user in sid != null ? [sid] : users.GetSubKeyNames())
                {
                    using var key = users.OpenSubKey(user);
                    if (key?.GetValue(name) != null) return true;
                }
            }
        return false;
    }
}
