using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// NTFS change journal on every fixed NTFS drive. Gives creations, deletions, renames and
/// timestamp changes of executables/jars/prefetch files, and — because records are numbered in
/// strict order — reveals the clock being moved backwards.
/// </summary>
public sealed class UsnJournalCollector : ICollector
{
    public string Name => "USN Journal";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        if (!ctx.Options.ReadUsnJournal) return 0;
        int items = 0;
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType != DriveType.Fixed || !drive.IsReady || drive.DriveFormat != "NTFS") continue;
            items += ReadVolume(ctx, drive.Name[..2], ct);
        }
        return items;
    }

    sealed record DirEntry(ulong Parent, string Name);

    int ReadVolume(ScanContext ctx, string letter, CancellationToken ct)
    {
        using var volume = CreateFile($@"\\.\{letter}", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (volume.IsInvalid)
            throw new UnauthorizedAccessException($"Cannot open volume {letter} (run as administrator).");

        var journalData = new byte[80];
        if (!DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, null, 0, journalData, journalData.Length, out _, IntPtr.Zero))
        {
            int err = Marshal.GetLastWin32Error();
            if (err is ERROR_JOURNAL_NOT_ACTIVE or ERROR_JOURNAL_DELETE_IN_PROGRESS)
            {
                string what = err == ERROR_JOURNAL_NOT_ACTIVE ? "disabled" : "being deleted right now";
                // Windows always runs the journal on its own drive; on other drives it is only switched on once
                // something (Search, OneDrive, backup) needs it, so an inactive one there is normal.
                bool system = IsSystemDrive(letter) || err == ERROR_JOURNAL_DELETE_IN_PROGRESS;
                ctx.Check("USN Journal", $"Change journal {letter}", system ? CheckState.Bad : CheckState.Warning, $"The USN journal is {what}.");
                ctx.Flag(system ? Severity.High : Severity.Low, FindingCategory.AntiForensics, $"USN journal {what} on {letter}",
                    system
                        ? "Windows keeps the change journal on by default. Turning it off or deleting it " +
                          "(fsutil usn deletejournal) erases the record of file deletions and renames."
                        : "This is not the Windows drive. Windows only turns the journal on for extra drives when something needs it, " +
                          "so this can be normal, but it also means file deletions on this drive are not recorded.");
                return 0;
            }
            throw new Win32Exception(err);
        }

        ulong journalId = BitConverter.ToUInt64(journalData, 0);
        long firstUsn = BitConverter.ToInt64(journalData, 8);
        long nextUsn = BitConverter.ToInt64(journalData, 16);
        ulong maxSize = BitConverter.ToUInt64(journalData, 40);

        var dirs = EnumerateDirectories(volume, nextUsn, ct);
        var pathCache = new Dictionary<ulong, string?>();
        string? ResolveDir(ulong frn)
        {
            if (pathCache.TryGetValue(frn, out var cached)) return cached;
            var parts = new List<string>();
            ulong cur = frn;
            string? result = null;
            for (int guard = 0; guard < 512; guard++)
            {
                if ((cur & 0x0000FFFFFFFFFFFF) == 5) { parts.Reverse(); result = letter + "\\" + string.Join('\\', parts); break; }
                if (!dirs.TryGetValue(cur, out var d)) break;
                parts.Add(d.Name);
                cur = d.Parent;
            }
            if (result != null && result.EndsWith('\\')) result = result.TrimEnd('\\');
            pathCache[frn] = result;
            return result;
        }

        string FullPath(ulong parent, string name)
        {
            var dir = ResolveDir(parent);
            return dir != null ? $"{dir}\\{name}" : $"?\\{name}";
        }

        var order = new ClockOrderTracker(ctx.Options.Tolerance);
        var renameOld = new Dictionary<ulong, string>();
        int items = 0, records = 0, futureRecords = 0;
        DateTime? firstFuture = null;
        var futureLimit = ctx.NowUtc.AddMinutes(5).ToFileTimeUtc();
        var pfDeletes = new List<PfDelete>();
        var pfCreates = new List<DateTime>();
        var pfLastActive = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        var recentDeletes = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        var hardLinks = new List<(string Path, DateTime? Time)>();

        var input = new byte[40];
        var output = new byte[1 << 20];
        long start = firstUsn;
        while (start < nextUsn)
        {
            ct.ThrowIfCancellationRequested();
            BitConverter.GetBytes(start).CopyTo(input, 0);
            BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(input, 8);   // reason mask: everything
            BitConverter.GetBytes(0u).CopyTo(input, 12);           // return only on close: no
            BitConverter.GetBytes(0UL).CopyTo(input, 16);          // timeout
            BitConverter.GetBytes(0UL).CopyTo(input, 24);          // bytes to wait for: return immediately
            BitConverter.GetBytes(journalId).CopyTo(input, 32);
            if (!DeviceIoControl(volume, FSCTL_READ_USN_JOURNAL, input, input.Length, output, output.Length,
                    out int returned, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_JOURNAL_ENTRY_DELETED) break; // the oldest records were overwritten while reading
                throw new Win32Exception(err);
            }
            if (returned <= 8) break;
            long next = BitConverter.ToInt64(output, 0);

            UsnParser.ParseBuffer(output.AsSpan(0, returned), (in UsnRecord r) =>
            {
                records++;
                order.Observe(r.TimeStamp);
                if (r.TimeStamp > futureLimit)
                {
                    futureRecords++;
                    firstFuture ??= FileTime.ToUtc(r.TimeStamp);
                }

                if (r.IsDirectory)
                {
                    if (!dirs.ContainsKey(r.FileRef)) dirs[r.FileRef] = new DirEntry(r.ParentRef, r.Name.ToString());
                    return;
                }

                bool artifacts = ctx.Options.IncludeArtifactFiles;
                bool interesting = FileTypes.IsInteresting(r.Name) || (artifacts && FileTypes.IsArtifact(r.Name));
                var reason = r.Reason;

                if ((reason & UsnReason.RenameOldName) != 0)
                {
                    renameOld[r.FileRef] = FullPath(r.ParentRef, r.Name.ToString());
                    return;
                }

                if ((reason & UsnReason.Close) == 0) return;

                string? oldPath = null;
                if ((reason & UsnReason.RenameNewName) != 0 && renameOld.Remove(r.FileRef, out var o)) oldPath = o;
                bool oldInteresting = oldPath != null && (FileTypes.IsInteresting(oldPath) || (artifacts && FileTypes.IsArtifact(Path.GetFileName(oldPath))));
                if (!interesting && !oldInteresting) return;

                var time = FileTime.ToUtc(r.TimeStamp);
                long usn = r.Usn; // ref structs cannot be captured by the local function below
                string path = FullPath(r.ParentRef, r.Name.ToString());

                void Emit(EvidenceKind kind, string p, string detail, string? related = null)
                {
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.UsnJournal, Kind = kind, Path = p, TimeUtc = time,
                        Origin = $"{letter} USN {usn}", Detail = detail, RelatedPath = related,
                    });
                    items++;
                }

                if (oldPath != null)
                {
                    Emit(EvidenceKind.Renamed, oldPath, $"Renamed to {path}", path);
                    if (interesting) Emit(EvidenceKind.Renamed, path, $"Renamed from {oldPath}", oldPath);
                    // Explorer's "Replace the file in the destination" (and many updaters): the old file is deleted and
                    // the new one is moved onto its name seconds later.
                    if (interesting && recentDeletes.Remove(path, out var gone) && time is { } moved && moved - gone is { } gap &&
                        gap >= TimeSpan.Zero && gap <= TimeSpan.FromSeconds(10))
                        Emit(EvidenceKind.Modified, path, $"Replaced: the old file was deleted and {Path.GetFileName(oldPath)} was moved onto its name " +
                                                          $"{gap.TotalSeconds:0} s later (how Explorer's \"Replace the file\" swaps a file)", oldPath);
                }
                if (!interesting) return;

                bool created = (reason & UsnReason.FileCreate) != 0;
                bool deleted = (reason & UsnReason.FileDelete) != 0;
                if (deleted && time is { } dt) recentDeletes[path] = dt;
                // A second name for the same file: run under a harmless-looking name, Prefetch and BAM record that name.
                if ((reason & UsnReason.HardLinkChange) != 0 && !deleted && !FileTypes.IsWindowsFile(path))
                {
                    Emit(EvidenceKind.HardLinked, path, "Hard link added or removed: this name is (or was) a second name for another file");
                    if (FileTypes.FromPath(path) is FileType.Exe or FileType.Dll or FileType.Jar or FileType.Script) hardLinks.Add((path, time));
                }
                if (created) Emit(EvidenceKind.Created, path, "File created");
                // Prefetch bookkeeping: when each .pf was last written, and how many appeared, to judge deletions later.
                if (path.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) && !deleted && time is { } pt)
                {
                    pfLastActive[r.Name.ToString()] = pt;
                    if (created) pfCreates.Add(pt);
                }
                if (deleted)
                {
                    Emit(EvidenceKind.Deleted, path, "File deleted");
                    if (path.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) && time is { } t)
                        pfDeletes.Add(new PfDelete(r.Name.ToString(), t, pfLastActive.TryGetValue(r.Name.ToString(), out var la) ? la : null));
                }
                if (!created && !deleted)
                {
                    if ((reason & (UsnReason.DataOverwrite | UsnReason.DataExtend | UsnReason.DataTruncation)) != 0)
                        Emit(EvidenceKind.Modified, path, ContentChange(reason));
                    if ((reason & UsnReason.BasicInfoChange) != 0)
                        Emit(EvidenceKind.TimestampChanged, path, "Attributes or timestamps changed");
                }
            });

            if (next <= start) break;
            start = next;
        }

        ReportJournal(ctx, letter, journalId, maxSize, order, records, futureRecords, firstFuture);
        ReportPrefetchDeletes(ctx, letter, pfDeletes, pfCreates, order.Earliest);
        ReportHardLinks(ctx, letter, hardLinks);
        return items;
    }

    /// <summary>
    /// How the contents were replaced, from the reasons the journal collected for one open/close of the file:
    /// overwriting with copy also re-applies permissions; type / a redirect / a program rewriting it only empties and refills it.
    /// </summary>
    internal static string ContentChange(UsnReason reason)
    {
        if ((reason & UsnReason.DataTruncation) == 0) return "File contents changed";
        if ((reason & UsnReason.SecurityChange) != 0)
            return "Contents replaced by another file: emptied, rewritten and given new permissions (the pattern copy leaves when it overwrites a file)";
        if ((reason & (UsnReason.DataExtend | UsnReason.DataOverwrite)) != 0)
            return "Contents replaced in place: emptied, then rewritten (the pattern type a > b, a redirect, or a program rewriting the file leaves)";
        return "File emptied (cut shorter)";
    }

    static void ReportHardLinks(ScanContext ctx, string letter, List<(string Path, DateTime? Time)> links)
    {
        if (links.Count == 0) return;
        var files = links.GroupBy(l => l.Path, StringComparer.OrdinalIgnoreCase).Select(g => (Path: g.Key, Time: g.Max(l => l.Time))).OrderByDescending(l => l.Time).ToList();
        var latest = files[0].Time;
        bool thisBoot = files.Any(f => f.Time >= ctx.BootUtc);
        string list = string.Join(", ", files.Take(15).Select(f => $"{f.Path} ({Util.When.L(f.Time)})")) + (files.Count > 15 ? $" and {files.Count - 15} more" : "");
        ctx.Flag(thisBoot ? Severity.Medium : Severity.Low, FindingCategory.AntiForensics,
            files.Count == 1 ? $"Hard link made to a program: {Path.GetFileName(files[0].Path)}" : $"Hard links made to {files.Count} programs on {letter}",
            $"A hard link gives one file a second name. Run through that name, Prefetch, BAM and the other records show the second " +
            $"name instead of the real file. Outside Windows' own folders this is rare. {list}.", timeUtc: latest);
    }

    static Dictionary<ulong, DirEntry> EnumerateDirectories(SafeFileHandle volume, long highUsn, CancellationToken ct)
    {
        var dirs = new Dictionary<ulong, DirEntry>();
        var input = new byte[24];
        var output = new byte[1 << 20];
        ulong startFrn = 0;
        BitConverter.GetBytes(0L).CopyTo(input, 8);
        BitConverter.GetBytes(highUsn).CopyTo(input, 16);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            BitConverter.GetBytes(startFrn).CopyTo(input, 0);
            if (!DeviceIoControl(volume, FSCTL_ENUM_USN_DATA, input, input.Length, output, output.Length,
                    out int returned, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_HANDLE_EOF) break;
                throw new Win32Exception(err);
            }
            if (returned <= 8) break;
            UsnParser.ParseBuffer(output.AsSpan(0, returned), (in UsnRecord r) =>
            {
                if (r.IsDirectory) dirs[r.FileRef] = new DirEntry(r.ParentRef, r.Name.ToString());
            });
            ulong next = BitConverter.ToUInt64(output, 0);
            if (next == startFrn) break;
            startFrn = next;
        }
        return dirs;
    }

    static void ReportJournal(ScanContext ctx, string letter, ulong journalId, ulong maxSize, ClockOrderTracker order,
        int records, int futureRecords, DateTime? firstFuture)
    {
        // The journal ID is the FILETIME at which the journal was created.
        var created = FileTime.ToUtc((long)journalId);
        string coverage = order.Earliest is { } e ? $"covers {Util.When.L(e)} → {Util.When.L(order.Latest)}" : "is empty";
        var state = CheckState.Ok;
        string detail = $"{records:N0} records, {coverage}, max size {maxSize / (1024 * 1024)} MB" +
                        (created is { } c ? $", created {Util.When.L(c)}" : "") + ".";

        if (created is { } jc && ctx.OsInstallUtc is { } install && jc > install.AddDays(1) &&
            ctx.NowUtc - jc < TimeSpan.FromDays(30))
        {
            // A drive formatted (or first used) recently gets a brand-new journal; so does an extra drive the
            // first time something switches its journal on.
            bool system = IsSystemDrive(letter);
            DateTime? formatted = null;
            try { formatted = Directory.GetCreationTimeUtc(letter + @"\System Volume Information"); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            bool freshDrive = formatted is { } f && (jc - f).Duration() < TimeSpan.FromDays(1);
            if (!freshDrive)
            {
                state = system ? CheckState.Bad : CheckState.Warning;
                ctx.Flag(system ? Severity.High : Severity.Medium, FindingCategory.AntiForensics, $"USN journal on {letter} was recreated recently",
                    $"The journal was created {Util.When.L(jc)}, long after Windows was installed ({Util.When.L(install)}). " +
                    "This happens when someone runs \"fsutil usn deletejournal\" to wipe file history." +
                    (system ? "" : " This is not the Windows drive, where Windows can also start a journal the first time something needs one."),
                    timeUtc: jc);
            }
        }
        ctx.Check("USN Journal", $"Change journal {letter}", state, detail);

        foreach (var (before, after) in order.Rollbacks)
        {
            ctx.ClockChanges.Add(new ClockChange
            {
                Source = $"USN journal {letter}", OldTimeUtc = before, NewTimeUtc = after,
                Detail = "Consecutive journal records went backwards in time.",
            });
        }
        if (futureRecords > 0)
        {
            ctx.Flag(Severity.High, FindingCategory.ClockTampering, $"Journal records dated in the future on {letter}",
                $"{futureRecords:N0} records are dated after the current system time (first: {Util.When.L(firstFuture)}). " +
                "The clock is currently set earlier than it was when those changes happened.", timeUtc: firstFuture);
        }
    }

    static bool IsSystemDrive(string letter) =>
        string.Equals(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))?.TrimEnd('\\'), letter, StringComparison.OrdinalIgnoreCase);

    /// <summary>A deleted .pf, with when the journal last saw it written before the deletion (null = not in the journal).</summary>
    internal sealed record PfDelete(string Name, DateTime Time, DateTime? LastActive);

    /// <summary>What is known about one burst of deletions, for grading.</summary>
    internal sealed record PfBurst(int Count, TimeSpan Age, int FilesBefore, bool AllRecreated, IReadOnlyList<string> RecentlyUsed,
        bool UsageKnown, bool DuringUpdate);

    static void ReportPrefetchDeletes(ScanContext ctx, string letter, List<PfDelete> deletes, List<DateTime> creates, DateTime? journalStart)
    {
        if (deletes.Count == 0) return;
        string dir = $"{letter}\\Windows\\Prefetch";
        List<DateTime>? updates = null;
        foreach (var burst in Bursts(deletes.OrderBy(d => d.Time).ToList(), TimeSpan.FromMinutes(5)))
        {
            var start = burst[0].Time;
            // How full the folder was just before: today's count, minus files created since, plus files deleted since.
            int filesBefore = ctx.PrefetchFileCount - creates.Count(c => c >= start) + deletes.Count(d => d.Time >= start);
            // Windows removes the least-recently-used files; a cleaner takes everything, including programs used that day.
            var recent = burst.Where(d => d.LastActive is { } la && d.Time - la < TimeSpan.FromDays(1)).Select(d => d.Name).ToList();
            bool usageKnown = journalStart is { } js && js <= start - TimeSpan.FromDays(1);
            updates ??= Bypass.ServiceJudge.UpdateTimes();
            bool duringUpdate = updates.Any(u => (u - start).Duration() < TimeSpan.FromHours(2));
            var info = new PfBurst(burst.Count, ctx.NowUtc - start, filesBefore, burst.All(b => File.Exists(Path.Combine(dir, b.Name))),
                recent, usageKnown, duringUpdate);
            var (severity, note) = GradePrefetchBurst(info);
            var names = string.Join(", ", burst.Select(b => b.Name).Take(25)) + (burst.Count > 25 ? $" and {burst.Count - 25} more" : "");
            ctx.Flag(severity, FindingCategory.Deletion,
                burst.Count == 1 ? $"Prefetch file deleted: {burst[0].Name}" : $"{burst.Count} prefetch files deleted",
                $"Deleted from {dir} at {Util.When.L(start)}: {names}. {note}", timeUtc: start);
        }
    }

    /// <summary>
    /// Windows deletes prefetch files on its own: when the folder reaches its limit (about 1024 files) it
    /// removes a large batch of the least-recently-used ones, its maintenance drops stale entries, and
    /// updates clear some. A cleaner looks different: it also removes files of programs used that day.
    /// </summary>
    internal static (Severity Severity, string Note) GradePrefetchBurst(PfBurst b)
    {
        const string housekeeping = "Windows removes prefetch files by itself from time to time, so on its own this is weak evidence.";
        string recentList = string.Join(", ", b.RecentlyUsed.Take(15)) + (b.RecentlyUsed.Count > 15 ? " …" : "");
        if (b.AllRecreated)
            return (Severity.Low, "A file with the same name exists again now, so it was rewritten. Windows does this, but so does " +
                                  "someone deleting it and running the program again to reset its run history.");
        if (b.FilesBefore >= 950)
            return (Severity.Low, $"The folder held about {b.FilesBefore} files just before, at Windows' limit of about 1024, so Windows " +
                                  "trimmed the oldest ones itself." + (b.RecentlyUsed.Count > 0 ? $" Programs used in the day before among them: {recentList}." : ""));
        if (b.DuringUpdate && b.RecentlyUsed.Count == 0)
            return (Severity.Low, "A Windows update was being installed around then, and the deleted files were not in recent use. " + housekeeping);
        if (b.Count >= 5)
        {
            if (b.RecentlyUsed.Count > 0)
                return (b.Age < TimeSpan.FromDays(7) ? Severity.High : Severity.Medium,
                    $"The batch includes prefetch files of programs used in the day before ({recentList}). Windows' own cleanup removes " +
                    "old, unused entries; removing recently used ones is what cleaners and manual deletion do.");
            if (b.UsageKnown)
                return (Severity.Low, "None of the deleted files had been used in the day before, which matches Windows' cleanup of old " +
                                      "entries rather than a cleaner. " + housekeeping);
            return (Severity.Medium, "The change journal does not go back far enough to tell whether these were old entries (Windows' " +
                                     "cleanup) or recently used ones (a cleaner).");
        }
        if (b.RecentlyUsed.Count > 0 && b.Age < TimeSpan.FromHours(24))
            return (Severity.Medium, $"It belonged to a program used shortly before ({recentList}) and was deleted shortly before the scan. " + housekeeping);
        return (Severity.Low, housekeeping);
    }

    internal static List<List<PfDelete>> Bursts(List<PfDelete> sorted, TimeSpan gap)
    {
        var result = new List<List<PfDelete>>();
        foreach (var d in sorted)
        {
            if (result.Count == 0 || d.Time - result[^1][^1].Time > gap) result.Add(new());
            result[^1].Add(d);
        }
        return result;
    }
}
