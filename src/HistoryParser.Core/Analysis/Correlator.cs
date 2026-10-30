using HistoryParser.Core.Models;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Analysis;

/// <summary>
/// Merges evidence from every source into one record per file, works out whether the file still
/// exists, and cross-checks the timestamps the sources give for the same file against each other
/// and against detected clock changes.
/// <para>
/// Rules are written as "leads": each finding says what was seen and why it matters, so staff can
/// judge it. Only conditions that cannot happen on an untouched machine are rated High.
/// </para>
/// </summary>
public sealed class Correlator
{
    readonly DateTime _now;
    readonly TimeSpan _tol;
    readonly IReadOnlyList<ClockChange> _clockChanges;
    readonly HashSet<string> _runningNames;
    readonly Func<string, bool> _fileExists;
    readonly Func<string, bool> _driveExists;
    readonly Func<string, DateTime?> _lastWrite;

    public Correlator(DateTime nowUtc, TimeSpan tolerance, IReadOnlyList<ClockChange> clockChanges,
        IEnumerable<string> runningProcessNames, Func<string, bool>? fileExists = null,
        Func<string, bool>? driveExists = null, Func<string, DateTime?>? lastWriteUtc = null)
    {
        _now = nowUtc;
        _tol = tolerance;
        _clockChanges = clockChanges;
        _runningNames = new HashSet<string>(runningProcessNames, StringComparer.OrdinalIgnoreCase);
        _fileExists = fileExists ?? (p => File.Exists(p) || Directory.Exists(p));
        _driveExists = driveExists ?? (p => Directory.Exists(Path.GetPathRoot(p)));
        _lastWrite = lastWriteUtc ?? (p => File.Exists(p) ? File.GetLastWriteTimeUtc(p) : null);
    }

    public List<FileRecord> Build(IEnumerable<Evidence> evidence)
    {
        var groups = new Dictionary<string, List<Evidence>>(StringComparer.Ordinal);
        var unresolved = new List<Evidence>();
        foreach (var e in evidence)
        {
            if (string.IsNullOrEmpty(e.Path) || e.Path[0] == '[') continue;
            if (e.Path.StartsWith(@"?\", StringComparison.Ordinal)) { unresolved.Add(e); continue; }
            var key = PathNormalizer.Key(e.Path);
            if (!groups.TryGetValue(key, out var list)) groups[key] = list = new List<Evidence>();
            list.Add(e);
        }

        // Evidence with only a file name (USN records in deleted folders, DPS strings) joins a
        // record by name when exactly one record has that name; otherwise it stays on its own.
        var byName = groups.Keys.GroupBy(k => Path.GetFileName(k)).ToDictionary(g => g.Key, g => g.ToList());
        foreach (var e in unresolved)
        {
            var nameKey = PathNormalizer.Key(e.Path[2..]);
            if (byName.TryGetValue(nameKey, out var keys) && keys.Count == 1)
                groups[keys[0]].Add(e with { Detail = e.Detail + " (matched by file name only)" });
            else
            {
                var key = PathNormalizer.Key(e.Path);
                if (!groups.TryGetValue(key, out var list)) groups[key] = list = new List<Evidence>();
                list.Add(e);
            }
        }

        var records = new List<FileRecord>(groups.Count);
        foreach (var (_, items) in groups)
        {
            var record = CreateRecord(items);
            Analyze(record);
            records.Add(record);
        }
        return records;
    }

    static FileRecord CreateRecord(List<Evidence> items)
    {
        // Prefer a mixed-case spelling for display (Prefetch paths are all upper case).
        var display = items.Select(e => e.Path).FirstOrDefault(p => p.Any(char.IsLower)) ?? items[0].Path;
        var r = new FileRecord { Path = display, Name = Path.GetFileName(display) };
        r.Evidence.AddRange(items.OrderByDescending(e => e.TimeUtc ?? DateTime.MinValue));
        // A file whose content shows it is something else (a jar named .png) is listed as what it really is.
        r.Type = items.Select(e => e.ActualType).FirstOrDefault(t => t != null) ?? FileTypes.FromPath(display);
        r.IsWindowsFile = FileTypes.IsWindowsFile(display);

        var runs = items.Where(e => e.Kind is EvidenceKind.Execution or EvidenceKind.LoadedModule && e.TimeUtc.HasValue).ToList();
        r.LastExecutionUtc = runs.Count > 0 ? runs.Max(e => e.TimeUtc) : null;
        r.LastActivityUtc = items.Where(e => e.TimeUtc.HasValue).Select(e => e.TimeUtc).DefaultIfEmpty(null).Max();
        r.WasExecutedDirectly = items.Any(e => e.Kind == EvidenceKind.Execution);
        r.WasLoaded = items.Any(e => e.Kind == EvidenceKind.LoadedModule);
        var counts = items.Where(e => e.RunCount.HasValue && e.Source is EvidenceSource.Prefetch).Select(e => e.RunCount!.Value).ToList();
        r.RunCount = counts.Count > 0 ? counts.Max() : null;
        return r;
    }

    void Analyze(FileRecord r)
    {
        ResolveStatus(r);
        CheckFutureTimes(r);
        CheckDeletionOrder(r);
        CheckReplacement(r);
        CheckBamAgainstPrefetch(r);
        CheckLaunchesAgainstPrefetch(r);
        CheckClockChanges(r);
        CheckShimCacheModified(r);
    }

    // ---------------------------------------------------------------------------------------

    void ResolveStatus(FileRecord r)
    {
        bool rooted = r.Path.Length >= 3 && r.Path[1] == ':' && r.Path[2] == '\\';
        var deleted = r.Evidence.Where(e => e.Kind == EvidenceKind.Deleted && e.TimeUtc.HasValue).MaxBy(e => e.TimeUtc);
        var recycled = r.Evidence.Where(e => e.Kind == EvidenceKind.Recycled).MaxBy(e => e.TimeUtc);
        var renamedAway = r.Evidence.Where(e => e.Kind == EvidenceKind.Renamed && e.Detail.StartsWith("Renamed to"))
            .MaxBy(e => e.TimeUtc);

        if (rooted && _fileExists(r.Path))
        {
            r.Status = FileStatus.Exists;
            r.StatusDetail = "File is present";
        }
        else if (recycled != null)
        {
            r.Status = FileStatus.InRecycleBin;
            r.DeletedUtc = recycled.TimeUtc;
            r.StatusDetail = $"In the Recycle Bin since {Util.When.L(recycled.TimeUtc)}";
        }
        else if (deleted != null && (renamedAway == null || deleted.TimeUtc >= renamedAway.TimeUtc))
        {
            r.Status = FileStatus.Deleted;
            r.DeletedUtc = deleted.TimeUtc;
            r.StatusDetail = $"Deleted {Util.When.L(deleted.TimeUtc)}";
        }
        else if (renamedAway != null)
        {
            r.Status = FileStatus.Renamed;
            r.DeletedUtc = renamedAway.TimeUtc;
            r.StatusDetail = $"Renamed to {renamedAway.RelatedPath} at {Util.When.L(renamedAway.TimeUtc)}";
        }
        else if (rooted && !_driveExists(r.Path))
        {
            r.Status = FileStatus.DriveNotConnected;
            r.StatusDetail = $"Drive {r.Path[..2]} is not connected (USB stick or unmounted volume?)";
        }
        else if (rooted)
        {
            r.Status = FileStatus.Missing;
            r.StatusDetail = "Not present, and no deletion record (journal rolled over, or removed another way)";
        }
        else
        {
            r.Status = FileStatus.Unknown;
            r.StatusDetail = "Full path unknown";
        }
    }

    void CheckFutureTimes(FileRecord r)
    {
        var future = r.Evidence.Where(e => e.TimeUtc > _now + TimeSpan.FromMinutes(5)).MaxBy(e => e.TimeUtc);
        if (future == null) return;
        Add(r, Severity.High, FindingCategory.ClockTampering, "Timestamp in the future",
            $"{Display.Source(future.Source)} records {Util.When.L(future.TimeUtc)} for this file, which is later than the current system time " +
            $"({Util.When.L(_now)}). The clock was moved back after that.", future.TimeUtc);
    }

    void CheckDeletionOrder(FileRecord r)
    {
        if (r.Status is not (FileStatus.Deleted or FileStatus.InRecycleBin or FileStatus.Renamed) || r.DeletedUtc is not { } gone)
            return;
        var lastRun = LastRunEvidence(r);
        if (lastRun == null) return;

        var recreated = r.Evidence.Any(e => e.Kind is EvidenceKind.Created && e.TimeUtc > gone);
        string verb = r.Status switch { FileStatus.Renamed => "renamed", FileStatus.InRecycleBin => "recycled", _ => "deleted" };

        // Only a real execution time can make the order impossible: a "loaded" time is just the
        // loader's latest run, and the module may have been loaded on an earlier one.
        // BAM/DAM stamp when the process ended, and updaters rename a program while it is still running
        // (Discord.exe.old, old_chrome.exe), so for a rename only a start time makes the order impossible.
        bool endTime = lastRun.Source is EvidenceSource.Bam or EvidenceSource.Dam or EvidenceSource.CrashReport;
        if (lastRun.Kind == EvidenceKind.Execution && lastRun.TimeUtc > gone + _tol && !recreated &&
            !(endTime && r.Status == FileStatus.Renamed))
        {
            Add(r, Severity.High, FindingCategory.ClockTampering, $"Run recorded after the file was {verb}",
                $"{Display.Source(lastRun.Source)} says it ran at {Util.When.L(lastRun.TimeUtc)}, but it was {verb} at {Util.When.L(gone)} and never came back. " +
                "That order is impossible unless the clock was changed or a record was edited.", lastRun.TimeUtc);
        }
        else if (!r.IsWindowsFile && r.Type is FileType.Exe or FileType.Jar or FileType.Dll or FileType.Script &&
                 lastRun.TimeUtc <= gone + _tol)
        {
            var gap = gone - lastRun.TimeUtc!.Value;
            // Installers run and delete their own helpers in Temp, and updaters replace old versions in their own
            // version folders. Only files that look like those get the allowance: a cheat run from Temp and deleted does not.
            bool temp = Util.FileTypes.IsInstallerTemp(r.Path);
            bool update = Bypass.ArtifactAudit.LooksLikeUpdate(r.Path) || recreated;
            Add(r, gap < TimeSpan.FromHours(1) && !temp && !update ? Severity.Medium : Severity.Low, FindingCategory.Deletion,
                $"Ran, then {verb}",
                $"Last {(lastRun.Kind == EvidenceKind.LoadedModule ? "loaded" : "run")} {Util.When.L(lastRun.TimeUtc)} ({Display.Source(lastRun.Source)}), " +
                $"{verb} {Util.When.L(gone)} ({FormatGap(gap)} later)." +
                (update ? " A new copy appeared afterwards or it sits in an app's version folder, which is what an auto-update looks like." : ""), gone);
        }
    }

    /// <summary>A file that was created, edited or had its timestamps changed after it last ran: swapped for a clean copy?</summary>
    void CheckReplacement(FileRecord r)
    {
        if (r.Status != FileStatus.Exists || r.IsWindowsFile || LastRunEvidence(r)?.TimeUtc is not { } lastRun) return;
        var after = r.Evidence
            .Where(e => e.Source == EvidenceSource.UsnJournal && e.TimeUtc > lastRun + _tol &&
                        e.Kind is EvidenceKind.Created or EvidenceKind.Modified or EvidenceKind.TimestampChanged or EvidenceKind.Renamed)
            .OrderBy(e => e.TimeUtc).ToList();
        if (after.Count == 0) return;

        var first = after[0];
        // New or rewritten contents mean a different file now sits at that path. An attribute/timestamp
        // change alone is common (OneDrive, antivirus, archive bit), so it stays a weak lead.
        bool replaced = after.Any(e => e.Kind is EvidenceKind.Created or EvidenceKind.Modified);
        string what = string.Join(", ", after.Select(e => e.Kind).Distinct().Select(k => k switch
        {
            EvidenceKind.Created => "re-created", EvidenceKind.Modified => "contents changed",
            EvidenceKind.TimestampChanged => "timestamps/attributes changed", _ => "renamed",
        }));
        // The journal's reasons tell how (copied over, rewritten in place, swapped by Explorer); show the first one known.
        var how = after.FirstOrDefault(e => e.Kind == EvidenceKind.Modified && e.Detail != "File contents changed")?.Detail;
        Add(r, replaced ? Severity.Medium : Severity.Low,
            FindingCategory.TimelineInconsistency, replaced ? "File replaced after its last run" : "File attributes changed after its last run",
            $"Last run {Util.When.L(lastRun)}; afterwards {what} (first at {Util.When.L(first.TimeUtc)}). The file on disk may not be the one that ran." +
            (how != null ? $" {how}." : ""),
            first.TimeUtc);
    }

    /// <summary>
    /// BAM is written when a process starts or exits, so its time can never be earlier than the
    /// last start Prefetch recorded — unless the process is still running.
    /// </summary>
    void CheckBamAgainstPrefetch(FileRecord r)
    {
        var bam = MaxTime(r, EvidenceSource.Bam, EvidenceKind.Execution);
        var pf = MaxTime(r, EvidenceSource.Prefetch, EvidenceKind.Execution);
        if (bam is not { } b || pf is not { } p) return;
        if (b >= p - _tol || _runningNames.Contains(r.Name)) return;
        // Windows writes BAM when the process ends, so a run that was still going when the PC crashed, lost
        // power or was run under another account never updates it. On its own this is a weak lead.
        Add(r, Severity.Low, FindingCategory.TimelineInconsistency, "BAM time is older than the Prefetch run",
            $"Prefetch shows a run at {Util.When.L(p)} but BAM's last execution is {Util.When.L(b)} ({FormatGap(p - b)} earlier) and the program " +
            "is not running now. Either one of the two was altered or the clock was moved, or that run never ended cleanly " +
            "(crash, power loss) so Windows never updated BAM.",
            p);
    }

    /// <summary>
    /// PCA and UserAssist record launch times. A launch inside the window Prefetch covers should be
    /// one of its run times; a launch after Prefetch's newest run means Prefetch stopped updating.
    /// </summary>
    void CheckLaunchesAgainstPrefetch(FileRecord r)
    {
        var pfRuns = r.Evidence.Where(e => e.Source == EvidenceSource.Prefetch && e.Kind == EvidenceKind.Execution && e.TimeUtc.HasValue)
            .Select(e => e.TimeUtc!.Value).OrderBy(t => t).ToList();
        if (pfRuns.Count == 0) return;
        int pfCount = r.RunCount ?? pfRuns.Count;
        // With 8 times kept, only the window they span is fully covered; with fewer, every run since the first is.
        var coveredFrom = pfRuns[0];
        var newest = pfRuns[^1];
        var slack = _tol + TimeSpan.FromSeconds(30); // Prefetch writes ~10 s after launch

        foreach (var launch in r.Evidence.Where(e => e.Source is EvidenceSource.Pca or EvidenceSource.UserAssist &&
                                                     e.Kind == EvidenceKind.Execution && e.TimeUtc.HasValue))
        {
            var t = launch.TimeUtc!.Value;
            // Prefetch is written after a launch settles; a launch just before the scan, or a program
            // still running, may simply not be in it yet.
            if (t > _now - TimeSpan.FromMinutes(5) || _runningNames.Contains(r.Name)) continue;
            if (t > newest + TimeSpan.FromMinutes(10))
            {
                Add(r, Severity.Low, FindingCategory.TimelineInconsistency, $"{Display.Source(launch.Source)} launch is newer than Prefetch",
                    $"{Display.Source(launch.Source)} records a launch at {Util.When.L(t)}, but the newest Prefetch run is {Util.When.L(newest)}. The .pf may have been " +
                    "deleted and rebuilt, replaced with an old copy, or the clock moved — but Prefetch can also miss a launch for " +
                    "benign reasons (seen with very short-lived programs). Compare with the other sources.", t);
            }
            else if (t >= coveredFrom - slack && t <= newest + slack && !pfRuns.Any(p => (p - t).Duration() <= slack))
            {
                Add(r, Severity.Low, FindingCategory.TimelineInconsistency, $"{Display.Source(launch.Source)} launch missing from Prefetch",
                    $"{Display.Source(launch.Source)} records a launch at {Util.When.L(t)}, inside the period Prefetch covers ({Util.When.L(coveredFrom)} – {Util.When.L(newest)}, " +
                    $"run count {pfCount}), but no Prefetch run time matches it within {slack.TotalMinutes:0.#} min.", t);
            }
        }
    }

    void CheckClockChanges(FileRecord r)
    {
        if (_clockChanges.Count == 0 || r.LastExecutionUtc == null) return;
        foreach (var e in r.Evidence.Where(e => e.Kind == EvidenceKind.Execution && e.TimeUtc.HasValue))
        {
            var t = e.TimeUtc!.Value;
            foreach (var c in _clockChanges)
            {
                if (c.IsRollback && t >= c.NewTimeUtc && t <= c.OldTimeUtc)
                {
                    Add(r, Severity.High, FindingCategory.ClockTampering, "Run time falls inside a clock rollback",
                        $"{Display.Source(e.Source)} time {Util.When.L(t)} lies in {Util.When.L(c.NewTimeUtc)} – {Util.When.L(c.OldTimeUtc)}, a period the clock went through twice " +
                        $"after it was moved back ({c.Source}). This run may really have happened later than it appears.", t);
                    return;
                }
                if ((t - c.NewTimeUtc).Duration() <= TimeSpan.FromMinutes(10) || (t - c.OldTimeUtc).Duration() <= TimeSpan.FromMinutes(10))
                {
                    Add(r, Severity.Medium, FindingCategory.ClockTampering, "Run time is next to a clock change",
                        $"{Display.Source(e.Source)} time {Util.When.L(t)} is within 10 minutes of the clock being changed {Util.When.L(c.OldTimeUtc)} → {Util.When.L(c.NewTimeUtc)} ({c.Source}).", t);
                    return;
                }
            }
        }
    }

    void CheckShimCacheModified(FileRecord r)
    {
        if (r.Status != FileStatus.Exists || r.IsWindowsFile) return;
        var shim = r.Evidence.FirstOrDefault(e => e.Source == EvidenceSource.ShimCache && e.FileModifiedUtc.HasValue);
        if (shim == null || _lastWrite(r.Path) is not { } current) return;
        if ((current - shim.FileModifiedUtc!.Value).Duration() <= TimeSpan.FromSeconds(2)) return;
        Add(r, Severity.Low, FindingCategory.TimelineInconsistency, "File differs from the one Windows cached",
            $"ShimCache recorded a last-modified time of {Util.When.L(shim.FileModifiedUtc)}; the file on disk now says {Util.When.L(current)}. " +
            "It was replaced, updated or had its timestamps edited since.", current);
    }

    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Latest direct execution. Prefetch "loaded" entries count only for jars (a jar run through
    /// javaw never executes on its own) — and even then only as the javaw run that last listed it.
    /// </summary>
    static Evidence? LastRunEvidence(FileRecord r) =>
        r.Evidence.Where(e => e.TimeUtc.HasValue &&
                              (e.Kind == EvidenceKind.Execution || (e.Kind == EvidenceKind.LoadedModule && r.Type is FileType.Jar or FileType.Script)))
            .MaxBy(e => e.TimeUtc);

    static DateTime? MaxTime(FileRecord r, EvidenceSource source, EvidenceKind kind) =>
        r.Evidence.Where(e => e.Source == source && e.Kind == kind && e.TimeUtc.HasValue).Select(e => e.TimeUtc).Max();

    static void Add(FileRecord r, Severity severity, FindingCategory category, string title, string detail, DateTime? time) =>
        r.Findings.Add(new Finding
        {
            Severity = severity, Category = category, Title = title, Detail = detail, Path = r.Path, TimeUtc = time,
        });

    internal static string FormatGap(TimeSpan gap)
    {
        var a = gap.Duration();
        return a.TotalDays >= 1 ? $"{a.TotalDays:0.#} days" :
            a.TotalHours >= 1 ? $"{a.TotalHours:0.#} h" :
            a.TotalMinutes >= 1 ? $"{a.TotalMinutes:0} min" : $"{a.TotalSeconds:0} s";
    }
}
