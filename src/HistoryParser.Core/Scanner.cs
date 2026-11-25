using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Win32;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Util;

namespace HistoryParser.Core;

public static class Scanner
{
    public static string Version =>
        typeof(Scanner).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    public static Task<ScanResult> RunAsync(ScanOptions options, IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default) =>
        Task.Run(() => Run(options, progress, ct), ct);

    public static ScanResult Run(ScanOptions options, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
    {
        var started = DateTime.UtcNow;
        var boot = started - TimeSpan.FromMilliseconds(Environment.TickCount64);
        var java = SessionTimes.RunningJava();
        var ctx = new ScanContext(options, PathNormalizer.ForThisMachine(), started, boot)
        {
            OsInstallUtc = OsInstallDate(),
            SignInUtc = SessionTimes.SignInUtc(),
            Games = java.Where(g => !g.Unrecognised).ToList(),
            OtherJava = java.Where(g => g.Unrecognised).ToList(),
        };

        // Prefetch runs first: the USN collector needs to know how full the Prefetch folder is.
        ICollector first = new PrefetchCollector();
        ICollector[] rest =
        [
            new SystemStateCollector(), new BamCollector(), new BamDeletedCollector(), new PcaCollector(), new UserAssistCollector(),
            new ShimCacheCollector(), new MuiCacheCollector(), new JavaUsageCollector(), new RecycleBinCollector(),
            new ShellHistoryCollector(), new EventLogCollector(), new UsnJournalCollector(), new ProcessMemoryCollector(),
            new AmcacheCollector(), new RecentShortcutCollector(), new JumpListCollector(), new FileDialogCollector(), new ExplorerUsageCollector(), new CrashReportCollector(),
            new CapabilityAccessCollector(), new LoadedDriverCollector(), new DefenderDetectionCollector(),
        ];
        int total = rest.Length + 3, done = 0;
        var statuses = new ConcurrentBag<SourceStatus>();

        void RunOne(ICollector c)
        {
            progress?.Report(new ScanProgress($"Reading {c.Name}…", done, total));
            var sw = Stopwatch.StartNew();
            try
            {
                int n = c.Collect(ctx, ct);
                statuses.Add(new SourceStatus(c.Name, true, n, "OK", sw.Elapsed));
            }
            catch (OperationCanceledException) { throw; }
            catch (UnauthorizedAccessException e)
            {
                statuses.Add(new SourceStatus(c.Name, false, 0, $"Access denied — run as administrator. ({e.Message})", sw.Elapsed));
            }
            catch (Exception e)
            {
                statuses.Add(new SourceStatus(c.Name, false, 0, $"{e.GetType().Name}: {e.Message}", sw.Elapsed));
            }
            progress?.Report(new ScanProgress($"Finished {c.Name}", Interlocked.Increment(ref done), total));
        }

        RunOne(first);
        Parallel.ForEach(rest, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 4, 8), CancellationToken = ct }, RunOne);

        progress?.Report(new ScanProgress("Correlating timestamps…", ++done, total));
        var clockChanges = Dedupe(ctx.ClockChanges).OrderBy(c => c.NewTimeUtc).ToList();
        foreach (var c in clockChanges.Where(c => c.Source.Contains("order") || c.Source.Contains("USN")))
        {
            var mag = Correlator.FormatGap(c.Delta);
            ctx.Flag(c.Delta.Duration() > TimeSpan.FromHours(1) ? Severity.High : Severity.Medium, FindingCategory.ClockTampering,
                $"Clock moved back {mag} ({c.Source})",
                $"Records written in strict order jump from {Util.When.L(c.OldTimeUtc)} back to {Util.When.L(c.NewTimeUtc)}. {c.Detail} " +
                "Any timestamp between those two times may have been produced while the clock was wrong.", timeUtc: c.NewTimeUtc);
        }
        foreach (var c in clockChanges.Where(c => !c.Source.Contains("order") && !c.Source.Contains("USN")))
        {
            ctx.Flag(c.Severity, FindingCategory.ClockTampering,
                $"System clock {(c.IsRollback ? "moved back" : "moved forward")} {Correlator.FormatGap(c.Delta)}",
                $"{c.Source}: {Util.When.L(c.OldTimeUtc)} → {Util.When.L(c.NewTimeUtc)}. {c.Detail}".Trim(), timeUtc: c.NewTimeUtc);
        }

        var running = Process.GetProcesses().Select(p => { using (p) return p.ProcessName + ".exe"; }).ToList();
        // Small time-service corrections are reported but do not taint individual run times.
        var significant = clockChanges.Where(c => c.Severity >= Severity.Medium || c.IsRollback).ToList();
        var correlator = new Correlator(started, options.Tolerance, significant, running, bootUtc: boot);
        var evidence = ctx.Evidence.ToList();
        var since = TimeWindows.Since(options.Window, started, boot, ctx.SignInUtc, ctx.Games.Count > 0 ? ctx.Games[0].StartUtc : null);

        // Which files are routine (Windows' own, or a known publisher's) is decided by verifying each one, never by its
        // folder - so it has to be worked out before the records are built. Only files inside the chosen period are
        // verified; older ones stay "not checked", which keeps them in view.
        if (options.InspectFiles)
        {
            progress?.Report(new ScanProgress("Verifying which files are Windows' own…", done, total));
            RoutineFiles.Forget();
            RoutineFiles.Prime(RecentPaths(evidence, since), ct);
        }
        var files = correlator.Build(evidence);

        // Hashing and signature checks are the slow part, so only files inside the chosen period get them; every
        // cross-check above already ran on the full history.
        var shown = since is { } from ? files.Where(f => f.LastActivityUtc >= from).ToList() : files;

        if (options.InspectFiles)
        {
            progress?.Report(new ScanProgress("Hashing and checking signatures…", ++done, total));
            Parallel.ForEach(shown.Where(FileInspector.ShouldInspect),
                new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 4, 12), CancellationToken = ct }, FileInspector.Inspect);
            // Files that were verified but are not hashed (libraries in Program Files, Windows' own) still say who signed them.
            foreach (var r in shown.Where(r => r.Signature == SignatureStatus.NotChecked && r.Status == FileStatus.Exists && r.Type is FileType.Exe or FileType.Dll))
            {
                var facts = SignatureTrust.Of(r.Path);
                if (facts.Status == SignatureStatus.NotChecked) continue;
                r.Signature = r.IsWindowsFile ? SignatureStatus.WindowsFile : FileInspector.Verify(r.Path);
                if (facts.Status is SignatureStatus.Signed or SignatureStatus.Invalid or SignatureStatus.Untrusted) r.Signer = FileInspector.SignerName(r.Path);
            }
        }

        // Renamed / disguised programs, faked dates, hidden streams, host programs. Reading NTFS's own
        // timestamps needs the raw volume, so that part only runs as administrator.
        progress?.Report(new ScanProgress("Checking programs for disguises and faked dates…", done, total));
        TamperAnalysis.Run(shown, readNtfs: options.InspectFiles && WinApi.IsElevated());
        DownloadOrigin.Annotate(shown);

        // Our own runs, unpacked runtime and launcher are labelled and taken out of the counts.
        var general = ctx.Findings.ToList();
        SelfTraces.Mark(files, general, ctx.OwnRuntimeFiles.Keys);
        var findings = general.Concat(files.SelectMany(f => f.Findings))
            .OrderByDescending(f => f.Severity).ThenByDescending(f => f.TimeUtc ?? DateTime.MinValue).ToList();

        progress?.Report(new ScanProgress("Done", total, total));
        var result = new ScanResult
        {
            Machine = new MachineInfo
            {
                ComputerName = Environment.MachineName,
                UserName = Environment.UserDomainName + "\\" + Environment.UserName,
                OsVersion = OsVersion(),
                BootTimeUtc = boot,
                OsInstallUtc = ctx.OsInstallUtc,
                SignInUtc = ctx.SignInUtc,
                ShellStartUtc = ctx.ShellStartUtc,
                GameStartUtc = ctx.Games.Count > 0 ? ctx.Games[0].StartUtc : null,
                GameProgram = ctx.Games.Count > 0 ? $"{ctx.Games[0].Program} (pid {ctx.Games[0].Pid})" : "",
                Games = SessionTimes.AllGames(ctx.Games, evidence, ctx.OtherJava),
                TimeZone = TimeZoneInfo.Local.DisplayName,
                IsElevated = WinApi.IsElevated(),
                ToolVersion = Version,
                ToolSha256 = SelfTraces.OneFile ? SelfTraces.OwnHash ?? "" : "",
            },
            StartedUtc = started,
            FinishedUtc = DateTime.UtcNow,
            Files = files.OrderByDescending(f => f.LastActivityUtc ?? DateTime.MinValue).ToList(),
            Findings = findings,
            Checks = ctx.Checks.OrderBy(c => c.Area).ThenBy(c => c.Name).ToList(),
            Sources = statuses.OrderBy(s => s.Name).ToList(),
            ClockChanges = clockChanges,
            MemoryHits = ctx.MemoryHits.OrderBy(h => h.Process).ThenBy(h => h.Path).ToList(),
            ServiceEvents = ctx.ServiceEvents.OrderByDescending(e => e.TimeUtc ?? DateTime.MinValue).ToList(),
            Folders = ctx.Folders.OrderByDescending(f => f.LastActivityUtc ?? DateTime.MinValue).ToList(),
            Commands = ctx.Commands
                .OrderByDescending(c => c.Suspicion != null)
                .ThenByDescending(c => c.TimeUtc ?? DateTime.MinValue)
                .ThenBy(c => c.Group).ThenBy(c => c.Source).ThenByDescending(c => c.Order).ToList(),
            Timeline = evidence.OrderByDescending(e => e.TimeUtc ?? DateTime.MinValue).ToList(),
        };
        return options.TrimToWindow ? Trim(result, options.Window) : result;
    }

    /// <summary>
    /// Keeps only the chosen period. Everything was already cross-checked against the full history, so a
    /// deletion today still knows about a run two weeks ago. A file stays (with all its evidence) when
    /// anything about it happened in the period; undated findings describe the PC now and always stay.
    /// </summary>
    public static ScanResult Trim(ScanResult r, TimeWindow window) => Trim(r, window, null);

    /// <param name="gameStartUtc">The game the "since the game started" period is measured from, when the reader picked one; otherwise the scan's own.</param>
    public static ScanResult Trim(ScanResult r, TimeWindow window, DateTime? gameStartUtc)
    {
        if (TimeWindows.Since(window, r.StartedUtc, r.Machine.BootTimeUtc, r.Machine.SignInUtc, gameStartUtc ?? r.Machine.GameStartUtc) is not { } s)
            return Copy(r, window, null, r.Files, r.Findings, r.Timeline, r.ClockChanges, r.ServiceEvents, r.Commands, r.Folders);
        var files = r.Files.Where(f => f.LastActivityUtc >= s).ToList();
        var kept = files.Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return Copy(r, window, s, files,
            r.Findings.Where(f => TimeWindows.Keep(f, s, kept)).ToList(),
            r.Timeline.Where(e => e.TimeUtc >= s).ToList(),
            r.ClockChanges.Where(c => c.NewTimeUtc >= s || c.OldTimeUtc >= s).ToList(),
            r.ServiceEvents.Where(e => e.TimeUtc >= s).ToList(),
            r.Commands.Where(c => c.TimeUtc is not { } t || t >= s).ToList(), // undated shell history has no time to judge
            r.Folders.Where(f => f.LastActivityUtc >= s).ToList());
    }

    static ScanResult Copy(ScanResult r, TimeWindow window, DateTime? since, List<FileRecord> files, List<Finding> findings,
        List<Evidence> timeline, List<ClockChange> clock, List<Bypass.ServiceEvent> services, List<CommandEntry> commands,
        List<FolderVisit> folders) => new()
    {
        Machine = r.Machine, StartedUtc = r.StartedUtc, FinishedUtc = r.FinishedUtc, Files = files, Findings = findings,
        Checks = r.Checks, Sources = r.Sources, ClockChanges = clock, MemoryHits = r.MemoryHits, ServiceEvents = services,
        Commands = commands, Folders = folders, Timeline = timeline, PrivateDetailsHidden = r.PrivateDetailsHidden, Window = window, SinceUtc = since,
    };

    /// <summary>Paths of programs and libraries with anything dated inside the period (every one when there is no period).</summary>
    static List<string> RecentPaths(List<Evidence> evidence, DateTime? since)
    {
        var latest = new Dictionary<string, (string Path, DateTime? Time)>(StringComparer.Ordinal);
        foreach (var e in evidence)
        {
            if (e.Path.Length < 4 || e.Path[1] != ':') continue;
            if (FileTypes.FromPath(e.Path) is not (FileType.Exe or FileType.Dll)) continue;
            var key = PathNormalizer.Key(e.Path);
            if (!latest.TryGetValue(key, out var seen) || e.TimeUtc > seen.Time || (seen.Time == null && e.TimeUtc != null))
                latest[key] = (e.Path, e.TimeUtc ?? seen.Time);
        }
        return latest.Values.Where(v => since is not { } from || v.Time >= from).Select(v => v.Path).ToList();
    }

    static IEnumerable<ClockChange> Dedupe(IEnumerable<ClockChange> changes) =>
        changes.GroupBy(c => (c.Source, c.OldTimeUtc.Ticks / TimeSpan.TicksPerSecond, c.NewTimeUtc.Ticks / TimeSpan.TicksPerSecond))
            .Select(g => g.First());

    static DateTime? OsInstallDate()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        return key?.GetValue("InstallDate") is int seconds and > 0
            ? DateTimeOffset.FromUnixTimeSeconds((uint)seconds).UtcDateTime
            : null;
    }

    static string OsVersion()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        if (key == null) return Environment.OSVersion.VersionString;
        var build = key.GetValue("CurrentBuild") as string ?? "?";
        var ubr = key.GetValue("UBR") is int u ? $".{u}" : "";
        var display = key.GetValue("DisplayVersion") as string ?? "";
        // ProductName still says "Windows 10" on Windows 11; the build number decides.
        var name = int.TryParse(build, out var b) && b >= 22000 ? "Windows 11" : "Windows 10";
        var edition = key.GetValue("EditionID") as string ?? "";
        return $"{name} {edition} {display} (build {build}{ubr})".Replace("  ", " ");
    }
}
