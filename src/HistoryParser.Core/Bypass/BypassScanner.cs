using System.Collections.Concurrent;
using System.Diagnostics;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// The one scan: the full execution-history scan (so every source it reads is available), then the
/// bypass audits on top. Findings are the bypass-relevant subset of History Parser's plus the audits' own.
/// </summary>
public static class BypassScanner
{
    public static Task<BypassReport> RunAsync(ScanOptions options, ArgumentRules rules, IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default) => Task.Run(() => Run(options, rules, progress, ct), ct);

    public static BypassReport Run(ScanOptions options, ArgumentRules rules, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
    {
        options.IncludeArtifactFiles = true;
        // The audits need the full history (a mod update vs. a removal, a run before a deletion); the period
        // shown is cut out afterwards with Trim.
        options.TrimToWindow = false;
        var history = Scanner.Run(options, new Progress<ScanProgress>(p =>
            progress?.Report(p with { Message = p.Message == "Done" ? "Execution history read" : p.Message, Total = p.Total + 13 })), ct);

        var ctx = new BypassContext(history, rules, options.Keywords) { ReadGameLogs = options.ReadGameLogs };
        // History Parser checks only that the execution records can be trusted: are the recording services and settings
        // healthy, were logs or evidence files tampered with, and were any record-erasing commands/arguments run. Cheat and
        // bypass detection (injection, drivers, the running game, blocking, Defender, boot, hardware) lives in the other tools.
        (string Name, Func<BypassContext, CancellationToken, int> Run)[] audits =
        [
            ("Event logs", LogAudit.Run),
            ("Services", ServiceAudit.Run),
            ("USB devices", UsbAudit.Run),
            ("Program arguments", ArgumentAudit.Run),
            ("Evidence files", ArtifactAudit.Run),
        ];
        int baseCount = history.Sources.Count + 3, done = 0;
        var statuses = new ConcurrentBag<SourceStatus>();
        Parallel.ForEach(audits, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = ct }, audit =>
        {
            progress?.Report(new ScanProgress($"Checking {audit.Name}…", baseCount + done, baseCount + audits.Length));
            var sw = Stopwatch.StartNew();
            try
            {
                int n = audit.Run(ctx, ct);
                statuses.Add(new SourceStatus(audit.Name, true, n, "OK", sw.Elapsed));
            }
            catch (OperationCanceledException) { throw; }
            catch (UnauthorizedAccessException e)
            {
                statuses.Add(new SourceStatus(audit.Name, false, 0, $"Access denied — run as administrator. ({e.Message})", sw.Elapsed));
            }
            catch (Exception e)
            {
                statuses.Add(new SourceStatus(audit.Name, false, 0, $"{e.GetType().Name}: {e.Message}", sw.Elapsed));
            }
            progress?.Report(new ScanProgress($"Finished {audit.Name}", baseCount + Interlocked.Increment(ref done), baseCount + audits.Length));
        });

        CrossCheckUsb(ctx);

        var findings = Analysis.SelfTraces.Mark(HistoryFindings(history).Concat(ctx.Findings), history.Files)
            .GroupBy(f => (f.Title, f.Path, f.TimeUtc)).Select(g => g.First())
            .OrderByDescending(f => f.Severity).ThenByDescending(f => f.TimeUtc ?? DateTime.MinValue).ToList();

        return new BypassReport
        {
            History = history,
            Findings = findings,
            Logs = ctx.Logs.OrderByDescending(l => l.State).ThenBy(l => l.Channel).ToList(),
            RecordGaps = ctx.RecordGaps.OrderByDescending(g => g.BeforeTimeUtc ?? DateTime.MinValue).ToList(),
            Services = ctx.Services.OrderByDescending(s => s.Status).ThenBy(s => s.Name).ToList(),
            ServiceEvents = ctx.ServiceEvents.OrderByDescending(e => e.TimeUtc ?? DateTime.MinValue).ToList(),
            UsbDevices = ctx.UsbDevices.OrderByDescending(d => d.LastConnectedUtc ?? DateTime.MinValue).ToList(),
            UsbEvents = ctx.UsbEvents.OrderByDescending(e => e.TimeUtc ?? DateTime.MinValue).ToList(),
            Arguments = ctx.Arguments.OrderByDescending(a => a.Flagged).ThenByDescending(a => a.TimeUtc ?? DateTime.MinValue).ToList(),
            Drivers = ctx.Drivers.OrderByDescending(d => d.Flagged).ThenBy(d => d.Name).ToList(),
            Tasks = ctx.Tasks.OrderByDescending(t => t.Flagged).ThenByDescending(t => t.CreatedUtc ?? DateTime.MinValue).ToList(),
            Software = ctx.Software.OrderByDescending(s => s.Flagged).ThenByDescending(s => s.TimeUtc ?? DateTime.MinValue).ToList(),
            Artifacts = ctx.Artifacts.OrderByDescending(a => a.Suspicious).ThenByDescending(a => a.TimeUtc ?? DateTime.MinValue).ToList(),
            Defender = ctx.Defender.OrderByDescending(d => d.TimeUtc ?? DateTime.MinValue).ToList(),
            Routes = ctx.Routes.OrderBy(r => r.Area).ThenByDescending(r => r.State switch { CheckState.Bad => 3, CheckState.Warning => 2, CheckState.Unknown => 1, _ => 0 }).ThenBy(r => r.Item).ToList(),
            Sources = history.Sources.Concat(statuses.OrderBy(s => s.Name)).ToList(),
        };
    }

    /// <summary>
    /// The report cut to a period, for display. Rows describing the PC now (logs, services, drivers, tasks,
    /// injection routes, running programs, plugged-in USB devices) always stay; dated rows stay when they fall
    /// in the period; undated findings stay unless they are about a file that fell outside it.
    /// </summary>
    public static BypassReport Trim(BypassReport r, TimeWindow window)
    {
        if (TimeWindows.Since(window, r.History.StartedUtc, r.History.Machine.BootTimeUtc) is not { } s)
            return Copy(r, Scanner.Trim(r.History, window), r.Findings, x => true);
        var history = Scanner.Trim(r.History, window);
        var kept = history.Files.Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var dropped = r.History.Files.Select(f => f.Path).Where(p => !kept.Contains(p)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var findings = r.Findings.Where(f => f.TimeUtc is { } t ? t >= s : f.Path == null || !dropped.Contains(f.Path)).ToList();
        return Copy(r, history, findings, t => t is not { } v || v >= s);
    }

    static BypassReport Copy(BypassReport r, ScanResult history, List<Finding> findings, Func<DateTime?, bool> inPeriod) => new()
    {
        History = history,
        Findings = findings,
        Logs = r.Logs,
        RecordGaps = r.RecordGaps.Where(g => inPeriod(g.BeforeTimeUtc)).ToList(),
        Services = r.Services,
        ServiceEvents = r.ServiceEvents.Where(e => inPeriod(e.TimeUtc)).ToList(),
        UsbDevices = r.UsbDevices.Where(d => d.ConnectedNow || inPeriod(d.LastConnectedUtc)).ToList(),
        UsbEvents = r.UsbEvents.Where(e => inPeriod(e.TimeUtc)).ToList(),
        Arguments = r.Arguments.Where(a => a.Source == "Running now" || inPeriod(a.TimeUtc)).ToList(),
        Drivers = r.Drivers,
        Tasks = r.Tasks,
        Software = r.Software.Where(x => inPeriod(x.TimeUtc)).ToList(),
        Artifacts = r.Artifacts.Where(a => inPeriod(a.TimeUtc)).ToList(),
        Defender = r.Defender.Where(d => inPeriod(d.TimeUtc)).ToList(),
        Routes = r.Routes,
        Sources = r.Sources,
        PrivateDetailsHidden = r.PrivateDetailsHidden,
    };

    /// <summary>History Parser findings that are about hiding evidence rather than about a specific cheat file.</summary>
    static IEnumerable<Finding> HistoryFindings(ScanResult history) => history.Findings.Where(f =>
        f.Category is FindingCategory.Integrity or FindingCategory.ClockTampering or FindingCategory.AntiForensics or FindingCategory.Driver ||
        f.Title.StartsWith("Name matches tool keyword", StringComparison.Ordinal) || // cleaners and time-changers
        (f.Category == FindingCategory.Deletion && f.Title.Contains("refetch", StringComparison.Ordinal)) ||
        (f.Category == FindingCategory.TimelineInconsistency && f.Severity >= Severity.Medium));

    /// <summary>Programs that ran from a USB drive (matched by drive letter or because their drive is gone).</summary>
    static void CrossCheckUsb(BypassContext ctx)
    {
        var usbLetters = ctx.UsbDevices.Where(d => d.DriveLetter.Length == 2)
            .ToDictionary(d => d.DriveLetter.ToUpperInvariant(), d => d.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var f in ctx.History.Files.Where(f => (f.WasExecutedDirectly || f.WasLoaded) && f.Path.Length > 2 && f.Path[1] == ':'))
        {
            string letter = f.Path[..2].ToUpperInvariant();
            bool usb = usbLetters.ContainsKey(letter);
            if (!usb && f.Status != FileStatus.DriveNotConnected) continue;
            ctx.Flag(Severity.Medium, FindingCategory.Usb, "Program ran from a removable drive",
                $"{f.Path} ran (last {Util.When.L(f.LastExecutionUtc)}) from {letter}" +
                (usb ? $", the drive letter of USB device \"{usbLetters[letter]}\"." : ", a drive that is not connected now."),
                f.Path, f.LastExecutionUtc);
        }
    }
}
