using System.Diagnostics.Eventing.Reader;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Were event logs disabled, shrunk, wiped, or edited record-by-record?
/// <list type="bullet">
/// <item>Disabled channels that Windows enables by default.</item>
/// <item>Maximum size set tiny, so old events roll off within minutes.</item>
/// <item>A log that is nowhere near full but starts only recently: cleared or its file replaced.</item>
/// <item>Gaps in the record numbers: tools that delete single events leave holes.</item>
/// <item>The event log service being shut down outside a normal shutdown (needed to edit .evtx files).</item>
/// </list>
/// </summary>
public static class LogAudit
{
    sealed record Channel(string Name, bool EnabledByDefault, bool ScanForGaps, bool Critical);

    static readonly Channel[] Channels =
    [
        new("System", true, true, true),
        new("Security", true, true, true),
        new("Application", true, true, true),
        new("Windows PowerShell", true, true, false),
        new("Microsoft-Windows-PowerShell/Operational", true, true, false),
        new("Microsoft-Windows-Partition/Diagnostic", true, false, false),
        new("Microsoft-Windows-Windows Defender/Operational", true, false, false),
        new("Microsoft-Windows-Kernel-PnP/Configuration", true, false, false),
        new("Microsoft-Windows-TaskScheduler/Operational", false, false, false),
        new("Microsoft-Windows-Sysmon/Operational", false, false, false),
    ];

    const int MaxGapScanRecords = 400_000;

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        using var session = new EventLogSession();
        foreach (var ch in Channels)
        {
            ct.ThrowIfCancellationRequested();
            var info = Inspect(ctx, session, ch, ct);
            if (info != null) { ctx.Logs.Add(info); items++; }
        }
        items += ServiceShutdowns(ctx);
        return items;
    }

    static LogChannelInfo? Inspect(BypassContext ctx, EventLogSession session, Channel ch, CancellationToken ct)
    {
        EventLogConfiguration cfg;
        try { cfg = new EventLogConfiguration(ch.Name, session); }
        catch (EventLogNotFoundException) { return null; } // e.g. Sysmon not installed
        catch (UnauthorizedAccessException)
        {
            return new LogChannelInfo { Channel = ch.Name, State = CheckState.Unknown, Note = "Access denied (run as administrator)." };
        }

        using (cfg)
        {
            EventLogInformation? info = null;
            try { info = session.GetLogInformation(ch.Name, PathType.LogName); }
            catch (Exception e) when (e is EventLogException or UnauthorizedAccessException) { }

            var oldest = Events.Read(ch.Name, newestFirst: false, max: 1).Select(Events.Utc).FirstOrDefault();
            var newest = Events.Read(ch.Name, newestFirst: true, max: 1).Select(Events.Utc).FirstOrDefault();
            var notes = new List<string>();
            var state = CheckState.Ok;

            if (ch.EnabledByDefault && !cfg.IsEnabled)
            {
                state = CheckState.Bad;
                notes.Add("disabled (Windows enables it by default)");
                ctx.Flag(Severity.High, FindingCategory.LogTampering, $"Event log disabled: {ch.Name}",
                    $"The \"{ch.Name}\" log is turned off, so nothing is recorded in it. Windows enables it by default.");
            }

            long max = cfg.MaximumSizeInBytes;
            if (ch.Critical && max > 0 && max < 4L * 1024 * 1024)
            {
                state = CheckState.Bad;
                notes.Add($"maximum size only {max / 1024} KB (default 20 MB)");
                ctx.Flag(Severity.Medium, FindingCategory.LogTampering, $"Event log shrunk: {ch.Name}",
                    $"The \"{ch.Name}\" log can only hold {max / 1024} KB (Windows uses 20 MB), so older events are " +
                    "overwritten almost immediately.");
            }

            // A log that is far from full keeps everything since it was last cleared. If its first event
            // is recent on a PC installed long ago, it was cleared or its file replaced.
            long? size = info?.FileSize;
            bool notFull = size is { } s && max > 0 && s < max * 0.8;
            // "Archive the log when full" makes Windows move the old file aside and start an empty one.
            bool archives = cfg.LogMode == EventLogMode.AutoBackup;
            if (archives) notes.Add("archives itself when full");
            if (ch.Critical && notFull && !archives && oldest is { } o && ctx.OsInstallUtc is { } install &&
                o > install.AddDays(2) && ctx.NowUtc - o < TimeSpan.FromDays(14))
            {
                if (state == CheckState.Ok) state = CheckState.Warning;
                notes.Add($"starts {Util.When.L(o)} although it is not full");
                ctx.Flag(Severity.Medium, FindingCategory.LogTampering, $"Event log starts recently: {ch.Name}",
                    $"The \"{ch.Name}\" log only goes back to {Util.When.L(o)} but is not full ({size / 1024} KB of {max / 1024} KB). " +
                    "Logs keep everything until they fill up, so it was most likely cleared or its file replaced (Windows also starts a new file if the old one was damaged).", timeUtc: o);
            }

            int gaps = 0;
            long missing = 0;
            if (ch.ScanForGaps)
            {
                foreach (var gap in FindGaps(ch.Name, ct))
                {
                    gaps++;
                    missing += gap.Missing;
                    if (gaps <= 50) ctx.RecordGaps.Add(gap);
                }
                if (gaps > 0)
                {
                    state = CheckState.Bad;
                    notes.Add($"{gaps} gap(s) in record numbers, {missing:N0} record(s) missing");
                    ctx.Flag(Severity.High, FindingCategory.LogTampering, $"Events deleted from the {ch.Name} log",
                        $"{missing:N0} record number(s) are missing from the middle of the \"{ch.Name}\" log in {gaps} place(s). " +
                        "Windows numbers events consecutively and only ever removes the oldest, so these were deleted individually " +
                        "with an editing tool. See the Logs page for where.");
                }
            }

            if (notes.Count == 0 && !cfg.IsEnabled)
                notes.Add("off (Windows leaves this log off by default)");
            else if (cfg.IsEnabled && info == null && oldest == null)
            {
                // Without admin rights the Security log cannot be opened at all; do not call it intact.
                notes.Add("could not be read (run as administrator)");
                if (state == CheckState.Ok) state = CheckState.Unknown;
            }

            return new LogChannelInfo
            {
                Channel = ch.Name,
                Enabled = cfg.IsEnabled,
                RecordCount = info?.RecordCount,
                MaxSizeBytes = max > 0 ? max : null,
                FileSizeBytes = size,
                OldestUtc = oldest,
                NewestUtc = newest,
                LastWriteUtc = info?.LastWriteTime?.ToUniversalTime(),
                RecordGaps = gaps,
                MissingRecords = missing,
                State = state,
                Note = notes.Count == 0 ? "Looks intact" : string.Join("; ", notes),
            };
        }
    }

    /// <summary>Walks a log oldest-first and reports every jump in the record numbers.</summary>
    internal static IEnumerable<RecordGap> FindGaps(string channel, CancellationToken ct)
    {
        long? previous = null;
        DateTime? previousTime = null;
        int n = 0;
        foreach (var r in Events.Read(channel, newestFirst: false, max: MaxGapScanRecords))
        {
            if ((++n & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
            if (r.RecordId is not { } id) continue;
            var t = Events.Utc(r);
            if (previous is { } p && id > p + 1) yield return new RecordGap(channel, p, id, previousTime, t);
            previous = id;
            previousTime = t;
        }
    }

    /// <summary>Gap detection over a plain list of record numbers (used by tests).</summary>
    public static List<RecordGap> GapsIn(string channel, IEnumerable<(long Id, DateTime? Time)> records)
    {
        var gaps = new List<RecordGap>();
        long? previous = null;
        DateTime? previousTime = null;
        foreach (var (id, t) in records)
        {
            if (previous is { } p && id > p + 1) gaps.Add(new RecordGap(channel, p, id, previousTime, t));
            previous = id;
            previousTime = t;
        }
        return gaps;
    }

    /// <summary>Security 1100: "The event logging service has shut down" — outside a shutdown, someone stopped it.</summary>
    static int ServiceShutdowns(BypassContext ctx)
    {
        int items = 0;
        foreach (var r in Events.Read("Security", "*[System[EventID=1100]]", 200))
        {
            if (Events.Utc(r) is not { } t || ctx.NearShutdown(t)) continue;
            ctx.Flag(Severity.High, FindingCategory.LogTampering, "Event log service stopped",
                $"The event logging service shut down at {Util.When.L(t)} while Windows kept running. That is required to edit or " +
                "replace log files.", timeUtc: t);
            ctx.ServiceEvents.Add(new ServiceEvent
            {
                TimeUtc = t, Service = "EventLog", Change = "Event logging service shut down (Security 1100)", EventId = 1100, Suspicious = true,
            });
            items++;
        }
        return items;
    }
}
