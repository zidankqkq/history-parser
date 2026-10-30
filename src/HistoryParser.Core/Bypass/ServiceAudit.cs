using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Services whose stopping or disabling stops evidence being recorded: their state now, when their
/// configuration last changed (registry key write time), and their full stop / start-type history.
/// </summary>
public static class ServiceAudit
{
    sealed record Watched(string Name, string Role, bool Critical);

    static readonly Watched[] Services =
    [
        new("SysMain", "records Prefetch", true),
        new("bam", "records BAM execution times", true),
        new("dam", "records DAM execution times", false),
        new("DPS", "keeps program paths in memory", true),
        new("PcaSvc", "records PCA launches", true),
        new("EventLog", "writes every event log", true),
        new("DiagTrack", "keeps program paths in memory", false),
        new("WSearch", "search index", false),
        new("Schedule", "runs scheduled tasks", false),
        new("VSS", "makes restore points / shadow copies", false),
        new("WinDefend", "Microsoft Defender", false),
        new("Sysmon64", "Sysmon monitoring (if installed)", false),
        new("Sysmon", "Sysmon monitoring (if installed)", false),
    ];

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        var updates = ServiceJudge.UpdateTimes();
        foreach (var w in Services)
        {
            ct.ThrowIfCancellationRequested();
            var s = WinApi.QueryService(w.Name);
            if (!s.Exists && w.Name.StartsWith("Sysmon", StringComparison.Ordinal)) continue;

            DateTime? changed = null;
            using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{w.Name}"))
                if (key != null) changed = WinApi.GetKeyLastWriteUtc(key);

            var notes = new List<string>();
            var state = CheckState.Ok;
            if (!s.Exists) { notes.Add("not installed"); state = w.Critical ? CheckState.Bad : CheckState.Warning; }
            if (s.IsDisabled) { notes.Add("disabled"); state = w.Critical ? CheckState.Bad : CheckState.Warning; }
            else if (s.Exists && !s.IsRunning && s.State != "Unknown" && w.Critical) { notes.Add($"not running ({s.State})"); state = CheckState.Bad; }

            if (s.ProcessStartUtc is { } started && started - ctx.BootUtc > TimeSpan.FromMinutes(10))
            {
                notes.Add($"restarted {Util.When.L(started)}");
                if (state == CheckState.Ok) state = CheckState.Warning;
                bool update = updates.Any(u => (u - started).Duration() < TimeSpan.FromMinutes(30));
                if (w.Name == "EventLog")
                    ctx.Flag(update ? Severity.Low : Severity.High, FindingCategory.LogTampering, "Event log service restarted",
                        $"The event log service was (re)started at {Util.When.L(started)}, {(started - ctx.BootUtc).TotalMinutes:0} min after boot. " +
                        "Stopping it is how log files are edited or swapped." +
                        (update ? " A Windows update was being installed around then, which can restart it." : ""), timeUtc: started);
            }

            // A service can look "Running" while its threads are frozen (suspended from outside): it records nothing.
            if (s.Pid > 0 && s.IsRunning && WinApi.Threads(s.Pid) is { Count: > 0 } threads && threads.Count(t => t.Suspended) is > 0 and var frozen)
            {
                bool all = frozen == threads.Count;
                notes.Add(all ? "every thread suspended" : $"{frozen} of {threads.Count} threads suspended");
                state = CheckState.Bad;
                ctx.Flag(all || w.Critical ? Severity.High : Severity.Medium, FindingCategory.ServiceTampering,
                    all ? $"{w.Name} is frozen" : $"{w.Name} has suspended threads",
                    $"{w.Name} ({w.Role}) shows as running, but {(all ? "every one of its threads is" : $"{frozen} of its {threads.Count} threads are")} " +
                    "suspended. Windows does not suspend service threads by itself; a tool that freezes them stops the service " +
                    $"recording while it still looks normal (process {s.Pid}).");
            }
            if (w.Name is "bam" or "dam" && DriverThreadsStarted($"{w.Name}.sys") is { } loaded && loaded - ctx.BootUtc > TimeSpan.FromMinutes(10))
            {
                notes.Add($"driver threads started {Util.When.L(loaded)}");
                if (state == CheckState.Ok) state = CheckState.Warning;
                bool update = updates.Any(u => (u - loaded).Duration() < TimeSpan.FromMinutes(30));
                ctx.Flag(update ? Severity.Low : Severity.Medium, FindingCategory.ServiceTampering, $"{w.Name} driver reloaded after boot",
                    $"The oldest thread of the {w.Name}.sys driver was created {Util.When.L(loaded)}, {(loaded - ctx.BootUtc).TotalMinutes:0} min after boot, " +
                    $"so the driver was stopped and loaded again. Reloading it drops the execution times it was holding." +
                    (update ? " A Windows update was being installed around then." : ""), timeUtc: loaded);
            }

            // Registry write times move when a service's start type or settings change. Windows updates
            // touch them too, so a recent change is a lead, not proof.
            if (changed is { } c && ctx.OsInstallUtc is { } install && c > install.AddDays(1) && ctx.NowUtc - c < TimeSpan.FromDays(14) && w.Critical)
            {
                notes.Add($"settings changed {Util.When.L(c)}");
                if (state == CheckState.Ok) state = CheckState.Warning;
                ctx.Flag(Severity.Low, FindingCategory.ServiceTampering, $"{w.Name} settings changed recently",
                    $"The configuration of {w.Name} ({w.Role}) was last changed {Util.When.L(c)}. Windows updates can do this; check the " +
                    "service history for a start-type change around that time.", timeUtc: c);
            }

            ctx.Services.Add(new ServiceRow
            {
                Name = w.Name, Role = w.Role, StartType = WinApi.StartTypeName(s.StartType), State = s.State,
                ProcessStartUtc = s.ProcessStartUtc, ConfigChangedUtc = changed, Status = state,
                Note = notes.Count == 0 ? "OK" : string.Join("; ", notes),
            });
            items++;
        }
        items += History(ctx, updates);
        return items;
    }

    /// <summary>
    /// When the oldest kernel thread that starts inside a driver was created, or null when the driver runs no thread of
    /// its own (or we are not administrator, which hides kernel addresses).
    /// </summary>
    static DateTime? DriverThreadsStarted(string driverFile)
    {
        if (WinApi.DriverRange(driverFile) is not { } range || range.Start == 0) return null;
        return WinApi.Threads(4).Where(t => t.StartAddress >= range.Start && t.StartAddress < range.End && t.CreatedUtc != null)
            .Select(t => t.CreatedUtc).Min();
    }

    /// <summary>Service Control Manager history for the watched services (locale-independent via the Binary field).</summary>
    static int History(BypassContext ctx, IReadOnlyList<DateTime> updates)
    {
        var watched = Services.ToDictionary(s => s.Name, StringComparer.OrdinalIgnoreCase);
        int items = 0;
        foreach (var r in Events.Read("System",
                     "*[System[Provider[@Name='Service Control Manager'] and (EventID=7036 or EventID=7040 or EventID=7034 or EventID=7031)]]", 20000))
        {
            var data = Events.Data(r);
            string name = r.Id == 7040 && data.TryGetValue("param4", out var p4) && p4.Length > 0
                ? p4 : Events.Binary(r) ?? data.GetValueOrDefault("param1") ?? "";
            if (!watched.TryGetValue(name, out var w) || Events.Utc(r) is not { } t) continue;
            string change;
            Severity? severity = null;
            string title = "", detail = "";
            switch (r.Id)
            {
                case 7036:
                    var st = data.GetValueOrDefault("param2") ?? "";
                    change = $"entered state: {st}";
                    if (st.Contains("stopped", StringComparison.OrdinalIgnoreCase) && !ctx.NearShutdown(t))
                    {
                        (severity, var note) = ServiceJudge.Stop(w.Name, t, updates);
                        (title, detail) = ($"{w.Name} service stopped", $"{w.Name} ({w.Role}) stopped at {Util.When.L(t)}, outside of a shutdown. {note}");
                    }
                    break;
                case 7040:
                    string from = data.GetValueOrDefault("param2") ?? "?", to = data.GetValueOrDefault("param3") ?? "?";
                    change = $"start type {from} → {to}";
                    (severity, var why) = ServiceJudge.StartTypeChange(w.Name, to, ServiceJudge.BySystem(r));
                    (title, detail) = ($"{w.Name} start type changed", $"{w.Name} ({w.Role}) was changed from \"{from}\" to \"{to}\" at {Util.When.L(t)}. {why}");
                    break;
                default:
                    change = r.Id == 7034 ? "terminated unexpectedly (killed or crashed)" : "terminated unexpectedly; Windows restarted it";
                    // Search and telemetry crash on their own often enough that only evidence services count.
                    if (ServiceJudge.Critical.Contains(w.Name))
                        (severity, title, detail) = (Severity.Medium, $"{w.Name} was killed",
                            $"{w.Name} ({w.Role}) {change} at {Util.When.L(t)}. Killing it from Task Manager or a process tool looks like this; a genuine crash looks the same.");
                    break;
            }
            if (severity is { } level)
                ctx.Flag(level, FindingCategory.ServiceTampering, title, detail.TrimEnd(), timeUtc: t);
            ctx.ServiceEvents.Add(new ServiceEvent { TimeUtc = t, Service = w.Name, Change = change, EventId = r.Id, Suspicious = severity >= Severity.Medium });
            items++;
        }
        return items;
    }
}
