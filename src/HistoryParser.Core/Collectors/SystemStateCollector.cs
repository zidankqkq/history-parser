using System.Diagnostics;
using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// "Is the evidence trustworthy and recent?" — checks that the services and settings which produce
/// the artifacts are enabled, and that the processes holding memory evidence have not been restarted.
/// </summary>
public sealed class SystemStateCollector : ICollector
{
    public string Name => "System state";

    sealed record Watched(string Service, string Feeds, bool Critical);

    static readonly Watched[] Services =
    [
        new("SysMain", "Prefetch files", true),
        new("bam", "BAM execution records", true),
        new("DPS", "DPS memory strings", true),
        new("PcaSvc", "PCA launch records and memory strings", true),
        new("EventLog", "all event logs", true),
        new("DiagTrack", "DiagTrack memory strings", false),
        new("WSearch", "search index", false),
    ];

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        ctx.Check("General", "Running as administrator", WinApi.IsElevated() ? CheckState.Ok : CheckState.Bad,
            WinApi.IsElevated() ? "Full access." : "Not elevated: Prefetch, USN journal, Security log and service memory are unreadable.");

        var uptime = ctx.NowUtc - ctx.BootUtc;
        ctx.Check("General", "Time since boot",
            uptime < TimeSpan.FromMinutes(15) ? CheckState.Warning : CheckState.Ok,
            $"Booted {Util.When.L(ctx.BootUtc)} ({uptime.TotalHours:0.#} h ago)." +
            (uptime < TimeSpan.FromMinutes(15) ? " A fresh reboot wipes all memory-based evidence." : ""));

        CheckPrefetchSetting(ctx);
        var updates = Bypass.ServiceJudge.UpdateTimes();
        foreach (var w in Services) CheckService(ctx, w, updates);
        CheckExplorer(ctx);
        return 0;
    }

    static void CheckPrefetchSetting(ScanContext ctx)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
        var value = key?.GetValue("EnablePrefetcher");
        switch (value)
        {
            case int v when v == 0:
                ctx.Check("Prefetch", "EnablePrefetcher", CheckState.Bad, "Prefetch is disabled in the registry (EnablePrefetcher = 0).");
                ctx.Flag(Severity.High, FindingCategory.Integrity, "Prefetch disabled",
                    "EnablePrefetcher is 0, so Windows is not recording program runs in Prefetch.");
                break;
            case int v when v is 1 or 2:
                ctx.Check("Prefetch", "EnablePrefetcher", CheckState.Warning,
                    $"EnablePrefetcher = {v} (partial; Windows default is 3 = applications + boot).");
                break;
            case int v:
                ctx.Check("Prefetch", "EnablePrefetcher", CheckState.Ok, $"EnablePrefetcher = {v}.");
                break;
            default:
                ctx.Check("Prefetch", "EnablePrefetcher", CheckState.Unknown, "Value not present (Windows uses its default).");
                break;
        }
    }

    static void CheckService(ScanContext ctx, Watched w, IReadOnlyList<DateTime> updates)
    {
        var s = WinApi.QueryService(w.Service);
        string startType = WinApi.StartTypeName(s.StartType);
        if (!s.Exists)
        {
            ctx.Check("Services", w.Service, w.Critical ? CheckState.Bad : CheckState.Warning,
                $"Not installed — {w.Feeds} unavailable.");
            return;
        }

        var problems = new List<string>();
        var state = CheckState.Ok;
        if (s.IsDisabled) { problems.Add("disabled"); state = w.Critical ? CheckState.Bad : CheckState.Warning; }
        // Kernel drivers like bam report through the SCM as well; "Unknown" means we could not query it.
        if (!s.IsRunning && s.State != "Unknown") { problems.Add($"not running ({s.State})"); state = w.Critical ? CheckState.Bad : CheckState.Warning; }

        string detail = $"{startType}, {s.State}";
        if (s.ProcessStartUtc is { } started)
        {
            detail += $", process started {Util.When.L(started)}";
            if (started - ctx.BootUtc > TimeSpan.FromMinutes(10))
            {
                problems.Add("restarted after boot");
                if (state == CheckState.Ok) state = CheckState.Warning;
                if (w.Service is "DPS" or "PcaSvc" or "DiagTrack")
                {
                    // Windows starts on-demand services when first needed and restarts services while installing updates.
                    bool onDemand = s.StartType == 3;
                    bool update = updates.Any(u => (u - started).Duration() < TimeSpan.FromMinutes(30));
                    string why = onDemand ? " It is set to start on demand, so Windows may simply have started it late."
                        : update ? " A Windows update was being installed around then, which restarts services."
                        : "";
                    ctx.Flag(onDemand || update || !w.Critical ? Severity.Low : Severity.Medium, FindingCategory.Integrity, $"{w.Service} restarted after boot",
                        $"{w.Service} was (re)started at {Util.When.L(started)}, {(started - ctx.BootUtc).TotalMinutes:0} min after boot. " +
                        "Restarting it wipes the program paths it keeps in memory." + why, timeUtc: started);
                }
            }
        }
        detail += $" — feeds {w.Feeds}.";
        if (problems.Count > 0) detail = $"Problem: {string.Join(", ", problems)}. " + detail;

        // A stopped on-demand service may just be idle; disabled or a stopped automatic one is not.
        if (w.Critical && (s.IsDisabled || (!s.IsRunning && s.State != "Unknown")))
        {
            bool idle = !s.IsDisabled && s.StartType == 3;
            ctx.Flag(idle ? Severity.Medium : Severity.High, FindingCategory.Integrity, $"{w.Service} is {(s.IsDisabled ? "disabled" : "stopped")}",
                $"{w.Service} produces {w.Feeds}. While it is off, that evidence is not recorded." +
                (idle ? " It is set to start on demand, so Windows may only have stopped it while idle; check the service history for who changed it." : ""));
        }
        ctx.Check("Services", w.Service, state, detail);
    }

    static void CheckExplorer(ScanContext ctx)
    {
        var explorers = Process.GetProcessesByName("explorer");
        try
        {
            if (explorers.Length == 0)
            {
                ctx.Check("Processes", "explorer.exe", CheckState.Warning, "Explorer is not running.");
                return;
            }
            foreach (var p in explorers)
            {
                var started = WinApi.GetProcessStartUtc(p.Id);
                if (started is not { } s) continue;
                bool late = s - ctx.BootUtc > TimeSpan.FromMinutes(10);
                ctx.Check("Processes", $"explorer.exe (pid {p.Id})", late ? CheckState.Warning : CheckState.Ok,
                    $"Started {Util.When.L(s)}." + (late
                        ? " Well after boot: Explorer was restarted (wiping its memory strings), or the user signed in later than Windows started — common with Fast Startup, where one boot spans several shutdowns."
                        : ""));
            }
        }
        finally
        {
            foreach (var p in explorers) p.Dispose();
        }
    }
}
