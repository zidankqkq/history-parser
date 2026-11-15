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
            // 1 = programs, 2 = boot only, 3 = both. With 2, Windows still prefetches its own startup but writes nothing for
            // the programs a person runs - the same blind spot as 0, without the value everyone checks for.
            case int v when v == 2:
                ctx.Check("Prefetch", "EnablePrefetcher", CheckState.Bad, "EnablePrefetcher = 2: Prefetch records Windows' own startup only, not the programs that are run.");
                ctx.Flag(Severity.High, FindingCategory.Integrity, "Prefetch switched off for programs",
                    "EnablePrefetcher is 2 (boot only), so Windows is not recording program runs in Prefetch. The Windows default is 3; " +
                    "2 looks less obvious than 0 but hides exactly the same thing.");
                break;
            case int v when v == 1:
                ctx.Check("Prefetch", "EnablePrefetcher", CheckState.Warning,
                    "EnablePrefetcher = 1 (programs only; the Windows default is 3 = programs + boot). Program runs are still recorded.");
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

    /// <summary>
    /// The desktop shell keeps the paths of programs opened from it in memory, and restarting it wipes them. It starts when
    /// the user signs in, so it is judged against the sign-in: a start well after that is a restart. Only the shell is
    /// judged (the process that owns the desktop), never the extra Explorer processes Windows starts for folder windows.
    /// </summary>
    static void CheckExplorer(ScanContext ctx)
    {
        if (SessionTimes.ShellStart() is not { } shell)
        {
            ctx.Check("Processes", "explorer.exe", CheckState.Warning, "The desktop shell (Explorer) is not running.");
            // Closing Explorer wipes what it kept in memory just as a restart does. Only said for a signed-in desktop:
            // a session without one (a service, a build agent) has no shell to begin with.
            if (ctx.SignInUtc != null && Environment.UserInteractive)
                ctx.Flag(ctx.Games.Count > 0 ? Severity.Medium : Severity.Low, FindingCategory.Integrity, ShellClosed,
                    "No program owns the desktop: Explorer was closed and not started again. It keeps the paths of the programs opened from it " +
                    "in memory, and closing it wipes them." + (ctx.Games.Count > 0 ? " The game is running." : ""));
            return;
        }
        ctx.ShellStartUtc = shell.StartUtc;
        var (state, detail, finding) = JudgeShell(shell.StartUtc, ctx.BootUtc, ctx.SignInUtc, ctx.Games.Count > 0 ? ctx.Games[0].StartUtc : null);
        ctx.Check("Processes", $"explorer.exe (pid {shell.Pid})", state, detail);
        if (finding is { } f) ctx.Flag(f.Severity, FindingCategory.Integrity, f.Title, f.Detail, timeUtc: shell.StartUtc);
    }

    /// <summary>How long after the sign-in (or the boot) the shell may start and still count as started with it.</summary>
    internal static readonly TimeSpan ShellGrace = TimeSpan.FromMinutes(10);

    public const string ShellRestarted = "Explorer was restarted after sign-in";
    public const string ShellClosed = "Explorer is not running";

    internal static (CheckState State, string Detail, (Severity Severity, string Title, string Detail)? Finding) JudgeShell(
        DateTime started, DateTime bootUtc, DateTime? signInUtc, DateTime? gameUtc)
    {
        if (signInUtc is not { } signIn)
        {
            // Without the sign-in only the boot is left to compare with, and one boot can span several sign-ins.
            bool late = started - bootUtc > ShellGrace;
            return (late ? CheckState.Warning : CheckState.Ok, $"Started {Util.When.L(started)}." + (late
                ? " Well after boot: Explorer was restarted (wiping its memory strings), or the user signed in later than Windows started — the sign-in time could not be read to tell which."
                : ""), null);
        }
        var after = started - signIn;
        if (after <= ShellGrace) return (CheckState.Ok, $"Started {Util.When.L(started)}, with the sign-in at {Util.When.L(signIn)}.", null);

        string gap = Analysis.Correlator.FormatGap(after);
        bool duringGame = gameUtc is { } game && started > game;
        return (CheckState.Warning, $"Restarted {Util.When.L(started)}, {gap} after the sign-in at {Util.When.L(signIn)}.",
            (duringGame ? Severity.Medium : Severity.Low, ShellRestarted,
                $"The desktop shell (explorer.exe) started at {Util.When.L(started)}, {gap} after the sign-in at {Util.When.L(signIn)}, so it was restarted. " +
                "Explorer keeps the paths of the programs opened from it in memory, and a restart wipes them." +
                (duringGame ? $" The game was already running (started {Util.When.L(gameUtc)})." : " It also restarts after a crash or an update.")));
    }
}
