using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// The session's reference times, gathered into one list: Windows installed, PC started, signed in, Explorer started, game
/// started, recording services started, clock changed, Recycle Bin changed, USB drive removed, scanned. Every other time
/// in a scan is read against these. Nothing is judged here that is not judged where the fact was read: a mark only repeats
/// the state its own check gave it.
/// </summary>
public static class SessionAudit
{
    /// <summary>How long after startup a service may start and still count as started with Windows (the same allowance the service checks use).</summary>
    static readonly TimeSpan StartupGrace = TimeSpan.FromMinutes(10);

    public static List<SessionMark> Marks(BypassContext ctx) => Marks(ctx.History.Machine, ctx.NowUtc, ctx.OpenedUtc,
        ctx.Services, ctx.UsbDevices, ctx.History.ClockChanges, RecycleBinChangedUtc());

    internal static List<SessionMark> Marks(MachineInfo machine, DateTime nowUtc, DateTime openedUtc, IEnumerable<ServiceRow> services,
        IEnumerable<UsbDevice> usb, IEnumerable<ClockChange> clock, DateTime? recycleBinUtc)
    {
        var marks = new List<SessionMark>();
        void Add(string what, DateTime? time, string detail = "", CheckState state = CheckState.Ok) =>
            marks.Add(new SessionMark { What = what, TimeUtc = time, Detail = detail, State = state });

        if (machine.OsInstallUtc is { } installed)
        {
            bool fresh = nowUtc - installed < TimeSpan.FromDays(2);
            Add("Windows installed", installed, fresh ? "Under two days ago: there is little history to read" : "", fresh ? CheckState.Warning : CheckState.Ok);
        }

        bool justStarted = nowUtc - machine.BootTimeUtc < TimeSpan.FromMinutes(15);
        Add("PC started", machine.BootTimeUtc, justStarted ? "Minutes ago: what programs kept in memory is gone" : "", justStarted ? CheckState.Warning : CheckState.Ok);

        if (machine.SignInUtc is { } signIn) Add("Signed in", signIn);

        if (machine.ShellStartUtc is { } shell)
        {
            var (state, _, finding) = SystemStateCollector.JudgeShell(shell, machine.BootTimeUtc, machine.SignInUtc, machine.GameStartUtc);
            Add("Explorer started", shell,
                finding != null ? "Restarted after sign-in" : state == CheckState.Warning ? "Well after the PC started" : "", state);
        }

        // Every game that is running, so a second one is never out of sight. Earlier starts are listed with the games, not here.
        var running = machine.Games.Where(g => g.Pid != null && !g.Unrecognised).OrderBy(g => g.StartUtc).ToList();
        foreach (var game in running) Add("Game started", game.StartUtc, $"{game.Program} (pid {game.Pid})");
        if (running.Count == 0)
        {
            if (machine.GameStartUtc is { } only) Add("Game started", only, machine.GameProgram); // a report from before the games were listed
            else Add("Game", null, "Not running", CheckState.Unknown);
        }

        var started = services.Where(s => s.ProcessStartUtc.HasValue).ToList();
        var late = started.Where(s => s.ProcessStartUtc!.Value - machine.BootTimeUtc > StartupGrace).OrderBy(s => s.ProcessStartUtc).ToList();
        foreach (var service in late)
            Add($"{service.Name} started", service.ProcessStartUtc, "Well after the PC started", CheckState.Warning);
        if (late.Count == 0 && started.Count > 0)
            Add("Recording services started", started.Max(s => s.ProcessStartUtc), "With the PC");

        if (clock.Where(c => c.Severity >= Severity.Medium || c.IsRollback).OrderByDescending(c => c.NewTimeUtc).FirstOrDefault() is { } change)
            Add("Clock changed", change.NewTimeUtc,
                $"Moved {(change.IsRollback ? "back" : "forward")} {Analysis.Correlator.FormatGap(change.Delta)}", CheckState.Warning);

        if (recycleBinUtc is { } bin)
        {
            bool during = bin > openedUtc;
            Add("Recycle Bin last changed", bin, during ? "After this program was opened" : "", during ? CheckState.Warning : CheckState.Ok);
        }

        if (usb.Where(d => d.LastRemovedUtc.HasValue).OrderByDescending(d => d.LastRemovedUtc).FirstOrDefault() is { } removed)
        {
            bool during = removed.LastRemovedUtc > openedUtc;
            Add("USB device removed", removed.LastRemovedUtc, during ? $"{removed.Name} · after this program was opened" : removed.Name,
                during ? CheckState.Warning : CheckState.Ok);
        }

        Add("Scanned", nowUtc);
        return marks.OrderBy(m => m.TimeUtc == null).ThenBy(m => m.TimeUtc).ToList();
    }

    /// <summary>
    /// When the signed-in user's Recycle Bin folders last changed, on any fixed drive: moving a file in, restoring one and
    /// emptying the bin all write to that folder.
    /// </summary>
    static DateTime? RecycleBinChangedUtc()
    {
        string sid;
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            sid = identity.User?.Value ?? "";
        }
        catch (System.Security.SecurityException) { return null; }
        if (sid.Length == 0) return null;

        DateTime? latest = null;
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                var bin = new DirectoryInfo(Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin", sid));
                if (bin.Exists && (latest == null || bin.LastWriteTimeUtc > latest)) latest = bin.LastWriteTimeUtc;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return latest;
    }
}
