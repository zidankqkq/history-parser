using System.Diagnostics.Eventing.Reader;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// How much a service stop or start-type change means. Shared by both apps so they never disagree.
/// Windows changes services itself all the time (updates, trigger-start services stopping when idle),
/// so the account that made a change and what else was happening at the time decide the severity.
/// </summary>
public static class ServiceJudge
{
    /// <summary>Services whose loss stops evidence being recorded. Search, telemetry etc. are context only.</summary>
    public static readonly HashSet<string> Critical = new(StringComparer.OrdinalIgnoreCase)
        { "SysMain", "bam", "DPS", "PcaSvc", "EventLog", "Sysmon", "Sysmon64" };

    /// <summary>LocalSystem, LocalService, NetworkService: Windows (or an installer) acting on its own.</summary>
    public static bool BySystem(EventRecord r)
    {
        try { return r.UserId?.Value is "S-1-5-18" or "S-1-5-19" or "S-1-5-20"; }
        catch (EventLogException) { return false; }
    }

    /// <summary>Severity for event 7040, or null when it is not worth a finding.</summary>
    public static (Severity? Severity, string Note) StartTypeChange(string service, string to, bool bySystem)
    {
        bool critical = Critical.Contains(service);
        bool disabled = to.Contains("disabled", StringComparison.OrdinalIgnoreCase);
        bool manual = to.Contains("demand", StringComparison.OrdinalIgnoreCase) || to.Contains("manual", StringComparison.OrdinalIgnoreCase);
        string who = bySystem
            ? " The change was made by the SYSTEM account, which is how Windows updates and installers change services."
            : " The change was made by a user account, not by Windows itself.";

        if (!disabled && !manual)   // back to automatic: turning it on is never the bypass
            return (bySystem ? null : Severity.Low, "It was set to start automatically." + who);
        if (!critical)
            return (bySystem ? null : Severity.Low, who.Trim());
        if (disabled)
            return (bySystem ? Severity.Medium : Severity.High, who.Trim());
        return (bySystem ? Severity.Low : Severity.Medium, who.Trim());
    }

    /// <summary>Severity for a 7036 "stopped" outside a shutdown, or null when it is not worth a finding.</summary>
    public static (Severity? Severity, string Note) Stop(string service, DateTime t, IReadOnlyList<DateTime> updates)
    {
        if (!Critical.Contains(service)) return (null, "");
        if (updates.Any(u => u - t < TimeSpan.FromMinutes(30) && t - u < TimeSpan.FromMinutes(10)))
            return (Severity.Low, "A Windows update was being installed at the time, which stops and restarts services.");
        // Trigger-start services (PcaSvc on some builds, DPS when idle) stop by themselves.
        if (WinApi.QueryService(service).StartType == 3)
            return (Severity.Low, "This service is set to start on demand, and Windows stops such services when they are idle.");
        return (Severity.Medium, "");
    }

    /// <summary>When Windows Update finished installing something (19 = installed, 20 = failed, 43 = started).</summary>
    public static List<DateTime> UpdateTimes()
    {
        var times = new List<DateTime>();
        try
        {
            var q = new EventLogQuery("System", PathType.LogName,
                "*[System[Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19 or EventID=20 or EventID=43)]]");
            using var reader = new EventLogReader(q);
            for (var r = reader.ReadEvent(); r != null && times.Count < 5000; r = reader.ReadEvent())
                using (r)
                    if (r.TimeCreated is { } tc) times.Add(tc.ToUniversalTime());
        }
        catch (Exception e) when (e is EventLogException or UnauthorizedAccessException) { }
        return times;
    }
}
