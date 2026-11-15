using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Bypass;

/// <summary>Thread-safe sink the bypass audits (which run in parallel) write into.</summary>
public sealed class BypassContext
{
    public BypassContext(ScanResult history, ArgumentRules argumentRules, KeywordLists keywords)
    {
        History = history;
        ArgumentRules = argumentRules;
        Keywords = keywords;
        NowUtc = history.StartedUtc;
        BootUtc = history.Machine.BootTimeUtc;
        OsInstallUtc = history.Machine.OsInstallUtc;
        ShutdownTimes = history.Timeline
            .Where(e => e.Source == EvidenceSource.EventLog && e.TimeUtc.HasValue &&
                        (e.Path.Contains("shut down", StringComparison.OrdinalIgnoreCase) ||
                         e.Path.Contains("stopped (shutdown)", StringComparison.OrdinalIgnoreCase)))
            .Select(e => e.TimeUtc!.Value).ToList();
    }

    public ScanResult History { get; }
    public ArgumentRules ArgumentRules { get; }
    public KeywordLists Keywords { get; }
    /// <summary>Whether to read Minecraft and launcher logs for launch arguments.</summary>
    public bool ReadGameLogs { get; init; } = true;
    public DateTime NowUtc { get; }
    public DateTime BootUtc { get; }
    public DateTime? OsInstallUtc { get; }
    public IReadOnlyList<DateTime> ShutdownTimes { get; }

    /// <summary>When this program was opened (before the scan was started from its window). Anything later happened in front of it.</summary>
    public DateTime OpenedUtc { get; init; } = OwnStart();

    static DateTime OwnStart()
    {
        try { using var self = System.Diagnostics.Process.GetCurrentProcess(); return self.StartTime.ToUniversalTime(); }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { return DateTime.UtcNow; }
    }

    /// <summary>Checks of whether the PC is still recording, shown with the history scan's own on the integrity page.</summary>
    public ConcurrentBag<IntegrityCheck> Checks { get; } = new();

    public void Check(string area, string name, CheckState state, string detail) => Checks.Add(new IntegrityCheck(area, name, state, detail));

    public ConcurrentBag<Finding> Findings { get; } = new();
    public ConcurrentBag<LogChannelInfo> Logs { get; } = new();
    public ConcurrentBag<RecordGap> RecordGaps { get; } = new();
    public ConcurrentBag<ServiceRow> Services { get; } = new();
    public ConcurrentBag<ServiceEvent> ServiceEvents { get; } = new();
    public ConcurrentBag<UsbDevice> UsbDevices { get; } = new();
    public ConcurrentBag<UsbEvent> UsbEvents { get; } = new();
    public ConcurrentBag<ArgumentHit> Arguments { get; } = new();
    public ConcurrentBag<DriverRow> Drivers { get; } = new();
    public ConcurrentBag<TaskRow> Tasks { get; } = new();
    public ConcurrentBag<SoftwareRow> Software { get; } = new();
    public ConcurrentBag<ArtifactChange> Artifacts { get; } = new();
    public ConcurrentBag<DefenderChange> Defender { get; } = new();
    public ConcurrentBag<DefenderDetection> Detections { get; } = new();
    /// <summary>The antivirus as it is now, one row per fact, in the order they were added.</summary>
    public ConcurrentQueue<IntegrityCheck> Antivirus { get; } = new();
    public ConcurrentBag<RouteCheck> Routes { get; } = new();

    /// <summary>The audits raise a finding straight after the check it comes from. This keeps the two together for whoever wants one row per check.</summary>
    public ConcurrentDictionary<RouteCheck, Finding> PairedFindings { get; } = new();
    [ThreadStatic] static RouteCheck? _lastRoute;

    public void Route(string area, string item, string value, CheckState state, string detail = "", string path = "", DateTime? timeUtc = null)
    {
        var route = new RouteCheck { Area = area, Item = item, Value = value, State = state, Detail = detail, Path = path, TimeUtc = timeUtc };
        Routes.Add(route);
        _lastRoute = state is CheckState.Bad or CheckState.Warning ? route : null;
    }

    /// <summary>True when an event happened within a few minutes of a shutdown (services stop then).</summary>
    public bool NearShutdown(DateTime t) => ShutdownTimes.Any(s => Math.Abs((s - t).TotalMinutes) < 5);

    public void Flag(Severity severity, FindingCategory category, string title, string detail, string? path = null, DateTime? timeUtc = null)
    {
        var finding = new Finding { Severity = severity, Category = category, Title = title, Detail = detail, Path = path, TimeUtc = timeUtc };
        Findings.Add(finding);
        if (_lastRoute is { } route) PairedFindings.TryAdd(route, finding);
        _lastRoute = null;
    }
}

/// <summary>Event-log reading helpers shared by the audits.</summary>
internal static class Events
{
    /// <summary>Records matching <paramref name="xpath"/>, newest first by default; nothing if the log is missing or unreadable.</summary>
    public static IEnumerable<EventRecord> Read(string log, string xpath = "*", int max = 5000, bool newestFirst = true)
    {
        EventLogReader reader;
        try { reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = newestFirst }); }
        catch (Exception e) when (e is EventLogException or UnauthorizedAccessException) { yield break; }
        using (reader)
        {
            for (int n = 0; n < max; n++)
            {
                EventRecord? r;
                try { r = reader.ReadEvent(); }
                catch (Exception e) when (e is EventLogException or UnauthorizedAccessException) { yield break; }
                if (r == null) yield break;
                using (r) yield return r;
            }
        }
    }

    static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    /// <summary>Named EventData values (case-insensitive).</summary>
    public static Dictionary<string, string> Data(EventRecord r)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var e in XDocument.Parse(r.ToXml()).Descendants(Ns + "Data"))
                if ((string?)e.Attribute("Name") is { } name) d[name] = e.Value;
        }
        catch (Exception e) when (e is EventLogException or System.Xml.XmlException) { }
        return d;
    }

    public static string? Binary(EventRecord r)
    {
        try
        {
            var hex = XDocument.Parse(r.ToXml()).Descendants(Ns + "Binary").FirstOrDefault()?.Value;
            if (string.IsNullOrEmpty(hex) || hex.Length % 4 != 0) return null;
            return System.Text.Encoding.Unicode.GetString(Convert.FromHexString(hex)).TrimEnd('\0');
        }
        catch (Exception e) when (e is EventLogException or FormatException or System.Xml.XmlException) { return null; }
    }

    public static DateTime? Utc(EventRecord r) => r.TimeCreated?.ToUniversalTime();
}
