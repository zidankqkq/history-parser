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
    public ConcurrentBag<RouteCheck> Routes { get; } = new();

    public void Route(string area, string item, string value, CheckState state, string detail = "", string path = "", DateTime? timeUtc = null) =>
        Routes.Add(new RouteCheck { Area = area, Item = item, Value = value, State = state, Detail = detail, Path = path, TimeUtc = timeUtc });

    /// <summary>True when an event happened within a few minutes of a shutdown (services stop then).</summary>
    public bool NearShutdown(DateTime t) => ShutdownTimes.Any(s => Math.Abs((s - t).TotalMinutes) < 5);

    public void Flag(Severity severity, FindingCategory category, string title, string detail, string? path = null, DateTime? timeUtc = null) =>
        Findings.Add(new Finding { Severity = severity, Category = category, Title = title, Detail = detail, Path = path, TimeUtc = timeUtc });
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
