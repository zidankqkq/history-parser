using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Text;
using System.Xml.Linq;
using HistoryParser.Core.Models;
using HistoryParser.Core.Parsers;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Windows event logs: clock changes, cleared logs, forensic services being stopped/disabled,
/// newly installed services and drivers, and boots/shutdowns for context.
/// </summary>
public sealed class EventLogCollector : ICollector
{
    public string Name => "Event logs";

    /// <summary>Services whose stopping or disabling erases or pauses the evidence this tool reads.</summary>
    internal static readonly Dictionary<string, string> WatchedServices = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SysMain"] = "Prefetch", ["DPS"] = "DPS memory strings", ["PcaSvc"] = "PCA launch records",
        ["EventLog"] = "event logging", ["DiagTrack"] = "diagnostic tracking", ["bam"] = "BAM", ["Sysmon"] = "Sysmon",
        ["Sysmon64"] = "Sysmon", ["WSearch"] = "search indexing",
    };

    static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        int items = 0;
        var errors = new List<string>();
        var shutdowns = new List<DateTime>();

        Run(errors, "System boots", () =>
        {
            foreach (var r in Query("System",
                         "*[System[(Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12 or EventID=13)) or " +
                         "(Provider[@Name='EventLog'] and (EventID=6005 or EventID=6006 or EventID=6008))]]"))
            {
                if (r.TimeCreated is not { } local) continue;
                var t = local.ToUniversalTime();
                bool isShutdown = r.Id is 13 or 6006;
                if (isShutdown) shutdowns.Add(t);
                string label = r.Id switch
                {
                    12 => "Windows started", 13 => "Windows shut down", 6005 => "Event log service started",
                    6006 => "Event log service stopped (shutdown)", 6008 => "Previous shutdown was unexpected", _ => "",
                };
                ctx.Add(new Evidence
                {
                    Source = EvidenceSource.EventLog, Kind = EvidenceKind.Presence, Path = "[System] " + label,
                    TimeUtc = t, Origin = $"System/{r.Id}", Detail = label,
                });
                items++;
            }
        });

        Run(errors, "Clock changes (Kernel-General 1)", () =>
        {
            foreach (var r in Query("System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=1]]"))
            {
                var data = Data(r);
                if (ParseTime(data.GetValueOrDefault("OldTime")) is not { } oldT ||
                    ParseTime(data.GetValueOrDefault("NewTime")) is not { } newT) continue;
                string reason = data.GetValueOrDefault("Reason") ?? "";
                string process = Path.GetFileName(data.GetValueOrDefault("ProcessName") ?? "");
                if (ClassifyKernelGeneral(reason, process, newT - oldT) is not { } c) continue;
                items += RecordClockChange(ctx, "System event 1 (Kernel-General)", oldT, newT, c.Severity, c.Detail);
            }
        });

        Run(errors, "Clock changes (Security 4616)", () =>
        {
            foreach (var r in Query("Security", "*[System[EventID=4616]]"))
            {
                var data = Data(r);
                if (ParseTime(data.GetValueOrDefault("PreviousTime")) is not { } oldT ||
                    ParseTime(data.GetValueOrDefault("NewTime")) is not { } newT) continue;
                string process = Path.GetFileName(data.GetValueOrDefault("ProcessName") ?? "");
                if (ClassifyKernelGeneral("1", process, newT - oldT) is not { } c) continue;
                items += RecordClockChange(ctx, "Security event 4616", oldT, newT, c.Severity,
                    $"{c.Detail} (account {data.GetValueOrDefault("SubjectUserName")})");
            }
        });

        Run(errors, "Log clears", () =>
        {
            foreach (var (log, xpath) in new[]
                     {
                         ("System", "*[System[Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=104]]"),
                         ("Security", "*[System[EventID=1102]]"),
                     })
            {
                foreach (var r in Query(log, xpath))
                {
                    var t = r.TimeCreated?.ToUniversalTime();
                    var channel = XDocument.Parse(r.ToXml()).Descendants().FirstOrDefault(e => e.Name.LocalName == "Channel" && e.Parent?.Name.LocalName != "System")?.Value ?? log;
                    ctx.Flag(Severity.High, FindingCategory.AntiForensics, $"Event log cleared: {channel}",
                        $"The \"{channel}\" event log was cleared at {Util.When.L(t)}. Everything logged before that point is gone.",
                        timeUtc: t);
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.EventLog, Kind = EvidenceKind.Deleted, Path = $"[Event log] {channel} cleared",
                        TimeUtc = t, Origin = $"{log}/{r.Id}", Detail = "Log cleared",
                    });
                    items++;
                }
            }
        });

        // Needs the shutdown list from the first query.
        Run(errors, "Service changes", () =>
        {
            var updates = Bypass.ServiceJudge.UpdateTimes();
            foreach (var r in Query("System",
                         "*[System[Provider[@Name='Service Control Manager'] and (EventID=7036 or EventID=7040 or EventID=7045 or EventID=7034 or EventID=7031)]]"))
            {
                if (r.TimeCreated is not { } local) continue;
                var t = local.ToUniversalTime();
                var xml = XDocument.Parse(r.ToXml());
                var data = DataFrom(xml);

                if (r.Id == 7045)
                {
                    items += ServiceInstalled(ctx, data, t);
                    continue;
                }

                string service = data.GetValueOrDefault("param4") is { Length: > 0 } p4 && r.Id == 7040
                    ? p4 : BinaryServiceName(xml) ?? data.GetValueOrDefault("param1") ?? "";
                if (!WatchedServices.TryGetValue(service, out var role)) continue;

                if (r.Id == 7036)
                {
                    string state = data.GetValueOrDefault("param2") ?? "";
                    bool stopped = state.Contains("stopped", StringComparison.OrdinalIgnoreCase);
                    bool nearShutdown = shutdowns.Any(s => Math.Abs((s - t).TotalMinutes) < 5);
                    var (sev, note) = stopped && !nearShutdown ? Bypass.ServiceJudge.Stop(service, t, updates) : (null, "");
                    if (sev is { } level)
                        ctx.Flag(level, FindingCategory.Integrity, $"{service} service stopped",
                            $"{service} ({role}) entered the stopped state at {Util.When.L(t)}, outside of a shutdown. {note}".TrimEnd(), timeUtc: t);
                    ctx.ServiceEvents.Add(new Bypass.ServiceEvent
                    {
                        TimeUtc = t, Service = service, Change = $"entered state: {state}", EventId = 7036, Suspicious = sev >= Severity.Medium,
                    });
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.EventLog, Kind = EvidenceKind.Presence, Path = $"[Service] {service}",
                        TimeUtc = t, Origin = "System/7036", Detail = $"{service} entered state: {state}",
                    });
                    items++;
                }
                else if (r.Id == 7040)
                {
                    string from = data.GetValueOrDefault("param2") ?? "?", to = data.GetValueOrDefault("param3") ?? "?";
                    var (sev, note) = Bypass.ServiceJudge.StartTypeChange(service, to, Bypass.ServiceJudge.BySystem(r));
                    if (sev is { } level)
                        ctx.Flag(level, FindingCategory.Integrity, $"{service} start type changed",
                            $"{service} ({role}) was changed from \"{from}\" to \"{to}\" at {Util.When.L(t)}. {note}".TrimEnd(), timeUtc: t);
                    ctx.ServiceEvents.Add(new Bypass.ServiceEvent
                    {
                        TimeUtc = t, Service = service, Change = $"start type {from} → {to}", EventId = 7040, Suspicious = sev >= Severity.Medium,
                    });
                    ctx.Add(new Evidence
                    {
                        Source = EvidenceSource.EventLog, Kind = EvidenceKind.Modified, Path = $"[Service] {service}",
                        TimeUtc = t, Origin = "System/7040", Detail = $"Start type {from} → {to}",
                    });
                    items++;
                }
                else
                {
                    // 7034: ended unexpectedly; 7031: ended unexpectedly and Windows restarted it. Killing a
                    // service from Task Manager or a process tool produces exactly these.
                    string change = r.Id == 7034 ? "ended unexpectedly (killed or crashed)" : "ended unexpectedly; Windows restarted it";
                    // Search and telemetry crash on their own often enough that only evidence services count.
                    bool critical = Bypass.ServiceJudge.Critical.Contains(service);
                    if (critical)
                        ctx.Flag(Severity.Medium, FindingCategory.Integrity, $"{service} was killed",
                            $"{service} ({role}) {change} at {Util.When.L(t)}. Killing it from Task Manager or a process tool looks like this; a genuine crash looks the same.", timeUtc: t);
                    ctx.ServiceEvents.Add(new Bypass.ServiceEvent { TimeUtc = t, Service = service, Change = change, EventId = r.Id, Suspicious = critical });
                    items++;
                }
            }
        });

        if (ctx.Options.CheckEventLogOrdering)
        {
            Run(errors, "Record ordering", () =>
            {
                var order = new ClockOrderTracker(ctx.Options.Tolerance);
                int n = 0;
                var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName));
                using (reader)
                {
                    for (EventRecord? r = reader.ReadEvent(); r != null && n < 300_000; r = reader.ReadEvent(), n++)
                    {
                        using (r)
                        {
                            ct.ThrowIfCancellationRequested();
                            // The EventLog service's own events (6005 start, 6013 uptime, ...) are stamped when
                            // the service writes them, while events queued before a sleep/shutdown are flushed
                            // after them with their original, earlier times. They would fake a rollback.
                            if (r.ProviderName == "EventLog") continue;
                            if (r.TimeCreated is { } tc) order.Observe(tc.ToUniversalTime());
                        }
                    }
                }
                foreach (var (before, after) in order.Rollbacks)
                    ctx.ClockChanges.Add(new ClockChange
                    {
                        Source = "System event log order", OldTimeUtc = before, NewTimeUtc = after,
                        Detail = "A later event record carries an earlier time than the record before it.",
                    });
                ctx.Check("Event logs", "System log", CheckState.Ok,
                    $"{n:N0} records, {Util.When.L(order.Earliest)} → {Util.When.L(order.Latest)}.");
            });
        }

        if (errors.Count > 0)
            ctx.Check("Event logs", "Event log access", CheckState.Warning, string.Join("; ", errors));
        return items;
    }

    /// <summary>
    /// Kernel-General event 1 reasons: 1 = a program set the time, 2 = re-synced from the hardware
    /// clock (every resume from sleep/hibernate: a large forward jump that is completely normal),
    /// 3 = time-zone change. Returns null for changes that are not worth reporting.
    /// </summary>
    internal static (Severity Severity, string Detail)? ClassifyKernelGeneral(string reason, string process, TimeSpan delta)
    {
        if (delta.Duration() < TimeSpan.FromMinutes(1)) return null; // routine drift correction
        bool timeService = process.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);
        switch (reason)
        {
            case "2" when delta > TimeSpan.Zero:
            case "3":
                return null;
            case "2":
                return (Severity.High, "Hardware (BIOS/CMOS) clock is behind the system clock — it was set back.");
            default:
                if (timeService)
                    return (delta.Duration() > TimeSpan.FromMinutes(10) ? Severity.Medium : Severity.Low,
                        "Corrected by the Windows Time service. A large correction means the clock had been wrong.");
                return (delta.Duration() > TimeSpan.FromMinutes(5) ? Severity.High : Severity.Medium,
                    $"Changed by {(process.Length > 0 ? process : "an unknown process")} — someone set the time manually.");
        }
    }

    static int RecordClockChange(ScanContext ctx, string source, DateTime oldT, DateTime newT, Severity severity, string detail)
    {
        var delta = newT - oldT;
        ctx.ClockChanges.Add(new ClockChange
        {
            Source = source, OldTimeUtc = oldT, NewTimeUtc = newT, Detail = detail, Severity = severity,
        });
        ctx.Add(new Evidence
        {
            Source = EvidenceSource.EventLog, Kind = EvidenceKind.Modified, Path = "[System] Clock changed",
            TimeUtc = newT, Origin = source,
            Detail = $"System time changed {Util.When.L(oldT)} → {Util.When.L(newT)} ({FormatDelta(delta)}) {detail}".Trim(),
        });
        return 1;
    }

    static int ServiceInstalled(ScanContext ctx, Dictionary<string, string> data, DateTime t)
    {
        string name = data.GetValueOrDefault("ServiceName") ?? "?";
        string image = data.GetValueOrDefault("ImagePath") ?? "";
        string type = data.GetValueOrDefault("ServiceType") ?? "";
        string path = ctx.Paths.Normalize(StripImagePath(image));
        bool isDriver = type.Contains("kernel", StringComparison.OrdinalIgnoreCase) ||
                        type.Contains("driver", StringComparison.OrdinalIgnoreCase) ||
                        path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
        ctx.Add(new Evidence
        {
            Source = EvidenceSource.EventLog, Kind = EvidenceKind.Created,
            Path = path.Length > 0 ? path : $"[Service] {name}", TimeUtc = t, Origin = "System/7045",
            Detail = $"{(isDriver ? "Driver" : "Service")} \"{name}\" installed ({type}, start: {data.GetValueOrDefault("StartType")})",
        });
        if (isDriver && !FileTypes.IsWindowsFile(path))
        {
            // Installed software (anti-cheats, RGB, hardware tools) keeps drivers in Program Files;
            // a driver loaded from Downloads/Temp/Desktop is how driver mappers get kernel access.
            bool installed = path.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) ||
                             path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase);
            ctx.Flag(installed ? Severity.Low : Severity.Medium, FindingCategory.Driver, $"Kernel driver installed: {name}",
                $"Driver \"{name}\" from {image} was installed at {Util.When.L(t)}." +
                (installed ? "" : " It is not in Program Files — kernel cheats and driver mappers load drivers this way."),
                path, t);
        }
        return 1;
    }

    internal static string StripImagePath(string image)
    {
        var s = image.Trim();
        if (s.StartsWith('"'))
        {
            int end = s.IndexOf('"', 1);
            return end > 0 ? s[1..end] : s.Trim('"');
        }
        int dotSys = s.IndexOf(".sys", StringComparison.OrdinalIgnoreCase);
        int dotExe = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        int cut = new[] { dotSys, dotExe }.Where(i => i >= 0).DefaultIfEmpty(-1).Min();
        s = cut >= 0 ? s[..(cut + 4)] : s;
        if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            s = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + s[11..];
        else if (s.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
            s = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), s);
        return s;
    }

    static string FormatDelta(TimeSpan d)
    {
        var a = d.Duration();
        string mag = a.TotalDays >= 1 ? $"{a.TotalDays:0.#} days" : a.TotalHours >= 1 ? $"{a.TotalHours:0.#} h" : $"{a.TotalMinutes:0.#} min";
        return d < TimeSpan.Zero ? $"moved back {mag}" : $"moved forward {mag}";
    }

    static void Run(List<string> errors, string what, Action action)
    {
        try { action(); }
        catch (EventLogNotFoundException) { }
        catch (UnauthorizedAccessException) { errors.Add($"{what}: access denied"); }
        catch (EventLogException e) { errors.Add($"{what}: {e.Message}"); }
    }

    static IEnumerable<EventRecord> Query(string log, string xpath)
    {
        using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath));
        for (EventRecord? r = reader.ReadEvent(); r != null; r = reader.ReadEvent())
        {
            using (r) yield return r;
        }
    }

    static Dictionary<string, string> Data(EventRecord r) => DataFrom(XDocument.Parse(r.ToXml()));

    static Dictionary<string, string> DataFrom(XDocument xml)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in xml.Descendants(Ns + "Data"))
        {
            var name = (string?)e.Attribute("Name");
            if (name != null) d[name] = e.Value;
        }
        return d;
    }

    /// <summary>SCM events carry the service key name as UTF-16 hex in the Binary field (locale independent).</summary>
    static string? BinaryServiceName(XDocument xml)
    {
        var hex = xml.Descendants(Ns + "Binary").FirstOrDefault()?.Value;
        if (string.IsNullOrEmpty(hex) || hex.Length % 4 != 0) return null;
        try { return Encoding.Unicode.GetString(Convert.FromHexString(hex)).TrimEnd('\0'); }
        catch (FormatException) { return null; }
    }

    internal static DateTime? ParseTime(string? s) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out var t) ? t : null;
}
