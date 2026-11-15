using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// The antivirus as a record of the PC. Four questions, each answered from Windows' own records:
/// <list type="bullet">
/// <item>Is anything protecting the PC now (Defender's live state, another antivirus registered with Windows, policy switches)?</item>
/// <item>When was protection switched off, for how long, and what ran meanwhile (Defender's log: 5001 off, 5000 on)?</item>
/// <item>What is Defender told to ignore (the exclusion list, and when each entry was added: 5007)?</item>
/// <item>What did it detect, what touched the file, and what was done about it - removed, or kept (1116 … 1119, 1006 … 1009, 1015)?</item>
/// </list>
/// Judged by what was done, never by what a threat is called: Defender's verdict on a file is context, since its
/// machine-learning names hit harmless unsigned tools every day. Switching protection off, telling it to skip a folder,
/// and keeping a file it caught are actions, and those are what gets flagged.
/// Event ids and field names were read from this provider's own definitions and from real events (2026-11-14).
/// </summary>
public static class AntivirusAudit
{
    const string Log = "Microsoft-Windows-Windows Defender/Operational";

    /// <summary>
    /// Protection that comes back within this may be Defender restarting or updating itself. It is still listed and marked,
    /// as Low: two minutes is plenty to start something, so a gap this short becomes Medium when a program ran inside it.
    /// </summary>
    static readonly TimeSpan Blip = TimeSpan.FromMinutes(2);

    /// <summary>One event from Defender's log, reduced to what the checks read.</summary>
    internal sealed record Entry(int Id, DateTime? TimeUtc, IReadOnlyDictionary<string, string> Data)
    {
        public string this[string name] => Data.TryGetValue(name, out var v) ? v.Trim() : "";
    }

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        var live = LiveStatus.Read();
        var entries = ReadLog(ct);
        int items = Protection(ctx, live);

        var detections = DetectionsFrom(entries, LastRuns(ctx.History));
        var changes = Named(ChangesFrom(entries, ctx.NowUtc, live.RealTime), detections);
        foreach (var change in changes) ctx.Defender.Add(change.Row);
        foreach (var d in detections) ctx.Detections.Add(d);
        FlagChanges(ctx, changes, live, detections);
        FlagKept(ctx, detections);
        items += changes.Count + detections.Count;

        items += Exclusions(ctx, changes);
        if (entries.Count == 0)
            ctx.Antivirus.Enqueue(new IntegrityCheck("Records", "Defender's log", CheckState.Unknown,
                "No events could be read from Defender's log: it is empty, switched off, or was cleared. See Event logs."));
        return items;
    }

    // ---- what is protecting the PC now -------------------------------------------------------------------

    /// <summary>Defender's state as Windows reports it, and the other antivirus products registered with Windows.</summary>
    internal sealed record LiveStatus
    {
        public bool Readable { get; init; }
        public bool? RealTime { get; init; }
        public bool? Antivirus { get; init; }
        public bool? Tamper { get; init; }
        public bool? Behaviour { get; init; }
        public bool? Downloads { get; init; }
        public string Mode { get; init; } = "";
        public DateTime? DefinitionsUtc { get; init; }
        /// <summary>Other antivirus products registered with Windows.</summary>
        public IReadOnlyList<OtherProduct> Others { get; init; } = [];

        /// <summary>
        /// Another antivirus is protecting the PC: registered, says it is on, and installed like a product. Being registered is
        /// not enough. Windows switches Defender off for whatever registers as an antivirus, and tools that exist to switch
        /// Defender off do exactly that with a borrowed, validly signed vendor program run from wherever they were unpacked.
        /// </summary>
        public bool OtherIsOn => Others.Any(o => o.On && o.Installed);

        public static LiveStatus Read()
        {
            try
            {
                if (Type.GetTypeFromProgID("WbemScripting.SWbemLocator") is not { } locatorType) return new LiveStatus();
                dynamic locator = Activator.CreateInstance(locatorType)!;
                var status = new LiveStatus();
                try
                {
                    dynamic defender = locator.ConnectServer(".", @"root\Microsoft\Windows\Defender");
                    foreach (dynamic s in defender.ExecQuery("SELECT * FROM MSFT_MpComputerStatus"))
                    {
                        status = status with { Readable = true, RealTime = (bool?)s.RealTimeProtectionEnabled, Antivirus = (bool?)s.AntivirusEnabled };
                        // Each of the rest on its own: an older Defender lacks some of them, and that must not lose the others.
                        try { status = status with { Tamper = (bool?)s.IsTamperProtected }; } catch (Exception e) when (IsWmiFailure(e)) { }
                        try { status = status with { Behaviour = (bool?)s.BehaviorMonitorEnabled }; } catch (Exception e) when (IsWmiFailure(e)) { }
                        try { status = status with { Downloads = (bool?)s.IoavProtectionEnabled }; } catch (Exception e) when (IsWmiFailure(e)) { }
                        try { status = status with { Mode = (string?)s.AMRunningMode ?? "" }; } catch (Exception e) when (IsWmiFailure(e)) { }
                        try { status = status with { DefinitionsUtc = CimTime(Convert.ToString(s.AntivirusSignatureLastUpdated, CultureInfo.InvariantCulture)) }; }
                        catch (Exception e) when (IsWmiFailure(e)) { }
                    }
                }
                catch (Exception e) when (IsWmiFailure(e)) { }

                var others = new List<OtherProduct>();
                try
                {
                    dynamic center = locator.ConnectServer(".", @"root\SecurityCenter2");
                    foreach (dynamic av in center.ExecQuery("SELECT displayName, productState, pathToSignedProductExe FROM AntiVirusProduct"))
                    {
                        // Defender's own entry points at "windowsdefender://". Anything else calling itself Defender is judged like any other product.
                        string program = Environment.ExpandEnvironmentVariables(Convert.ToString(av.pathToSignedProductExe, CultureInfo.InvariantCulture) ?? "").Trim('"', ' ');
                        if ((string?)av.displayName is not { Length: > 0 } name || program.StartsWith("windowsdefender:", StringComparison.OrdinalIgnoreCase)) continue;
                        others.Add(new OtherProduct(name, ProductIsOn(Convert.ToInt32(av.productState)), program, LooksInstalled(program)));
                    }
                }
                catch (Exception e) when (IsWmiFailure(e)) { }
                return status with { Others = others };
            }
            catch (Exception e) when (IsWmiFailure(e)) { return new LiveStatus(); }
        }

        static bool IsWmiFailure(Exception e) => e is COMException or UnauthorizedAccessException or InvalidCastException or FormatException
            or OverflowException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or MissingMemberException;
    }

    /// <summary>An antivirus registered with Windows other than Defender: what it calls itself, whether it says it is on, the program it registered, and whether that program is installed like a product.</summary>
    internal sealed record OtherProduct(string Name, bool On, string Program, bool Installed);

    /// <summary>
    /// Whether the program an antivirus registered with is installed the way products are: a file that is there, validly
    /// signed with a chain that ends in a root Windows trusts by itself (not one added to this PC), inside a real Program
    /// Files folder. A real vendor program copied to Downloads or Temp and used to register is none of an installed product.
    /// </summary>
    internal static bool LooksInstalled(string program, Func<string, bool>? exists = null, Func<string, SignatureFacts>? signature = null)
    {
        if (program.Length < 4 || program[1] != ':' || !RoutineFiles.InProgramFiles(program) || !(exists ?? File.Exists)(program)) return false;
        var facts = (signature ?? SignatureTrust.Of)(program);
        return facts.Status == SignatureStatus.Signed && facts.Root is SignerRoot.Program or SignerRoot.Microsoft;
    }

    /// <summary>Security Center packs a product's state into one number; the second-lowest byte's high half is 1 when its protection is on.</summary>
    internal static bool ProductIsOn(int productState) => ((productState >> 12) & 0xF) == 1;

    /// <summary>WMI writes a time as "20261114050004.000000+000": local time, then minutes from UTC.</summary>
    internal static DateTime? CimTime(string? text)
    {
        if (text is not { Length: >= 25 }) return null;
        if (!DateTime.TryParseExact(text[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var local)) return null;
        return int.TryParse(text[21..25], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int minutes)
            ? DateTime.SpecifyKind(local.AddMinutes(-minutes), DateTimeKind.Utc) : null;
    }

    static int Protection(BypassContext ctx, LiveStatus live)
    {
        void Row(string name, CheckState state, string detail) => ctx.Antivirus.Enqueue(new IntegrityCheck("Protection", name, state, detail));
        string others = string.Join(", ", live.Others.Select(o => o.On ? o.Name : $"{o.Name} (off)"));

        // Registered as an antivirus and "on", but not installed like one. Windows has switched Defender off for it all the same.
        foreach (var fake in live.Others.Where(o => o.On && !o.Installed))
        {
            string where = fake.Program.Length > 0 ? fake.Program : "no program named";
            Row($"Registered as an antivirus: {fake.Name}", CheckState.Bad,
                $"Not installed like one ({where}). Windows switches Defender off for anything that registers as an antivirus.");
            ctx.Flag(Severity.Medium, FindingCategory.Defender, "Something registered as an antivirus is not installed like one",
                $"\"{fake.Name}\" is registered with Windows as an antivirus and says it is on, so Windows keeps Defender off. Its program is {where}: " +
                "not a validly signed file inside Program Files, which is where an installed antivirus lives. Tools made to switch Defender off " +
                "do it this way, with a borrowed vendor program run from the folder they were unpacked to. It is not counted as protection here.",
                fake.Program.Length > 3 && fake.Program[1] == ':' ? fake.Program : null);
        }

        if (!live.Readable)
        {
            Row("Microsoft Defender", live.OtherIsOn ? CheckState.Ok : CheckState.Unknown,
                live.Others.Count > 0 ? $"Its state could not be read. Registered with Windows: {others}."
                                      : "Its state could not be read, and no other antivirus is registered with Windows.");
            return 1;
        }

        bool defenderOn = live.RealTime == true && live.Antivirus != false;
        Row("Antivirus in use", defenderOn || live.OtherIsOn ? CheckState.Ok : CheckState.Bad,
            defenderOn ? "Microsoft Defender" + (live.Mode.Length > 0 && !live.Mode.Equals("Normal", StringComparison.OrdinalIgnoreCase) ? $" ({live.Mode})" : "") +
                         (live.Others.Count > 0 ? $"; also registered: {others}" : "")
            : live.OtherIsOn ? $"{others}. Defender steps aside when another antivirus is on."
            : live.Others.Count > 0 ? $"None is on. Defender is off, and so is: {others}."
            : "None. Defender is off and no other antivirus is registered with Windows.");

        if (!defenderOn && !live.OtherIsOn)
        {
            Row("Real-time protection", CheckState.Bad, "Off now. Nothing checks a file as it is opened or run.");
            ctx.Flag(Severity.Medium, FindingCategory.Defender, "No antivirus is watching this PC now",
                "Defender's real-time protection is off and no other antivirus that is switched on is registered with Windows. " +
                "The Antivirus page shows when it was switched off, if Defender's log still has it.");
        }
        else if (defenderOn) Row("Real-time protection", CheckState.Ok, "On");

        if (defenderOn || !live.OtherIsOn)
        {
            if (live.Tamper is { } tamper)
            {
                Row("Tamper protection", tamper ? CheckState.Ok : CheckState.Warning,
                    tamper ? "On: programs cannot switch Defender off or change its settings."
                           : "Off: any program running as administrator can switch Defender off.");
                if (!tamper)
                    ctx.Flag(Severity.Low, FindingCategory.Defender, "Defender's tamper protection is off",
                        "Tamper protection stops programs from switching Defender off. It is on by default; with it off, turning protection off takes one command.");
            }
            if (live.Behaviour == false) Row("Behaviour monitoring", CheckState.Warning, "Off: programs are not watched for what they do after they start.");
            if (live.Downloads == false) Row("Scanning of downloads", CheckState.Warning, "Off: downloaded files and attachments are not scanned as they arrive.");
            if (live.DefinitionsUtc is { } updated)
            {
                var age = ctx.NowUtc - updated;
                Row("Definitions", age > TimeSpan.FromDays(14) ? CheckState.Warning : CheckState.Ok,
                    $"Last updated {Util.When.L(updated)}" + (age > TimeSpan.FromDays(14) ? $", {(int)age.TotalDays} days ago: updates are not arriving." : "."));
            }
        }

        // A policy switch outranks the settings page: Defender stays off however the page reads.
        foreach (var (key, value, what) in new[]
                 {
                     (@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "Defender is switched off by policy"),
                     (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "Real-time protection is switched off by policy"),
                     (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "Behaviour monitoring is switched off by policy"),
                     (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", "Scanning of files as they are opened is switched off by policy"),
                     (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", "Scanning of downloads is switched off by policy"),
                 })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(key);
                if (k?.GetValue(value) is not int set || set != 1) continue;
                var when = WinApi.GetKeyLastWriteUtc(k);
                ctx.Antivirus.Enqueue(new IntegrityCheck("Policy", what, live.OtherIsOn ? CheckState.Warning : CheckState.Bad,
                    $@"HKLM\{key}\{value} = 1. That key was last changed {Util.When.L(when)}."));
                ctx.Flag(live.OtherIsOn ? Severity.Low : Severity.Medium, FindingCategory.Defender, what,
                    $@"HKLM\{key}\{value} = 1 (key last changed {Util.When.L(when)}). A policy value keeps this off whatever the settings page shows." +
                    (live.OtherIsOn ? " Another antivirus is on, which sets this itself." : " No other antivirus is on, so someone or something set it."), timeUtc: when);
            }
            catch (Exception e) when (e is SecurityException or UnauthorizedAccessException or IOException) { }
        }
        return ctx.Antivirus.Count;
    }

    // ---- Defender's log ---------------------------------------------------------------------------------

    static readonly int[] Wanted = [1006, 1007, 1008, 1009, 1011, 1013, 1015, 1116, 1117, 1118, 1119, 3002, 5000, 5001, 5007, 5008, 5010, 5012, 5013];

    static List<Entry> ReadLog(CancellationToken ct)
    {
        string xpath = "*[System[(" + string.Join(" or ", Wanted.Select(id => $"EventID={id}")) + ")]]";
        var entries = new List<Entry>();
        foreach (var r in Events.Read(Log, xpath, 12000))
        {
            ct.ThrowIfCancellationRequested();
            entries.Add(new Entry(r.Id, Events.Utc(r), Events.Data(r)));
        }
        return entries;
    }

    /// <summary>A change with the finding it deserves, if any. <paramref name="Until"/>: for a time protection was off, when that ended.</summary>
    internal sealed record Change(DefenderChange Row, Severity? Severity = null, string Title = "", string FindingDetail = "", DateTime? Until = null);

    /// <summary>
    /// What a "configuration changed" record (5007) means, or null for the hundreds Defender writes about itself (config
    /// hashes, diagnostics, service states). Old and new are "HKLM\…\value = 0x1"; an added value has no old, a removed one no new.
    /// </summary>
    internal static (string Setting, string Detail, bool Suspicious)? Classify(string oldValue, string newValue)
    {
        string value = newValue.Length > 0 ? newValue : oldValue;
        bool removed = newValue.Length == 0;
        if (value.Contains(@"\Exclusions\", StringComparison.OrdinalIgnoreCase))
        {
            string target = DefenderAudit.ExclusionTarget(value);
            return removed ? ("Exclusion removed", $"Defender scans this again: {target}.", false)
                           : ("Exclusion added", $"Defender was told not to scan: {target}.", true);
        }
        if (Tail(value, @"\Threats\ThreatIDDefaultAction\") is { } threat)
        {
            string id = threat.Split(' ')[0];
            if (removed) return ("Threat no longer allowed", $"The rule for threat {id} was removed: Defender acts on it again.", false);
            string action = ThreatAction(Number(value));
            bool kept = action is "Allow" or "No action";
            return ($"Threat set to: {action}", $"From now on Defender answers threat {id} with \"{action}\"" + (kept ? ": files it recognises as that threat are left alone." : "."), kept);
        }
        foreach (var (name, off, on, flagged) in Switches)
        {
            // The whole value name: "TamperProtectionSource" is not "TamperProtection".
            if (!value.Contains(name + " =", StringComparison.OrdinalIgnoreCase)) continue;
            long? n = Number(value);
            // "Disable…" values switch a protection off with 1; the others (TamperProtection, SpyNetReporting) are on when not 0.
            bool isOff = removed ? false : name.Contains("Disable", StringComparison.Ordinal) ? n == 1
                : name.EndsWith("TamperProtection", StringComparison.Ordinal) ? n is 0 or 4 : n == 0;
            return (isOff ? off : on, isOff ? "Changed in Defender's own settings." : "Back to normal.", isOff && flagged);
        }
        return null;
    }

    /// <summary>Registry values whose change is someone's decision about protection: (value name, text when off, text when on, flag when off).</summary>
    static readonly (string Name, string Off, string On, bool Flagged)[] Switches =
    [
        (@"\Real-Time Protection\DisableRealtimeMonitoring", "Real-time protection set to off", "Real-time protection set to on", true),
        (@"\Real-Time Protection\DisableBehaviorMonitoring", "Behaviour monitoring set to off", "Behaviour monitoring set to on", true),
        (@"\Real-Time Protection\DisableOnAccessProtection", "Scanning of files as they are opened set to off", "Scanning of files as they are opened set to on", true),
        (@"\Real-Time Protection\DisableIOAVProtection", "Scanning of downloads set to off", "Scanning of downloads set to on", true),
        (@"\Real-Time Protection\DisableScriptScanning", "Scanning of scripts set to off", "Scanning of scripts set to on", true),
        (@"\DisableAntiSpyware", "Defender switched off", "Defender switched on", true),
        (@"\DisableAntiVirus", "Defender switched off", "Defender switched on", true),
        (@"\Features\TamperProtection", "Tamper protection turned off", "Tamper protection turned on", true),
        (@"\SpyNet\SpyNetReporting", "Cloud protection turned off", "Cloud protection turned on", false),
        (@"\SpyNet\DisableBlockAtFirstSeen", "Blocking of never-seen files turned off", "Blocking of never-seen files turned on", false),
    ];

    /// <summary>"HKLM\SOFTWARE\Microsoft\Windows Defender\REAL-TIME PROTECTION\DisableRealtimeMonitoring = 1 -> 0" → "DisableRealtimeMonitoring = 1 -> 0".</summary>
    static string Short(string registryValue)
    {
        if (registryValue.Length == 0) return "";
        int eq = registryValue.LastIndexOf(" = ", StringComparison.Ordinal);
        int slash = registryValue.LastIndexOf('\\', eq > 0 ? eq : registryValue.Length - 1);
        return slash >= 0 ? registryValue[(slash + 1)..] : registryValue;
    }

    static string? Tail(string value, string marker)
    {
        int i = value.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        return i < 0 ? null : value[(i + marker.Length)..];
    }

    /// <summary>The number after " = " ("0x6" or "6"), or null.</summary>
    internal static long? Number(string value)
    {
        int eq = value.LastIndexOf(" = ", StringComparison.Ordinal);
        if (eq < 0) return null;
        string n = value[(eq + 3)..].Trim();
        return n.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? long.TryParse(n[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long hex) ? hex : null
            : long.TryParse(n, NumberStyles.Integer, CultureInfo.InvariantCulture, out long dec) ? dec : null;
    }

    /// <summary>Defender's numbers for what to do with a threat.</summary>
    internal static string ThreatAction(long? code) => code switch
    {
        1 => "Clean", 2 => "Quarantine", 3 => "Remove", 6 => "Allow", 8 => "Ask the user", 9 => "No action", 10 => "Block",
        null => "unknown", _ => $"action {code}",
    };

    /// <summary>Each time real-time protection went off, and when it came back (null: it has not, by the log).</summary>
    internal static List<(DateTime Off, DateTime? On)> OffPeriods(IEnumerable<Entry> entries)
    {
        var switches = entries.Where(e => e.Id is 5000 or 5001 && e.TimeUtc != null).OrderBy(e => e.TimeUtc).ToList();
        var periods = new List<(DateTime, DateTime?)>();
        for (int i = 0; i < switches.Count; i++)
        {
            if (switches[i].Id != 5001) continue;
            if (i > 0 && switches[i - 1].Id == 5001) continue; // already off: the same period
            var on = switches.Skip(i + 1).FirstOrDefault(s => s.Id == 5000);
            periods.Add((switches[i].TimeUtc!.Value, on?.TimeUtc));
        }
        return periods;
    }

    internal static List<Change> ChangesFrom(IReadOnlyList<Entry> entries, DateTime nowUtc, bool? realTimeNow)
    {
        var changes = new List<Change>();
        foreach (var (off, on) in OffPeriods(entries))
        {
            // The log says it never came back. Believe that only when Windows also says it is off now.
            bool stillOff = on == null && realTimeNow == false;
            var length = (on ?? (stillOff ? nowUtc : off)) - off;
            // Short enough to be Defender restarting or updating itself - and long enough to start something. So a short gap is
            // still listed and marked; what decides how seriously it is taken is whether anything ran inside it (FlagChanges).
            bool brief = on != null && length < Blip;
            string span = on != null ? $"Off for {Correlator.FormatGap(length)}: from {Util.When.L(off)} until {Util.When.L(on)}."
                : stillOff ? $"Off since {Util.When.L(off)} and still off ({Correlator.FormatGap(length)})."
                : $"Switched off at {Util.When.L(off)}. The log does not say when it came back; it is on now.";
            changes.Add(new Change(
                new DefenderChange
                {
                    TimeUtc = off, Setting = "Real-time protection turned off", Suspicious = true,
                    Detail = brief ? span + " As short as Defender restarting itself; see whether anything ran meanwhile." : span,
                    NewValue = on != null ? $"on again {Util.When.L(on)}" : "",
                },
                brief ? Severity.Low : Severity.Medium,
                stillOff ? "Real-time protection has been off" : brief ? "Real-time protection was off briefly" : "Real-time protection was switched off", span,
                on ?? (stillOff ? nowUtc : off)));
        }

        foreach (var e in entries)
        {
            switch (e.Id)
            {
                case 5007 when Classify(e["Old Value"], e["New Value"]) is { } c:
                    bool exclusion = c.Setting == "Exclusion added";
                    // Real-time protection going off already has its own row and finding, with how long it lasted (5001 / 5000).
                    bool realTime = c.Setting.StartsWith("Real-time protection set", StringComparison.Ordinal);
                    changes.Add(new Change(
                        new DefenderChange { TimeUtc = e.TimeUtc, Setting = c.Setting, Detail = c.Detail, OldValue = e["Old Value"], NewValue = e["New Value"], Suspicious = c.Suspicious },
                        !c.Suspicious || realTime ? null : exclusion || c.Setting.StartsWith("Threat set to", StringComparison.Ordinal) ? Severity.Medium : Severity.Low,
                        exclusion ? "Defender exclusion added" : c.Setting, $"At {Util.When.L(e.TimeUtc)}: {c.Detail}"));
                    break;
                case 5010 or 5012:
                    string what = e.Id == 5010 ? "Scanning for spyware turned off" : "Scanning for viruses turned off";
                    changes.Add(new Change(new DefenderChange { TimeUtc = e.TimeUtc, Setting = what, Suspicious = true, Detail = "Recorded by Defender when the scanning itself is switched off." },
                        Severity.Low, what, $"{what} at {Util.When.L(e.TimeUtc)}."));
                    break;
                case 5013:
                    // "…\DisableRealtimeMonitoring = 1 -> 0": tamper protection undid a change. "0 -> 0" changed nothing.
                    string change = e["Value"];
                    var sides = change.Split(" = ").LastOrDefault()?.Split("->").Select(s => s.Trim()).ToArray() ?? [];
                    bool real = sides.Length != 2 || sides[0] != sides[1];
                    bool aboutRealTime = change.Contains("DisableRealtimeMonitoring", StringComparison.OrdinalIgnoreCase);
                    changes.Add(new Change(
                        new DefenderChange
                        {
                            TimeUtc = e.TimeUtc, Setting = $"Tamper protection {e["Changed Type"].ToLowerInvariant()} a change", NewValue = change, Suspicious = real,
                            Detail = real ? $"Something changed a protected Defender setting, and tamper protection put it back: {Short(change)}." : $"No value changed: {Short(change)}.",
                        },
                        real && !aboutRealTime ? Severity.Low : null, "A protected Defender setting was changed and put back",
                        $"At {Util.When.L(e.TimeUtc)} tamper protection undid this change: {change}. Something tried to alter how Defender protects the PC."));
                    break;
                case 1009:
                    changes.Add(new Change(
                        new DefenderChange
                        {
                            TimeUtc = e.TimeUtc, Setting = "Restored from quarantine", NewValue = string.Join("; ", DefenderDetectionCollector.DetectionPaths(e["Path"])), Suspicious = true,
                            Detail = $"{e["Threat Name"]}: a file Defender had locked away was put back by {Who(e)}.",
                        },
                        Severity.Medium, "A file Defender caught was restored",
                        $"At {Util.When.L(e.TimeUtc)} {Who(e)} took {string.Join("; ", DefenderDetectionCollector.DetectionPaths(e["Path"]))} back out of quarantine " +
                        $"(Defender calls it {e["Threat Name"]}). Whoever did that decided to keep a file the antivirus had removed."));
                    break;
                case 1011:
                    changes.Add(new Change(new DefenderChange
                    {
                        TimeUtc = e.TimeUtc, Setting = "Quarantined item deleted", NewValue = string.Join("; ", DefenderDetectionCollector.DetectionPaths(e["Path"])),
                        Detail = $"{e["Threat Name"]}: removed from quarantine for good, by {Who(e)}. Defender does this itself after a while.",
                    }));
                    break;
                case 1013:
                    // Defender trims its own history: everything older than about two weeks, as SYSTEM. A person clearing it
                    // removes recent items, or does it under their own account.
                    DateTime? upTo = DateTime.TryParse(e["Timestamp"], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;
                    bool bySystem = e["User"].Equals("SYSTEM", StringComparison.OrdinalIgnoreCase);
                    bool recent = upTo is { } cut && e.TimeUtc is { } at && at - cut < TimeSpan.FromDays(2);
                    bool cleared = recent || !bySystem;
                    changes.Add(new Change(
                        new DefenderChange
                        {
                            TimeUtc = e.TimeUtc, Setting = "Detection history removed", Suspicious = cleared,
                            Detail = $"Detections from before {Util.When.L(upTo)} were removed by {Who(e)}." +
                                     (cleared ? " That is not Defender's own clean-up, which runs as SYSTEM and keeps the last two weeks." : " Defender's own clean-up."),
                        },
                        cleared ? Severity.Low : null, "Defender's detection history was cleared",
                        $"At {Util.When.L(e.TimeUtc)} {Who(e)} removed Defender's detections from before {Util.When.L(upTo)}. " +
                        "Defender's own clean-up runs as SYSTEM and only removes items older than about two weeks."));
                    break;
                case 5008:
                    changes.Add(new Change(new DefenderChange { TimeUtc = e.TimeUtc, Setting = "Defender's engine stopped unexpectedly", Detail = $"{e["Failure Type"]} {e["Exception Code"]}".Trim() }));
                    break;
                case 3002:
                    changes.Add(new Change(new DefenderChange { TimeUtc = e.TimeUtc, Setting = "Real-time protection failed", Detail = $"{e["Feature Name"]}: {e["Error Description"]}".Trim(' ', ':') }));
                    break;
            }
        }
        return changes.OrderByDescending(c => c.Row.TimeUtc ?? DateTime.MinValue).ToList();
    }

    /// <summary>A rule about a threat names it by number. The detections know what that number is called, so the row says both.</summary>
    internal static List<Change> Named(List<Change> changes, IReadOnlyList<DefenderDetection> detections)
    {
        var names = detections.Where(d => d.ThreatId.Length > 0).GroupBy(d => d.ThreatId).ToDictionary(g => g.Key, g => g.First().Threat);
        return changes.Select(c =>
        {
            string value = c.Row.NewValue.Length > 0 ? c.Row.NewValue : c.Row.OldValue;
            if (Tail(value, @"\Threats\ThreatIDDefaultAction\")?.Split(' ')[0] is not { } id || !names.TryGetValue(id, out var name)) return c;
            return c with { Row = c.Row with { Detail = c.Row.Detail.Replace($"threat {id}", $"{name} (threat {id})") } };
        }).ToList();
    }

    static string Who(Entry e)
    {
        string user = e["User"], domain = e["Domain"];
        return user.Length == 0 ? "an unknown account" : domain.Length > 0 && !domain.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ? $@"{domain}\{user}" : user;
    }

    static void FlagChanges(BypassContext ctx, List<Change> changes, LiveStatus live, List<DefenderDetection> detections)
    {
        foreach (var c in changes.Where(c => c.Severity != null))
        {
            string detail = c.FindingDetail;
            var severity = c.Severity!.Value;
            if (c.Row.Setting == "Real-time protection turned off")
            {
                // What ran while nothing was checking is the reason anyone switches it off.
                var ran = RanBetween(ctx.History, c.Row.TimeUtc!.Value, c.Until ?? c.Row.TimeUtc.Value);
                detail += ran.Count > 0
                    ? $" Programs that ran while it was off: {string.Join(", ", ran.Take(8))}{(ran.Count > 8 ? $" and {ran.Count - 8} more" : "")}."
                    : " No program run is recorded inside that time.";
                // A gap of seconds with a program started inside it is the short way to get something past Defender.
                if (ran.Count > 0) severity = Severity.Medium;
                // Said, not excused: Windows switches Defender off for a real antivirus being installed and for a tool posing
                // as one alike, so another product being registered does not make the gap any less of a gap.
                if (live.Others.Any(o => o.On))
                    detail += $" Registered with Windows as an antivirus now: {string.Join(", ", live.Others.Where(o => o.On).Select(o => o.Name))}. " +
                              "Windows switches Defender off when one registers.";
            }
            else if (c.Row.Setting == "Exclusion added")
            {
                string target = DefenderAudit.ExclusionTarget(c.Row.NewValue);
                detail = $"At {Util.When.L(c.Row.TimeUtc)} Microsoft Defender was told to stop scanning: {target}. " +
                         (ExclusionRisk(target) is { } risk ? risk + " " : "") + "Anything kept or run there is never checked, which is why cheats and loaders are put in excluded folders.";
            }
            else if (c.Row.Setting.StartsWith("Threat set to", StringComparison.Ordinal))
            {
                string id = Tail(c.Row.NewValue, @"\Threats\ThreatIDDefaultAction\")?.Split(' ')[0] ?? "";
                var caught = detections.Where(d => d.ThreatId == id).ToList();
                // A file or command kept this way has its own finding, which says when the threat was allowed.
                if (caught.Any(d => d.Kept && (d.Path.Length > 0 || d.Command.Length > 0))) continue;
                detail = caught.Count == 0
                    ? $"At {Util.When.L(c.Row.TimeUtc)} Defender was told to leave threat {id} alone from then on. No detection of it is left in the log."
                    : $"At {Util.When.L(c.Row.TimeUtc)} Defender was told to leave {caught[0].Threat} alone from then on. It had caught it in: {Where(caught[0])}.";
            }
            ctx.Flag(severity, FindingCategory.Defender, c.Title, detail, timeUtc: c.Row.TimeUtc);
        }
    }

    /// <summary>Names of programs, jars and scripts with a run recorded between the two times, leaving out routine files and this suite.</summary>
    static List<string> RanBetween(ScanResult history, DateTime fromUtc, DateTime toUtc)
    {
        var skip = history.Files.Where(f => f.Routine != null || f.IsWindowsFile || f.IsThisTool).Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return history.Timeline
            .Where(e => e.Kind == EvidenceKind.Execution && e.TimeUtc >= fromUtc && e.TimeUtc <= toUtc && !skip.Contains(e.Path) && e.Path.Length > 3 && e.Path[1] == ':')
            .Select(e => Path.GetFileName(e.Path)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ---- detections -------------------------------------------------------------------------------------

    static Dictionary<string, DateTime> LastRuns(ScanResult history) => history.Files
        .Where(f => f.LastExecutionUtc != null).GroupBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.Max(f => f.LastExecutionUtc!.Value), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// One row per detection. 1116 says what was found and 1117 what was done, joined by the detection's id; 1118 and 1119 say
    /// the action failed. The older 1006 / 1007 / 1008 (found by a scan) and 1015 (found by behaviour) carry the same facts
    /// under other field names.
    /// </summary>
    internal static List<DefenderDetection> DetectionsFrom(IReadOnlyList<Entry> entries, IReadOnlyDictionary<string, DateTime>? lastRuns,
        Func<string, bool>? exists = null)
    {
        exists ??= File.Exists;
        // "Allow on device" is one click on a detection: the rule appears seconds after the detection it answers. A rule from
        // another time is about another detection (rules are added and removed), so only one set soon after counts.
        var allowRules = entries.Where(e => e.Id == 5007 && e.TimeUtc != null && e["New Value"].Contains(@"\Threats\ThreatIDDefaultAction\", StringComparison.OrdinalIgnoreCase) &&
                                            ThreatAction(Number(e["New Value"])) is "Allow" or "No action")
            .Select(e => (Id: Tail(e["New Value"], @"\Threats\ThreatIDDefaultAction\")!.Split(' ')[0], Time: e.TimeUtc!.Value)).ToList();
        DateTime? AllowedAfter(string threatId, DateTime? caught) => caught is not { } at ? null
            : allowRules.Where(r => r.Id == threatId && r.Time >= at && r.Time - at < TimeSpan.FromDays(1)).Select(r => (DateTime?)r.Time).Min();
        var restored = entries.Where(e => e.Id == 1009).SelectMany(e => DefenderDetectionCollector.DetectionPaths(e["Path"])).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var rows = new List<DefenderDetection>();
        int n = 0;
        foreach (var group in entries.Where(e => e.Id is 1006 or 1007 or 1008 or 1015 or >= 1116 and <= 1119)
                     .GroupBy(e => e["Detection ID"] is { Length: > 0 } id ? id : $"none-{n++}"))
        {
            var found = group.Where(e => e.Id is 1116 or 1006 or 1015).OrderBy(e => e.TimeUtc).FirstOrDefault();
            var acted = group.Where(e => e.Id is 1117 or 1007).OrderByDescending(e => e.TimeUtc).FirstOrDefault();
            var failed = group.Where(e => e.Id is 1118 or 1119 or 1008).OrderByDescending(e => e.TimeUtc).FirstOrDefault();
            var any = found ?? acted ?? failed!;
            string First(params string[] names) => names.Select(name => any[name]).FirstOrDefault(v => v.Length > 0) ?? "";

            var paths = group.SelectMany(e => DefenderDetectionCollector.DetectionPaths(e["Path"]).Concat(DefenderDetectionCollector.DetectionPaths(e["Path Found"])))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            string raw = group.Select(e => e["Path"].Length > 0 ? e["Path"] : e["Path Found"]).FirstOrDefault(v => v.Length > 0) ?? "";
            string action = acted is null ? "" : acted["Action Name"] is { Length: > 0 } a ? a : acted["Cleaning Action"];
            string threatId = First("Threat ID");
            var allowedAt = AllowedAfter(threatId, (found ?? any).TimeUtc);
            bool wasRestored = paths.Any(restored.Contains), wasAllowed = allowedAt != null || action.Equals("Allow", StringComparison.OrdinalIgnoreCase);
            bool removed = action is "Quarantine" or "Remove" or "Clean" or "Block";
            bool stillThere = paths.Any(exists);

            var notes = new List<string>();
            if (failed != null) notes.Add($"The action failed: {failed["Error Description"]}".TrimEnd(' ', ':'));
            if (Downloaded(raw) is { } url) notes.Add($"Downloaded from {url}.");
            if (wasAllowed) notes.Add(allowedAt != null ? $"Set to Allow at {Util.When.L(allowedAt)}, right after it was caught: Defender was told to leave it alone."
                                                        : "Allowed: Defender was told to leave it alone.");
            if (wasRestored) notes.Add("Put back out of quarantine afterwards.");
            if (stillThere) notes.Add(removed && !wasRestored ? "A file is at that path now: it came back after Defender removed it." : "Still on disk.");
            if (lastRuns != null && paths.Select(p => lastRuns.TryGetValue(p, out var run) ? run : (DateTime?)null).Max() is { } lastRun)
                notes.Add($"It ran: last recorded run {Util.When.L(lastRun)}.");

            rows.Add(new DefenderDetection
            {
                TimeUtc = (found ?? any).TimeUtc, Threat = First("Threat Name") is { Length: > 0 } t ? t : "Unnamed threat",
                Level = First("Severity Name"), Category = First("Category Name"),
                Path = paths.FirstOrDefault() ?? "", Paths = paths, Command = CaughtCommand(raw),
                Process = First("Process Name") is var process && process.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ? "" : process, User = First("Detection User", "User"), FoundBy = First("Source Name", "Detection Source"),
                Action = wasRestored ? "Restored from quarantine" : wasAllowed ? "Allowed" : action.Length > 0 ? action : "No action recorded",
                Note = string.Join(" ", notes),
                // Kept on purpose: allowed, restored, or back on disk after being removed. A failed action alone is Defender's problem.
                Kept = wasAllowed || wasRestored || (removed && stillThere),
                DetectionId = First("Detection ID"), ThreatId = threatId,
            });
        }
        return rows.OrderByDescending(r => r.TimeUtc ?? DateTime.MinValue).ToList();
    }

    /// <summary>What a detection was found in, for a sentence: the file, or the command line that was caught.</summary>
    static string Where(DefenderDetection d) => d.Path.Length > 0 ? d.Path : d.Command.Length > 0 ? $"the command \"{d.Command}\"" : "something the log does not name";

    /// <summary>"CmdLine:_powershell -w hidden …" is a command that was caught as it was run, not a file. The whole text is the command: it may hold semicolons.</summary>
    internal static string CaughtCommand(string raw) =>
        raw.StartsWith("CmdLine:_", StringComparison.OrdinalIgnoreCase) ? raw["CmdLine:_".Length..].Trim() : "";

    /// <summary>"webfile:_C:\Users\x\Downloads\a.exe|https://site/a.exe|pid:12,…" names where the file was being downloaded from.</summary>
    internal static string? Downloaded(string raw)
    {
        foreach (var part in raw.Split(';').Select(p => p.Trim()))
            if (part.StartsWith("webfile:_", StringComparison.OrdinalIgnoreCase) && part.Split('|') is { Length: >= 2 } pieces &&
                pieces[1].StartsWith("http", StringComparison.OrdinalIgnoreCase))
                return pieces[1];
        return null;
    }

    static void FlagKept(BypassContext ctx, List<DefenderDetection> detections)
    {
        // A command Defender caught and was then told to allow has no file to hang a finding on.
        foreach (var d in detections.Where(d => d.Kept && d.Path.Length == 0 && d.Command.Length > 0).GroupBy(d => d.Command).Select(g => g.First()))
            ctx.Flag(Severity.Medium, FindingCategory.Defender, "A command Defender caught was allowed",
                $"At {Util.When.L(d.TimeUtc)} Defender caught this command as {d.Threat}: {d.Command} {d.Note}", timeUtc: d.TimeUtc);
        foreach (var group in detections.Where(d => d.Kept && d.Path.Length > 0).GroupBy(d => d.Path, StringComparer.OrdinalIgnoreCase))
        {
            var d = group.First();
            ctx.Flag(Severity.Medium, FindingCategory.Defender, "A file Defender caught was kept",
                $"Defender detected {d.Path} as {d.Threat} at {Util.When.L(d.TimeUtc)}" + (group.Count() > 1 ? $" ({group.Count()} times)" : "") +
                $". {d.Note} Defender's names for threats are often wrong about small unsigned tools, so what the file is still has to be checked; " +
                "what is certain is that someone chose to keep a file the antivirus removed.", d.Path, d.TimeUtc);
        }
    }

    // ---- exclusions ------------------------------------------------------------------------------------

    /// <summary>
    /// Why an exclusion gives cover, or null. An exclusion on a place the user can write to, on a kind of file that carries code,
    /// or on a program, is a place to keep or run something unseen; one on a program's own folder under Program Files is what
    /// installers add. The target is the text <see cref="DefenderAudit.ExclusionTarget"/> gives: "C:\x (folder or file)".
    /// </summary>
    internal static string? ExclusionRisk(string target)
    {
        int open = target.LastIndexOf(" (", StringComparison.Ordinal);
        string what = open > 0 ? target[..open].Trim() : target, kind = open > 0 ? target[(open + 2)..].TrimEnd(')') : "";
        if (kind == "process") return "Everything that program opens or writes goes unscanned.";
        if (kind == "file type")
            return what.TrimStart('.', '*').ToLowerInvariant() is "exe" or "dll" or "jar" or "sys" or "bat" or "cmd" or "ps1" or "vbs" or "js" or "py" or "zip" or "tmp" or ""
                ? "That is a kind of file that carries code." : null;
        if (kind is not ("folder or file" or "temporarypaths")) return null;
        string path = what.TrimEnd('\\');
        if (path.Length <= 2 || path.Contains('*')) return "That covers a whole drive or a wildcard.";
        // Only a program's own folder under Program Files or Windows needs administrator rights to write to. Temp is the exception inside Windows.
        bool guarded = (RoutineFiles.InProgramFiles(path + "\\") || RoutineFiles.InWindowsFolder(path + "\\")) && !path.Contains(@"\Temp", StringComparison.OrdinalIgnoreCase);
        return guarded ? null : "That is a place any program the user runs can write to.";
    }

    static int Exclusions(BypassContext ctx, List<Change> changes)
    {
        // When each entry was added, by the log, to show beside the entry as it is now.
        var added = changes.Where(c => c.Row.Setting == "Exclusion added")
            .GroupBy(c => DefenderAudit.ExclusionTarget(c.Row.NewValue), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Max(c => c.Row.TimeUtc), StringComparer.OrdinalIgnoreCase);
        int items = 0;
        bool denied = false;
        foreach (string root in new[] { @"SOFTWARE\Microsoft\Windows Defender\Exclusions", @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" })
            foreach (string kind in new[] { "Paths", "Processes", "Extensions", "TemporaryPaths", "IpAddresses" })
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey($@"{root}\{kind}");
                    if (k == null) continue;
                    foreach (string name in k.GetValueNames())
                    {
                        string target = DefenderAudit.ExclusionTarget($@"\Exclusions\{kind}\{name}");
                        string? risk = ExclusionRisk(target);
                        bool logged = added.TryGetValue(target, out var when);
                        ctx.Antivirus.Enqueue(new IntegrityCheck("Exclusion", target, risk != null ? CheckState.Bad : CheckState.Warning,
                            (logged ? $"Added {Util.When.L(when)}. " : $"In the list now; the log no longer has when it was added (the list last changed {Util.When.L(WinApi.GetKeyLastWriteUtc(k))}). ") +
                            (risk ?? "Not scanned by Defender.") + (root.Contains("Policies", StringComparison.Ordinal) ? " Set by policy." : "")));
                        items++;
                        // An entry whose adding is still in the log already has its finding there.
                        if (!logged)
                            ctx.Flag(risk != null ? Severity.Medium : Severity.Low, FindingCategory.Defender, "Defender exclusion in place",
                                $"Microsoft Defender does not scan: {target}. {risk ?? ""} The log no longer shows when it was added; the list last changed {Util.When.L(WinApi.GetKeyLastWriteUtc(k))}.".Replace("  ", " "));
                    }
                }
                catch (Exception e) when (e is SecurityException or UnauthorizedAccessException) { denied = true; }
                catch (IOException) { }
            }
        if (denied)
            ctx.Antivirus.Enqueue(new IntegrityCheck("Exclusion", "Exclusion list", CheckState.Unknown,
                "Windows only shows the list to an administrator. Exclusions added while Defender's log was kept are in the changes below either way."));
        else if (items == 0)
            ctx.Antivirus.Enqueue(new IntegrityCheck("Exclusion", "Exclusion list", CheckState.Ok, "Empty: Defender is not told to skip anything."));
        return items;
    }
}
