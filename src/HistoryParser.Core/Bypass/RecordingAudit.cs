using System.Diagnostics;
using Microsoft.Win32;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Is this PC still recording what runs, and is this program itself still its own?
/// <para>
/// Every execution record depends on something being switched on. A bypass that deletes nothing - it only stops the
/// recording, or makes the checking tool lie - leaves the records looking complete. These checks look at the switches
/// themselves, at whether the records keep up with what is running right now, and at what is loaded into this program.
/// </para>
/// </summary>
public static class RecordingAudit
{
    const string Area = "Recording";

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int Safe(string what, Func<int> check)
        {
            ct.ThrowIfCancellationRequested();
            try { return check(); }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException or InvalidOperationException
                                          or System.ComponentModel.Win32Exception)
            {
                ctx.Check(Area, what, CheckState.Unknown, "Could not be read - run as administrator to check this.");
                return 0;
            }
        }
        return Safe("FileInfo filter", () => HidingAudit.FileInfoFilter(ctx)) +
               Safe("Prefetch file attributes", () => BlockingAudit.PrefetchAttributes(ctx)) +
               Safe("Prefetch keeps up with running programs", () => PrefetchKeepsUp(ctx)) +
               Safe("Logging switches", () => BlockingAudit.LoggingSwitches(ctx)) +
               Safe("Event log sessions", () => EventLogSessions(ctx)) +
               Safe("Setup-environment switch", () => SetupEnvironmentSwitch(ctx)) +
               Safe("Recent-file lists", () => HidingAudit.RecentLists(ctx)) +
               Safe("Program launch tracking", () => LaunchTracking(ctx)) +
               Safe("This program", () => OwnProcess(ctx));
    }

    // ---- the setup-environment switch ----------------------------------------------------------------

    /// <summary>
    /// Control\MiniNT is how Windows knows it is running as its own setup and recovery environment (Windows PE), where
    /// event logs are not kept. An installed Windows never has the key. Creating it there is a published way to stop
    /// events being written without stopping the event log service or switching any log off, so nothing else here shows it.
    /// </summary>
    internal static int SetupEnvironmentSwitch(BypassContext ctx)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\MiniNT");
        var (state, detail, finding) = JudgeSetupSwitch(key != null, key != null ? WinApi.GetKeyLastWriteUtc(key) : null);
        ctx.Check(Area, "Setup-environment switch (MiniNT)", state, detail);
        if (finding is { } f) ctx.Flag(Severity.High, FindingCategory.LogTampering, f.Title, f.Detail, timeUtc: f.TimeUtc);
        return 1;
    }

    internal static (CheckState State, string Detail, (string Title, string Detail, DateTime? TimeUtc)? Finding) JudgeSetupSwitch(bool present, DateTime? writtenUtc) =>
        !present
            ? (CheckState.Ok, "Not set.", null)
            : (CheckState.Bad, $@"Control\MiniNT exists (written {Util.When.L(writtenUtc)}).",
                ("Windows is set to act as its setup environment (MiniNT)",
                 $@"The registry key Control\MiniNT exists, written {Util.When.L(writtenUtc)}. Windows has that key only in its setup and recovery " +
                 "environment, where no event logs are kept; an installed Windows never creates it. With it set, events stop being written " +
                 "while the event log service runs and every log reads as enabled.", writtenUtc));

    // ---- Prefetch against the process list -----------------------------------------------------------

    /// <summary>
    /// The same question asked two ways: which programs are running (the process list) and which programs Prefetch says
    /// ran. Windows writes a Prefetch file within seconds of every program start, so each program started a while ago must
    /// be in Prefetch with a run at least that recent. When hardly any is, Prefetch has stopped recording - whatever was
    /// done to stop it (a filter unloaded, a service frozen, the folder locked, something not known yet).
    /// </summary>
    static int PrefetchKeepsUp(BypassContext ctx)
    {
        var runs = ctx.History.Timeline.Where(e => e.Source == EvidenceSource.Prefetch && e.Kind == EvidenceKind.Execution && e.TimeUtc.HasValue && e.Origin != null)
            .GroupBy(e => PrefetchName(e.Origin!), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Max(e => e.TimeUtc!.Value), StringComparer.OrdinalIgnoreCase);
        if (runs.Count == 0)
        {
            // Nothing readable: without administrator rights that is the folder being closed to us, not Prefetch being empty.
            ctx.Check(Area, "Prefetch keeps up with running programs", CheckState.Unknown,
                WinApi.IsElevated() ? "Prefetch holds no runs to compare with." : "Prefetch cannot be read without administrator rights.");
            return 0;
        }

        var started = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id is 0 or 4 || process.Id == Environment.ProcessId) continue;
                if (WinApi.GetProcessStartUtc(process.Id) is not { } start) continue;
                // Programs started during startup are covered by boot prefetching, and one started moments ago is not written yet.
                if (start < ctx.BootUtc.AddMinutes(10) || start > ctx.NowUtc.AddMinutes(-3)) continue;
                string name;
                try { name = PrefetchName(process.ProcessName + ".exe"); }
                catch (InvalidOperationException) { continue; }
                // The newest start of each program is the one Prefetch must have caught up with.
                if (!started.TryGetValue(name, out var known) || start > known) started[name] = start;
            }
        }

        int recorded = started.Count(s => runs.TryGetValue(s.Key, out var last) && last >= s.Value.AddSeconds(-90));
        var missing = started.Where(s => !(runs.TryGetValue(s.Key, out var last) && last >= s.Value.AddSeconds(-90)))
            .OrderByDescending(s => s.Value).Select(s => $"{s.Key.ToLowerInvariant()} (started {Util.When.L(s.Value)})").ToList();
        if (started.Count < 6)
        {
            ctx.Check(Area, "Prefetch keeps up with running programs", CheckState.Ok,
                $"{recorded} of {started.Count} programs started since startup are in Prefetch (too few running to judge).");
            return started.Count;
        }

        bool stopped = recorded == 0, mostly = recorded * 5 < started.Count && started.Count >= 10;
        ctx.Check(Area, "Prefetch keeps up with running programs", stopped || mostly ? CheckState.Bad : CheckState.Ok,
            $"{recorded} of {started.Count} programs started since startup are in Prefetch with a run that recent." +
            (missing.Count > 0 ? $" Not recorded: {string.Join(", ", missing.Take(8))}{(missing.Count > 8 ? " …" : "")}." : ""));
        if (stopped || mostly)
            ctx.Flag(stopped ? Severity.High : Severity.Medium, FindingCategory.ServiceTampering, "Prefetch is not recording the programs that run",
                $"{started.Count} different programs were started after Windows finished starting and are running now, but Prefetch recorded " +
                $"{(stopped ? "none" : $"only {recorded}")} of those starts: {string.Join(", ", missing.Take(12))}{(missing.Count > 12 ? " …" : "")}. " +
                "Windows writes a Prefetch file within seconds of every start, so something is stopping it - whichever setting, service or filter that is. " +
                "Programs run in this state leave no Prefetch record at all.",
                timeUtc: started.Values.Min());
        return started.Count;
    }

    /// <summary>"NOTEPAD.EXE-D8414F97.pf" and "notepad.exe" both become NOTEPAD.EXE; Prefetch keeps at most 29 characters of a name.</summary>
    internal static string PrefetchName(string name)
    {
        if (name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) && name.LastIndexOf('-') is > 0 and var dash) name = name[..dash];
        name = name.ToUpperInvariant();
        return name.Length > 29 ? name[..29] : name;
    }

    // ---- switches ------------------------------------------------------------------------------------

    /// <summary>
    /// The System and Application logs are written through tracing sessions Windows starts at boot. Setting such a session not
    /// to start is a quiet way to stop a log: the service runs, the log is "enabled", and nothing arrives.
    /// </summary>
    static int EventLogSessions(BypassContext ctx)
    {
        int items = 0;
        foreach (var session in new[] { "EventLog-System", "EventLog-Application", "EventLog-Security" })
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Control\WMI\Autologger\{session}");
            if (key == null) continue;
            items++;
            bool off = key.GetValue("Start") is int start && start == 0;
            ctx.Check(Area, $"Log session {session}", off ? CheckState.Bad : CheckState.Ok, off ? "Set not to start (Start = 0)." : "Starts with Windows.");
            if (off)
                ctx.Flag(Severity.High, FindingCategory.LogTampering, $"Event log session switched off: {session}",
                    $@"Control\WMI\Autologger\{session}\Start is 0, so the tracing session that feeds this log is not started with Windows and nothing " +
                    "is written to it, although the event log service runs and the log reads as enabled. Windows sets this to 1.",
                    timeUtc: WinApi.GetKeyLastWriteUtc(key));
        }
        return items;
    }

    /// <summary>"Let Windows track app launches": with it off, UserAssist stops recording the programs started from Explorer.</summary>
    static int LaunchTracking(BypassContext ctx)
    {
        int items = 0;
        foreach (var sid in WinApi.LoadedUserSids())
        {
            using var advanced = Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced");
            if (advanced?.GetValue("Start_TrackProgs") is not int track || track != 0) continue;
            items++;
            string user = WinApi.SidToName(sid);
            ctx.Check(Area, $"Program launch tracking ({user})", CheckState.Warning, "Start_TrackProgs = 0: UserAssist is not recording program launches for this user.");
            ctx.Flag(Severity.Low, FindingCategory.LogTampering, $"Program launch tracking switched off ({user})",
                "Start_TrackProgs is 0, so Windows no longer records the programs this user starts from Explorer (UserAssist). It is a privacy " +
                "setting (Settings > Privacy > General) and \"debloat\" tools switch it off too; it also removes one of the records a check reads.");
        }
        return items;
    }

    // ---- this program ----------------------------------------------------------------------------------

    static readonly string[] SuiteNames =
        ["HistoryParser.exe", "ProgramChecker.exe", "ClientParser.exe", "MalwareChecker.exe", "CheatStringFinder.exe", "MinecraftScanner.exe", "historyparser-cli.exe"];

    /// <summary>
    /// What a result is worth depends on the program that produced it. Code loaded into this process can filter what it
    /// reads, so everything loaded here is checked: Microsoft's own libraries are expected, a known publisher's overlay or
    /// driver library is listed, and anything unsigned is reported. So are the ways Windows offers to put code into a
    /// program as it starts.
    /// </summary>
    static int OwnProcess(BypassContext ctx)
    {
        int items = 0;
        var problems = new List<string>();

        // .NET loads whatever these name into every .NET program before its own code runs.
        foreach (var (variable, what) in new[]
                 {
                     ("DOTNET_STARTUP_HOOKS", "a startup hook: code .NET runs inside the program before the program's own"),
                     ("CORECLR_PROFILER", "a profiler: a library .NET loads into the program that can rewrite its code"),
                     ("CORECLR_PROFILER_PATH", "a profiler library"), ("CORECLR_PROFILER_PATH_64", "a profiler library"),
                     ("DOTNET_BUNDLE_EXTRACT_BASE_DIR", "where this program unpacks the libraries it then loads"),
                 })
        {
            if (Environment.GetEnvironmentVariable(variable) is not { Length: > 0 } value) continue;
            items++;
            problems.Add($"{variable} is set");
            ctx.Flag(Severity.High, FindingCategory.AntiForensics, $"This program was started with {variable} set",
                $"The environment variable {variable} = \"{value}\" names {what}. Nothing sets it on a normal PC. With it set, what this " +
                "program reports can be filtered from inside; run the check again from a clean command prompt, or on a copy of the records.");
        }

        bool remote;
        using (var current = Process.GetCurrentProcess()) remote = CheckRemoteDebuggerPresent(current.Handle, out bool attached) && attached;
        if (Debugger.IsAttached || IsDebuggerPresent() || remote)
        {
            items++;
            problems.Add("a debugger is attached");
            ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, "A debugger is attached to this program",
                "Another program is debugging this one, which lets it pause it and change what it reads. Nothing does that on a normal PC.");
        }

        // Everything loaded into this process.
        string self = Environment.ProcessPath ?? "";
        var ownAssemblies = AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic).Select(a => a.Location).Where(l => l.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unsigned = new List<string>();
        var others = new List<string>();
        using (var me = Process.GetCurrentProcess())
        {
            foreach (ProcessModule module in me.Modules)
            {
                using (module)
                {
                    string path = module.FileName;
                    // This program's own file, and (in a developer build only) the assemblies .NET loaded for it by name.
                    if (path.Equals(self, StringComparison.OrdinalIgnoreCase) || ownAssemblies.Contains(path)) continue;
                    var facts = SignatureTrust.Of(path);
                    if (facts.IsMicrosoft) continue;
                    if (facts is { Status: SignatureStatus.Signed, Root: SignerRoot.Program }) others.Add($"{Path.GetFileName(path)} ({facts.Signer})");
                    else unsigned.Add($"{path} ({(facts.Status == SignatureStatus.Signed ? "signed through a certificate added to this PC" : Display.Signature(facts.Status).ToLowerInvariant())})");
                }
            }
        }
        items += unsigned.Count + others.Count;
        if (unsigned.Count > 0)
        {
            problems.Add($"{unsigned.Count} unsigned librar{(unsigned.Count == 1 ? "y" : "ies")} loaded");
            ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, unsigned.Count == 1 ? "Unsigned code is loaded into this program" : $"{unsigned.Count} unsigned libraries are loaded into this program",
                $"Loaded into this program, and not signed by a publisher Windows itself trusts: {string.Join("; ", unsigned.Take(8))}{(unsigned.Count > 8 ? " …" : "")}. " +
                "A library inside this process can change what it reads and reports. Some overlay and tuning tools inject an unsigned library into every " +
                "program; a library placed next to this program, or in the folder it unpacks to, gets loaded the same way.");
        }

        // Windows' own ways of putting code into a program as it starts.
        string exe = Path.GetFileName(self);
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var options = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            foreach (var name in SuiteNames.Append(exe).Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                using var entry = options?.OpenSubKey(name);
                if (entry == null) continue;
                var set = new[] { "Debugger", "VerifierDlls", "GlobalFlag", "MitigationOptions" }.Where(v => entry.GetValue(v) != null)
                    .Select(v => $"{v} = {entry.GetValue(v)}").ToList();
                if (set.Count == 0) continue;
                items++;
                problems.Add($"launch options set for {name}");
                ctx.Flag(Severity.High, FindingCategory.AntiForensics, $"{name} is hijacked at launch",
                    $@"Image File Execution Options\{name} sets {string.Join(", ", set)}. A ""Debugger"" there makes Windows start another program whenever " +
                    $"{name} is started; a verifier library is loaded into it before its own code. Nothing normal sets these for a screenshare tool.",
                    timeUtc: WinApi.GetKeyLastWriteUtc(entry));
            }
            using var windows = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
            if (windows?.GetValue("AppInit_DLLs") is string { Length: > 0 } appInit && windows.GetValue("LoadAppInit_DLLs") is int load && load != 0)
            {
                items++;
                problems.Add("AppInit_DLLs is set");
                ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, "A library is set to load into every program (AppInit_DLLs)",
                    $"AppInit_DLLs = \"{appInit}\" with LoadAppInit_DLLs on: Windows loads that library into every program with a window, this one included " +
                    "(unless Secure Boot is on, which disables it).", timeUtc: WinApi.GetKeyLastWriteUtc(windows));
            }
        }

        ctx.Check(Area, "This program is its own", problems.Count > 0 ? CheckState.Bad : CheckState.Ok,
            problems.Count > 0 ? $"{string.Join("; ", problems)}. See the findings."
                : "Nothing unsigned is loaded into it, no debugger, no startup hook, no launch hijack." +
                  (others.Count > 0 ? $" Loaded from other signed publishers: {string.Join(", ", others.Distinct().Take(10))}." : ""));
        return items;
    }
}
