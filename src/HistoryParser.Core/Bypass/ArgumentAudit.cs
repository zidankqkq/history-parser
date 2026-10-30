using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using HistoryParser.Core.Collectors;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using static HistoryParser.Core.Native.NativeMethods;

namespace HistoryParser.Core.Bypass;

/// <summary>
/// Program arguments, live and historical, checked against the editable argument rules:
/// running processes, process-creation events (Security 4688 / Sysmon 1, when enabled), PowerShell
/// launches, and Minecraft / launcher log files (which often print the full JVM command line).
/// Also inspects running Java processes for an active Java agent and for code loaded from files
/// that were deleted afterwards.
/// </summary>
public static class ArgumentAudit
{
    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        items += Running(ctx, ct);
        items += ProcessEvents(ctx);
        if (ctx.ReadGameLogs) items += LauncherLogs(ctx, ct);
        return items;
    }

    /// <summary>
    /// Java agents shipped by legitimate launchers. A command line whose only agents are these is
    /// reported as Low instead of Medium (they still show on the Arguments page).
    /// </summary>
    internal static readonly Dictionary<string, string> KnownLauncherAgents = new(StringComparer.OrdinalIgnoreCase)
    {
        ["theseus.jar"] = "Modrinth App",
    };

    static readonly System.Text.RegularExpressions.Regex AgentArg = new(@"-javaagent:(""[^""]+""|[^\s,]+)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    public static List<string> AgentsIn(string commandLine) =>
        AgentArg.Matches(commandLine).Select(m => m.Groups[1].Value.Trim('"')).ToList();

    /// <summary>Names the launcher an agent list belongs to, when every agent is a known launcher agent.</summary>
    public static string? KnownLauncher(IReadOnlyList<string> agents) =>
        agents.Count > 0 && agents.All(a => KnownLauncherAgents.ContainsKey(Path.GetFileName(a)))
            ? string.Join(", ", agents.Select(a => KnownLauncherAgents[Path.GetFileName(a)]).Distinct())
            : null;

    // Same arguments seen in many places (old logs repeat the same JVM line) are reported once.
    static readonly System.Text.RegularExpressions.Regex LogPrefix = new(@"^\s*\[[^\]]*\]\s*(\[[^\]]*\]\s*)*");

    static readonly System.Text.RegularExpressions.Regex EncodedArg = new(@"\s-e(nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>Text hidden in a PowerShell <c>-EncodedCommand</c> (Base64 of UTF-16), or null.</summary>
    public static string? DecodePowerShell(string commandLine)
    {
        var m = EncodedArg.Match(commandLine);
        if (!m.Success) return null;
        // Long commands may have been cut when they were logged; decode the complete part.
        var b64 = m.Groups[2].Value;
        bool partial = b64.Length % 4 != 0;
        if (partial) b64 = b64[..(b64.Length / 4 * 4)];
        try
        {
            var bytes = Convert.FromBase64String(b64);
            if (bytes.Length % 2 != 0) bytes = bytes[..^1];
            var text = System.Text.Encoding.Unicode.GetString(bytes);
            return partial ? text + " …(cut off)" : text;
        }
        catch (FormatException) { return null; }
    }

    static readonly System.Text.RegularExpressions.Regex JarArgument = new(@"(?:^|\s)-jar\s+(?:""([^""]+)""|(\S+))",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>The file a java / javaw command starts with -jar when it is not named like Java code; otherwise null.</summary>
    internal static string? DisguisedJarArgument(string program, string commandLine)
    {
        if (!Path.GetFileNameWithoutExtension(program).Equals("javaw", StringComparison.OrdinalIgnoreCase) &&
            !Path.GetFileNameWithoutExtension(program).Equals("java", StringComparison.OrdinalIgnoreCase)) return null;
        var m = JarArgument.Match(commandLine);
        if (!m.Success) return null;
        string target = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
        return Util.FileTypes.IsJavaContainerName(target) ? null : target;
    }

    static void Record(BypassContext ctx, string program, int? pid, string commandLine, string source, DateTime? time,
        bool includeWildcardRules = true, HashSet<string>? reported = null)
    {
        var reasons = ctx.ArgumentRules.Match(program, commandLine, includeWildcardRules);
        var severity = Severity.Medium;
        if (reasons.Count > 0 && KnownLauncher(AgentsIn(commandLine)) is { } launcher)
        {
            // The only agent is the launcher's own: say so instead of "loads a Java agent".
            reasons = reasons.Select(r => r.Contains("Java agent", StringComparison.Ordinal) ? $"uses {launcher}'s own Java agent" : r).ToList();
            if (reasons.All(r => r.StartsWith("uses ", StringComparison.Ordinal))) severity = Severity.Low;
        }

        // Java runs "-jar cape.png" as happily as "-jar client.jar": a jar under another name is hiding.
        if (DisguisedJarArgument(program, commandLine) is { } disguised)
        {
            bool provenCode = File.Exists(disguised) && Util.FileTypes.IsJavaArchive(disguised);
            reasons.Add(provenCode ? $"runs a jar renamed to \"{Path.GetFileName(disguised)}\" (its content is Java code)"
                                   : $"runs \"{Path.GetFileName(disguised)}\" as a jar although it is not named .jar");
            if (provenCode && Util.FileTypes.LooksHarmless(disguised)) severity = Severity.High;
        }

        // Show what an encoded PowerShell command really runs, and judge it by that.
        var decoded = DecodePowerShell(commandLine)?.Trim();
        string? shownDecoded = decoded == null ? null : Clip(decoded, 400);
        if (decoded != null)
        {
            // Decoded text first, so it survives the length cap on very long command lines.
            commandLine = $"[decoded] {decoded}{Environment.NewLine}{commandLine}";
            if (ctx.Keywords.ClassifyAt(decoded) is { } hit)
            {
                reasons.Add($"the encoded command {hit.Meaning}");
                severity = Severity.High;
                shownDecoded = KeywordLists.Around(decoded, hit.Index, hit.Length, 400); // the part that matched
            }
            // Editors, installers and automation tools run encoded PowerShell all the time; on its own, with
            // decoded text that matches no rule, it is context rather than a lead.
            else if (reasons.Count > 0 && reasons.All(r => r.Contains("encoded PowerShell", StringComparison.Ordinal)))
                severity = Severity.Low;
        }
        // This program's own launcher is not the player's doing.
        if (Analysis.SelfTraces.IsOurCommand(decoded ?? commandLine))
        {
            reasons.Clear();
            commandLine = $"[{Analysis.SelfTraces.Label}] {commandLine}";
        }
        ctx.Arguments.Add(new ArgumentHit
        {
            Program = program, Pid = pid, CommandLine = commandLine.Length > 8000 ? commandLine[..8000] + "…" : commandLine,
            Source = source, TimeUtc = time, Reasons = string.Join("; ", reasons),
        });
        if (reasons.Count == 0) return;
        string key = program + "|" + string.Join(";", reasons) + "|" + LogPrefix.Replace(commandLine, "");
        if (reported != null && !reported.Add(key)) return;
        ctx.Flag(severity, FindingCategory.Arguments, $"Flagged arguments: {program}",
            $"{source}: {program} {(pid is { } p ? $"(pid {p}) " : "")}{string.Join("; ", reasons)}. " +
            (shownDecoded != null ? $"Hidden command: {shownDecoded}" : $"Command line: {Clip(commandLine, 400)}"),
            timeUtc: time);
    }

    static string Clip(string s, int n) => s.Length > n ? s[..n] + "…" : s;

    // ---- running processes -----------------------------------------------------------------

    static int Running(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                ct.ThrowIfCancellationRequested();
                if (p.Id <= 4 || p.Id == Environment.ProcessId) continue; // not ourselves
                var cmd = WinApi.GetCommandLine(p.Id);
                if (string.IsNullOrWhiteSpace(cmd)) continue;
                string program = p.ProcessName + ".exe";
                Record(ctx, program, p.Id, cmd, "Running now", WinApi.GetProcessStartUtc(p.Id));
                items++;
                if (program.Equals("javaw.exe", StringComparison.OrdinalIgnoreCase) || program.Equals("java.exe", StringComparison.OrdinalIgnoreCase))
                    InspectJava(ctx, p.Id, program, cmd);
            }
        }
        return items;
    }

    /// <summary>instrument.dll = a Java agent is active; a module whose file is gone = loaded then deleted.</summary>
    static void InspectJava(BypassContext ctx, int pid, string program, string commandLine)
    {
        var modules = Modules(pid);
        if (modules.Any(m => Path.GetFileName(m).Equals("instrument.dll", StringComparison.OrdinalIgnoreCase)))
        {
            var agents = AgentsIn(commandLine);
            if (agents.Count == 0)
                ctx.Flag(Severity.High, FindingCategory.Process, $"Java agent attached to running {program} (pid {pid})",
                    "A Java agent is loaded in the game but none was given on its command line, so one was attached after it " +
                    "started — the way many injection clients load.");
            else if (KnownLauncher(agents) == null)
                ctx.Flag(Severity.Medium, FindingCategory.Process, $"Java agent active in {program} (pid {pid})",
                    $"The game was started with Java agent(s): {string.Join(", ", agents)}. Some clients use agents legitimately; " +
                    "check what each one is.");
        }
        foreach (var m in modules.Where(m => m.Length > 3 && m[1] == ':' && !File.Exists(m)))
            ctx.Flag(Severity.High, FindingCategory.Process, $"Code loaded from a deleted file in {program}",
                $"{program} (pid {pid}) has {m} loaded, but that file no longer exists. It was loaded and then deleted.", m);
    }

    public static List<string> Modules(int pid)
    {
        var list = new List<string>();
        using var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h.IsInvalid) return list;
        var handles = new IntPtr[2048];
        if (!EnumProcessModulesEx(h, handles, handles.Length * IntPtr.Size, out int needed, LIST_MODULES_ALL)) return list;
        int count = Math.Min(handles.Length, needed / IntPtr.Size);
        var name = new char[1024];
        for (int i = 0; i < count; i++)
        {
            int n = GetModuleFileNameEx(h, handles[i], name, name.Length);
            if (n > 0) list.Add(new string(name, 0, n));
        }
        return list;
    }

    // ---- process-creation history ------------------------------------------------------------

    static int ProcessEvents(BypassContext ctx)
    {
        int items = 0;
        foreach (var r in Events.Read("Security", "*[System[EventID=4688]]", 5000))
        {
            var d = Events.Data(r);
            var cmd = d.GetValueOrDefault("CommandLine") ?? "";
            if (cmd.Length == 0) continue;
            Record(ctx, Path.GetFileName(d.GetValueOrDefault("NewProcessName") ?? "?"), null, cmd, "Process created (Security 4688)", Events.Utc(r));
            items++;
        }
        foreach (var r in Events.Read("Microsoft-Windows-Sysmon/Operational", "*[System[EventID=1]]", 5000))
        {
            var d = Events.Data(r);
            var cmd = d.GetValueOrDefault("CommandLine") ?? "";
            if (cmd.Length == 0) continue;
            Record(ctx, Path.GetFileName(d.GetValueOrDefault("Image") ?? "?"), null, cmd, "Process created (Sysmon 1)", Events.Utc(r));
            items++;
        }
        // PowerShell launches are already collected as commands by History Parser.
        foreach (var c in ctx.History.Commands.Where(c => c.Source.StartsWith("PowerShell started", StringComparison.Ordinal)))
        {
            Record(ctx, "powershell.exe", null, c.Command, "PowerShell started (event 400)", c.TimeUtc);
            items++;
        }
        return items;
    }

    // ---- launcher / game logs -----------------------------------------------------------------

    static readonly string[] LogRoots =
    [
        @"AppData\Roaming\.minecraft", @".lunarclient", @"AppData\Roaming\.feather", @"AppData\Roaming\PrismLauncher",
        @"AppData\Roaming\ModrinthApp", @"AppData\Roaming\com.modrinth.theseus", @"AppData\Roaming\Badlion Client",
        @"AppData\Roaming\.tlauncher", @"AppData\Roaming\MultiMC", @"AppData\Roaming\gdlauncher_next", @"AppData\Roaming\.salwyrr",
    ];

    const long MaxLogBytes = 25L * 1024 * 1024;
    const int MaxLogFiles = 150;

    static int LauncherLogs(BypassContext ctx, CancellationToken ct)
    {
        var files = new List<FileInfo>();
        foreach (var profile in JavaUsageCollector.UserProfiles())
            foreach (var root in LogRoots)
            {
                var dir = Path.Combine(profile, root);
                if (Directory.Exists(dir)) files.AddRange(LogFiles(dir, 0));
            }

        int items = 0;
        var reported = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in files.Where(f => ctx.NowUtc - f.LastWriteTimeUtc < TimeSpan.FromDays(90))
                     .OrderByDescending(f => f.LastWriteTimeUtc).Take(MaxLogFiles))
        {
            ct.ThrowIfCancellationRequested();
            IEnumerable<string> lines;
            try { lines = ReadLines(file); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { continue; }
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in lines)
            {
                if (line.Length < 8 || !line.Contains('-')) continue;
                // Game logs: only the Java rules, not the "any program" word list (mods log words like "@Inject").
                if (ctx.ArgumentRules.Match("javaw.exe", line, includeWildcard: false).Count == 0) continue;
                if (!seen.Add(line)) continue;
                Record(ctx, "javaw.exe", null, line.Trim(), $"Launcher log: {file.FullName}", file.LastWriteTimeUtc, false, reported);
                items++;
            }
        }
        return items;
    }

    static IEnumerable<FileInfo> LogFiles(string dir, int depth)
    {
        if (depth > 5) yield break;
        string[] files, dirs;
        try
        {
            files = Directory.GetFiles(dir);
            dirs = Directory.GetDirectories(dir);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { yield break; }
        foreach (var f in files)
        {
            var name = Path.GetFileName(f);
            bool log = name.EndsWith(".log", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".log.gz", StringComparison.OrdinalIgnoreCase) ||
                       name.Equals("launcher_log.txt", StringComparison.OrdinalIgnoreCase);
            if (!log) continue;
            var fi = new FileInfo(f);
            if (fi.Length <= MaxLogBytes) yield return fi;
        }
        foreach (var d in dirs)
        {
            var n = Path.GetFileName(d);
            // Skip the game's asset and library trees; they are huge and contain no logs.
            if (n is "assets" or "libraries" or "versions" or "resourcepacks" or "saves" or "screenshots" or "shaderpacks" or "jre" or "runtime") continue;
            foreach (var f in LogFiles(d, depth + 1)) yield return f;
        }
    }

    static IEnumerable<string> ReadLines(FileInfo file)
    {
        using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        Stream s = file.Name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? new GZipStream(fs, CompressionMode.Decompress) : fs;
        using var reader = new StreamReader(s);
        var lines = new List<string>();
        long total = 0;
        for (string? line = reader.ReadLine(); line != null && total < MaxLogBytes * 4; line = reader.ReadLine())
        {
            total += line.Length;
            lines.Add(line);
        }
        return lines;
    }
}

/// <summary>System processes running from the wrong folder, and kernel drivers worth a second look.</summary>
public static class ProcessAudit
{
    static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    static readonly string System32 = Path.Combine(Windows, "System32");
    static readonly string SysWow64 = Path.Combine(Windows, "SysWOW64");

    static readonly HashSet<string> SystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "csrss", "lsass", "services", "smss", "wininit", "winlogon", "dwm", "conhost", "taskhostw",
        "RuntimeBroker", "spoolsv", "SearchIndexer", "sihost", "fontdrvhost", "dllhost", "ctfmon", "audiodg", "explorer",
    };

    /// <summary>Drivers that are signed but known to be abused to load unsigned kernel code (driver mappers).</summary>
    internal static readonly Dictionary<string, string> AbusedDrivers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["iqvw64e.sys"] = "Intel network diagnostics driver used by kdmapper",
        ["gdrv.sys"] = "Gigabyte driver used to map unsigned drivers",
        ["RTCore64.sys"] = "MSI Afterburner driver abused for kernel memory access",
        ["dbutil_2_3.sys"] = "Dell BIOS utility driver abused for kernel access",
        ["capcom.sys"] = "Capcom driver that runs arbitrary kernel code",
        ["mhyprot2.sys"] = "Genshin anti-cheat driver abused to kill processes",
        ["cpuz141.sys"] = "CPU-Z driver abused for kernel memory access",
        ["AsrDrv104.sys"] = "ASRock driver abused for kernel access",
        ["kprocesshacker.sys"] = "Process Hacker kernel driver",
        ["SystemInformer.sys"] = "System Informer kernel driver",
        ["procexp152.sys"] = "Process Explorer kernel driver",
        ["WinRing0x64.sys"] = "WinRing0 hardware access driver (also used by fan/RGB tools)",
    };

    public static int Run(BypassContext ctx, CancellationToken ct)
    {
        int items = 0;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (!SystemNames.Contains(p.ProcessName) || ImagePath(p.Id) is not { } path) continue;
                var dir = Path.GetDirectoryName(path) ?? "";
                bool ok = dir.Equals(System32, StringComparison.OrdinalIgnoreCase) || dir.Equals(SysWow64, StringComparison.OrdinalIgnoreCase) ||
                          (p.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase) && dir.Equals(Windows, StringComparison.OrdinalIgnoreCase));
                if (ok) continue;
                ctx.Flag(Severity.High, FindingCategory.Process, $"Fake system process: {p.ProcessName}.exe",
                    $"A process named like a Windows component ({p.ProcessName}.exe, pid {p.Id}) is running from {path} instead of {System32}.", path);
                items++;
            }
        }
        items += Drivers(ctx);
        return items;
    }

    internal static string? ImagePath(int pid)
    {
        using var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return null;
        var buf = new char[1024];
        int size = buf.Length;
        return QueryFullProcessImageName(h, 0, buf, ref size) ? new string(buf, 0, size) : null;
    }

    static int Drivers(BypassContext ctx)
    {
        var bases = new IntPtr[4096];
        if (!EnumDeviceDrivers(bases, bases.Length * IntPtr.Size, out int needed)) return 0;
        int count = Math.Min(bases.Length, needed / IntPtr.Size);
        var name = new char[1024];
        int items = 0;
        for (int i = 0; i < count; i++)
        {
            int n = GetDeviceDriverFileName(bases[i], name, name.Length);
            if (n <= 0) continue;
            var path = NormalizeDriverPath(new string(name, 0, n));
            var file = Path.GetFileName(path);
            bool windows = path.StartsWith(Windows, StringComparison.OrdinalIgnoreCase);
            bool installed = path.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) ||
                             path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase);
            string note = "";
            bool flagged = false;
            if (AbusedDrivers.TryGetValue(file, out var why))
            {
                note = why;
                flagged = true;
                ctx.Flag(Severity.Medium, FindingCategory.Process, $"Abusable kernel driver loaded: {file}",
                    $"{file} is loaded right now ({why}). Legitimate tools ship some of these too; check which program installed it.", path);
            }
            else if (!windows && !installed)
            {
                note = "loaded from outside Windows and Program Files";
                flagged = true;
                ctx.Flag(Severity.High, FindingCategory.Process, $"Driver loaded from an unusual folder: {file}",
                    $"The kernel driver {path} is loaded. Drivers normally live in Windows or an installed program's folder; " +
                    "one loaded from a user folder is how kernel cheats and mappers start.", path);
            }
            ctx.Drivers.Add(new DriverRow { Name = file, Path = path, Note = note, Flagged = flagged });
            items++;
        }
        return items;
    }

    public static string NormalizeDriverPath(string raw)
    {
        var p = raw;
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = Windows + p[11..];
        else if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        else if (p.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase)) p = Path.GetPathRoot(Windows)!.TrimEnd('\\') + p;
        else if (!p.Contains(':')) p = Path.Combine(System32, "drivers", Path.GetFileName(p));
        return p;
    }
}
