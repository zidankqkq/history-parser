using System.Diagnostics;
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Models;

namespace RatChecker.Core;

/// <summary>One thing found in a running game.</summary>
public sealed record ClientFinding(Severity Severity, string Area, string Title, string Why, string Evidence);

public sealed class ClientScanResult
{
    public required GameProcess Game { get; init; }
    public List<ClientFinding> Findings { get; } = new();
    /// <summary>Every jar the game loaded (its classpath, agents and mods), with the Program Checker's verdicts.</summary>
    public List<RatFileReport> Jars { get; } = new();
    public List<string> Notes { get; } = new();
    public int DllsChecked { get; set; }
    public int ProgramsChecked { get; set; }
    public long MemoryRead { get; set; }
    public int CustomStrings { get; set; }

    public Severity? Worst => Findings.Count == 0 ? null : Findings.Max(f => f.Severity);
}

/// <summary>
/// Checks a running Minecraft for a cheat by what any client has to leave in the game, whatever it is called: the jars
/// it was loaded from (each judged by the Program Checker's behaviour rules), DLLs inside the game that attach to its
/// Java, inject or fake input, native code that belongs to no file (a manually mapped DLL), classes that no loaded file
/// provides, servers the game contacted that no loaded file names, and - optionally - strings from the checker's own
/// lists (for example a Cheat String Finder file). The game's memory is only read.
///
/// Calibrated against what normal games do: launchers add their own Java agent (Modrinth's theseus.jar from Temp) and
/// mods unpack unsigned DLLs into Temp (voice chat codecs), so neither is a finding on its own - only what the code does.
/// </summary>
public static class ClientScan
{
    /// <summary>A string list to search for: its [core] strings (a client's own classes) and [supporting] ones.</summary>
    public sealed record StringListInput(string Name, IReadOnlyList<string> Core, IReadOnlyList<string> Supporting)
    {
        public static StringListInput Load(string path)
        {
            var (core, supporting) = GameDiff.ReadList(path);
            return new(Path.GetFileName(path), core, supporting);
        }
    }

    public static ClientScanResult Scan(GameProcess game, IReadOnlyList<StringListInput> lists, Action<string>? progress = null, CancellationToken ct = default)
    {
        var customStrings = lists.SelectMany(l => l.Core.Concat(l.Supporting)).Distinct(StringComparer.Ordinal).ToList();
        var result = new ClientScanResult { Game = game, CustomStrings = customStrings.Count };
        void Find(Severity s, string area, string title, string why, string evidence) => result.Findings.Add(new ClientFinding(s, area, title, why, evidence));

        // 1. The jars the game loaded: the classpath, -javaagent jars and the mods folder.
        progress?.Invoke("Finding the files the game loaded…");
        var jars = CheatStrings.GameJars(game.Pid, result.Notes);
        int done = 0;
        var reports = jars.AsParallel().WithDegreeOfParallelism(Math.Clamp(Environment.ProcessorCount / 2, 1, 6)).WithCancellation(ct).Select(path =>
        {
            var r = RatScanner.Scan(path);
            if (Interlocked.Increment(ref done) % 25 == 0) progress?.Invoke($"Checked {done:N0} of {jars.Count:N0} loaded files…");
            return r;
        }).ToList();
        result.Jars.AddRange(reports.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase));
        foreach (var r in reports)
        {
            var top = r.Signs.Where(s => CheatScanner.IsCheat(s.Category) && s.Severity >= Severity.Medium).OrderByDescending(s => s.Severity).ToList();
            if (r.CheatVerdict == CheatVerdict.Cheat)
                Find(Severity.High, "Loaded files", $"The game loaded cheat code: {r.Name}",
                    $"The Program Checker found cheat code in a file this game loaded: {string.Join("; ", top.Where(s => s.Severity == Severity.High).Select(s => s.Title).Distinct().Take(4))}.", r.Path);
            else if (r.CheatVerdict == CheatVerdict.Possible)
                Find(Severity.Medium, "Loaded files", $"A loaded file needs a look: {r.Name}",
                    $"{string.Join("; ", top.Select(s => s.Title).Distinct().Take(4))}. Open it in the Program Checker to see why.", r.Path);
            if (r.Verdict == RatVerdict.Dangerous)
                Find(Severity.High, "Loaded files", $"The game loaded a stealer / RAT: {r.Name}", r.VerdictText + " (Program Checker).", r.Path);
        }

        // 2. DLLs inside the game: judged by what they import, never by name or folder alone.
        progress?.Invoke("Checking the DLLs loaded in the game…");
        foreach (var dll in LoadedDlls(game.Pid, result.Notes))
        {
            ct.ThrowIfCancellationRequested();
            if (IsSystemFolder(dll)) continue;
            var sig = FileInspector.Verify(dll);
            if (sig is SignatureStatus.Signed or SignatureStatus.WindowsFile) continue;
            result.DllsChecked++;
            var r = RatScanner.Scan(dll);
            foreach (var s in r.Signs.Where(s => s.Category is RatCategory.CheatInjector or RatCategory.CheatClicker && s.Severity >= Severity.Medium))
                Find(Severity.High, "DLLs in the game", $"{s.Title}: {Path.GetFileName(dll)}",
                    $"An unsigned DLL loaded inside the game: {s.Why}", dll);
        }

        // 3. How code got in and what it touches: threads, hooks, access from outside, the network path, overlays.
        progress?.Invoke("Checking threads, hooks and access to the game…");
        Inspect(game, result, Find, ct);

        // Native code that belongs to no file: a DLL mapped by hand so it never shows in the module list.
        long kb = CheatStrings.HiddenCodeKb(game.Pid);
        if (kb >= 64)
            Find(Severity.High, "Game memory", "Hidden native code in the game",
                $"The game holds {kb:N0} KB of program code that belongs to no file. The JVM's own compiled code is writable; every DLL is a file. " +
                "Code like this was mapped in by hand - how native clients are injected so they never appear in the list of loaded DLLs.", $"{kb:N0} KB");

        // 4. Memory: classes no loaded file provides, servers no loaded file names, and the checker's own strings.
        progress?.Invoke("Reading the game's memory…");
        var hits = new HashSet<string>(StringComparer.Ordinal);
        var classes = new HashSet<string>(StringComparer.Ordinal);
        var hosts = new HashSet<string>(StringComparer.Ordinal);
        result.MemoryRead = CheatStrings.ScanMemory(game.Pid, [], hits, classes, progress, ct, hosts);
        // The lists: all of the game's memory, whole strings only - exactly how Cheat String Finder proved them absent
        // from a clean game, so a match means the same thing here.
        if (customStrings.Count > 0)
        {
            progress?.Invoke("Searching all of the game's memory for your strings…");
            CheatStrings.ScanMemory(game.Pid, customStrings, hits, null, progress, ct, allRegions: true, wholeStrings: true);
        }
        progress?.Invoke("Comparing with the loaded files…");
        var clean = CheatStrings.ReadClean(jars, null, null, out _, ct);
        var unexplained = CheatStrings.Unexplained(classes, clean);
        foreach (var pkg in unexplained.GroupBy(n => n[..n.LastIndexOf('/')]).OrderByDescending(g => g.Count()))
            Find(Severity.High, "Game memory", $"Code from no file: {pkg.Key.Replace('/', '.')}",
                $"{pkg.Count()} classes are loaded in the game from a package that none of the files the game loaded contains. Injected clients load their classes this way.",
                string.Join(", ", pkg.Take(12).Select(n => n[(n.LastIndexOf('/') + 1)..])) + (pkg.Count() > 12 ? " …" : ""));
        // 5. Everything else running beside the game: programs and the scripts they run, judged by what they do.
        progress?.Invoke("Checking the other running programs and scripts…");
        RunningPrograms(game.Pid, result, Find, ct);

        // A list's domains (a client's licence server, its site) also count when Windows looked them up recently.
        var domains = customStrings.Where(s => s.Contains('.') && Uri.CheckHostName(s) == UriHostNameType.Dns).ToList();
        if (domains.Count > 0)
        {
            // Without administrator rights Windows answers with an empty cache instead of an error.
            if (HistoryParser.Core.Native.DnsCache.Read() is { } dns && (dns.Count > 0 || HistoryParser.Core.Native.WinApi.IsElevated()))
            {
                var looked = dns.Select(d => d.Name).ToHashSet(StringComparer.Ordinal);
                var cached = domains.Where(d => looked.Contains(d.TrimEnd('.').ToLowerInvariant())).ToList();
                hits.UnionWith(cached);
                if (cached.Count > 0) result.Notes.Add($"Looked up recently by this PC (DNS cache): {string.Join(", ", cached)}.");
            }
            else result.Notes.Add("The DNS cache could not be read (run as administrator), so your list's domains were only searched for in the game.");
        }

        var namedHosts = CheatStrings.ContainedIn(hosts, clean, ct);
        foreach (var host in hosts.Where(h => !namedHosts.Contains(h)).Order())
            Find(Severity.Medium, "Game memory", $"Contacted a server no loaded file names: {host}",
                "The game sent a web request to this server, and none of the files it loaded mentions it. Native and injected clients contact their own servers (licence, config, downloads). Check what the server is.", host);
        // One finding per list, judged on how much of it is there - never one alarm per string.
        foreach (var list in lists)
        {
            var core = list.Core.Where(hits.Contains).ToList();
            var supporting = list.Supporting.Where(hits.Contains).ToList();
            if (JudgeList(list, core.Count, supporting.Count) is not { } severity) continue;
            int found = core.Count + supporting.Count, total = list.Core.Count + list.Supporting.Count;
            string why = severity switch
            {
                Severity.High => "Many strings from this list are in this game's memory. Each was proven absent from a clean game, so the client the list was made from is (or was) injected here.",
                Severity.Medium => "Part of the list matches. A couple of strings can be chance - a mod with similar names - so check them by hand (System Informer, Memory > Strings).",
                _ => "One string matched. On its own that means little.",
            };
            Find(severity, "Your strings", $"{list.Name}: {found} of {total} strings found",
                why + (list.Core.Count > 0 ? $" (Older list: {core.Count} of its {list.Core.Count} [core] strings found.)" : ""),
                string.Join(", ", core.Concat(supporting).Take(15)) + (found > 15 ? " …" : ""));
        }
        if (customStrings.Count > 0 && !customStrings.Any(hits.Contains))
            result.Notes.Add($"None of your {customStrings.Count:N0} strings were found in the game's memory.");
        return result;
    }

    /// <summary>
    /// How much of a list has to be there. Core strings are a client's own classes, proven absent from a clean game, so a
    /// few of them is the client. Supporting strings only add to that. A list without sections (older, or hand-made) needs
    /// more hits because nothing says which of its strings are the client itself.
    /// </summary>
    internal static Severity? JudgeList(StringListInput list, int core, int supporting)
    {
        if (list.Core.Count == 0)
            return supporting >= 5 ? Severity.High : supporting >= 2 ? Severity.Medium : supporting == 1 ? Severity.Low : null;
        if (core >= 3 || core >= 2 && supporting >= 2) return Severity.High;
        if (core >= 1 || supporting >= 3) return Severity.Medium;
        return supporting >= 1 ? Severity.Low : null;
    }

    /// <summary>A program is trusted for its access when it is validly signed (an overlay, an anticheat, a recorder).</summary>
    static bool Trusted(string? path) => path != null && File.Exists(path) && FileInspector.Verify(path) is SignatureStatus.Signed or SignatureStatus.WindowsFile;

    static string Who(int pid) => GameInspection.ImagePath(pid) is { } p ? $"{Path.GetFileName(p)} (PID {pid}) - {p}" : $"PID {pid}";

    static void Inspect(GameProcess game, ClientScanResult result, Action<Severity, string, string, string, string> find, CancellationToken ct)
    {
        using var h = HistoryParser.Core.Native.NativeMethods.OpenProcess(
            HistoryParser.Core.Native.NativeMethods.PROCESS_QUERY_INFORMATION | HistoryParser.Core.Native.NativeMethods.PROCESS_VM_READ, false, game.Pid);
        if (h.IsInvalid) { result.Notes.Add("The game could not be opened for reading - run as administrator."); return; }
        var mods = GameInspection.Modules(game.Pid);

        foreach (var (tid, start, where) in GameInspection.ForeignThreads(game.Pid, h, mods))
            find(Severity.High, "Threads", $"A thread started in code that belongs to no file (thread {tid})",
                "Every thread the game, Java or a DLL starts begins inside a loaded DLL. This one started in memory that no file explains - code was injected and started from outside.",
                $"start 0x{start:X} in {where}");

        foreach (var (module, function, target, where) in GameInspection.Hooks(h, mods, result.Notes))
        {
            bool fromNowhere = !File.Exists(where);
            var sev = fromNowhere || !Trusted(where) ? Severity.High : Severity.Low;
            find(sev, "Hooks", $"{module}!{function} is patched to jump into {(fromNowhere ? "code from no file" : Path.GetFileName(where))}",
                $"The start of {function} in the game no longer matches {module} on disk: it jumps elsewhere. Clients hook drawing to show their menu and ESP, input to fake clicks, and network functions to change packets." +
                (sev == Severity.Low ? " The jump leads into a signed program (overlays like Discord, Steam or RivaTuner do this), so it is listed for context." : ""),
                $"{module}!{function} → 0x{target:X} in {where}");
        }

        ct.ThrowIfCancellationRequested();
        int parent = GameInspection.ParentPid(game.Pid);
        if (GameInspection.WriteHandles(game.Pid) is { } holders)
            foreach (var (pid, access) in holders)
            {
                string? path = GameInspection.ImagePath(pid);
                bool launcher = pid == parent;
                var sev = launcher || Trusted(path) || path != null && path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)
                    ? Severity.Low : Severity.High;
                if (sev == Severity.Low && launcher) continue; // the launcher that started the game always holds full access
                find(sev, "Access to the game", $"{(path != null ? Path.GetFileName(path) : $"PID {pid}")} can change the game's memory",
                    $"This program holds a handle to the game with {Rights(access)}. External cheats and injectors need exactly that; programs that only watch the game don't." +
                    (sev == Severity.Low ? " It is signed or part of Windows, so it is listed for context." : ""),
                    Who(pid));
            }
        else result.Notes.Add("Other programs' access to the game could not be checked - run as administrator.");

        foreach (var (port, proxy) in GameInspection.LocalProxies(game.Pid))
        {
            string? path = GameInspection.ImagePath(proxy);
            find(Trusted(path) ? Severity.Low : Severity.Medium, "Network", $"The game connects through a local proxy on port {port}",
                "The game's connection goes to another program on this PC instead of straight to the server. Proxy clients cheat this way - they change packets between the game and the server, invisible to the game itself. Version proxies do it legitimately; check what the program is.",
                Who(proxy));
        }

        foreach (var (pid, title) in GameInspection.Overlays(game.Pid))
        {
            string? path = GameInspection.ImagePath(pid);
            find(Trusted(path) ? Severity.Low : Severity.Medium, "Screen", $"A click-through window is drawn over the game: {(path != null ? Path.GetFileName(path) : $"PID {pid}")}",
                "An always-on-top, click-through window covers the game. External ESP and cheat menus draw this way; signed overlays (GPU, recording, chat) do too.",
                $"\"{title}\" - {Who(pid)}");
        }
    }

    static readonly System.Text.RegularExpressions.Regex ScriptArg = new(
        @"(?:""([^""]+\.(?:ahk|au3|py|pyw|ps1|vbs|vbe|js|jse|bat|cmd|jar))""|(\S+\.(?:ahk|au3|py|pyw|ps1|vbs|vbe|js|jse|bat|cmd|jar)))(?=\s|$)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Every other running program: one running from a file that no longer exists, an unsigned program that fakes input or
    /// injects, and any script or jar a running program was started with (AutoHotkey, Python, PowerShell, java -jar).
    /// </summary>
    static void RunningPrograms(int gamePid, ClientScanResult result, Action<Severity, string, string, string, string> find, CancellationToken ct)
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var checkedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
            using (p)
            {
                ct.ThrowIfCancellationRequested();
                if (p.Id == gamePid || p.Id == Environment.ProcessId || p.Id <= 4) continue;
                string? image = GameInspection.ImagePath(p.Id);
                if (image == null) continue;
                if (!File.Exists(image))
                {
                    find(Severity.High, "Running programs", $"{Path.GetFileName(image)} is running from a file that was deleted",
                        "The program is running, but its file is gone. Deleting a cheat or bypass tool right after starting it is a common way to hide it from a screenshare.",
                        Who(p.Id));
                    continue;
                }
                var files = new List<string>();
                if (!image.StartsWith(win + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && !Trusted(image)) files.Add(image);
                if (HistoryParser.Core.Native.WinApi.GetCommandLine(p.Id) is { } cmd)
                    foreach (System.Text.RegularExpressions.Match m in ScriptArg.Matches(cmd))
                    {
                        var arg = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
                        if (File.Exists(arg)) files.Add(Path.GetFullPath(arg));
                    }
                foreach (var file in files.Where(checkedFiles.Add))
                {
                    var r = RatScanner.Scan(file);
                    var bad = r.Signs.Where(s => CheatScanner.IsCheat(s.Category) && s.Severity == Severity.High).Select(s => s.Title).Distinct().ToList();
                    if (bad.Count > 0)
                        find(Severity.High, "Running programs", $"{Path.GetFileName(file)} is running: {string.Join(", ", bad.Take(3))}",
                            $"A program or script running beside the game does what cheats do ({string.Join("; ", bad)}).", $"{file}\nrun by {Who(p.Id)}");
                    if (r.Verdict == RatVerdict.Dangerous)
                        find(Severity.High, "Running programs", $"{Path.GetFileName(file)} is running and looks like a stealer / RAT", r.VerdictText + " (Program Checker).", $"{file}\nrun by {Who(p.Id)}");
                }
                result.ProgramsChecked += files.Count;
                // A clicker pasted into PowerShell has no file to check: read the scripts the engine is holding.
                if (HostsPowerShell(p)) PowerShellScripts(p.Id, find, ct);
            }
    }

    /// <summary>Whether a process runs the PowerShell engine: powershell, pwsh, the ISE, a renamed copy, or any program hosting it.</summary>
    static bool HostsPowerShell(Process p)
    {
        try { return p.Modules.Cast<ProcessModule>().Any(m => m.ModuleName?.StartsWith("System.Management.Automation", StringComparison.OrdinalIgnoreCase) == true); }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException) { return false; }
    }

    /// <summary>Whole scripts in a PowerShell process's memory that fake clicks or keys while watching the keyboard. Only read.</summary>
    static void PowerShellScripts(int pid, Action<Severity, string, string, string, string> find, CancellationToken ct)
    {
        ScriptInput.Verdict? best = null;
        string? text = null;
        try
        {
            HistoryParser.Core.Collectors.ProcessMemoryCollector.ScanProcess(pid, long.MaxValue, ct, s =>
            {
                if ((best?.High ?? false) || ScriptInput.Judge(s) is not { } v || (best != null && !v.High)) return;
                best = v;
                text = s;
            }, HistoryParser.Core.Collectors.StringExtractor.InputNeedlesAscii, HistoryParser.Core.Collectors.StringExtractor.InputNeedlesWide, multiLine: true);
        }
        catch (UnauthorizedAccessException) { return; }
        if (best is { } b && text != null)
            find(b.High ? Severity.High : Severity.Medium, "Running programs", $"{b.Title}: running in PowerShell",
                $"{b.Why} This script is in the memory of a running PowerShell right now.",
                $"\"{KeywordLists.Around(text, b.Index, b.Length, 300)}\"\nin {Who(pid)}");
    }

    static string Rights(uint access)
    {
        var r = new List<string>();
        if ((access & 0x20) != 0) r.Add("write access to its memory");
        if ((access & 0x8) != 0) r.Add("memory-operation rights");
        if ((access & 0x2) != 0) r.Add("the right to start threads in it");
        return string.Join(", ", r);
    }

    /// <summary>The DLLs loaded in the process, by file path. Needs a 64-bit checker for a 64-bit game.</summary>
    static List<string> LoadedDlls(int pid, List<string> notes)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.Modules.Cast<ProcessModule>().Select(m => m.FileName).Where(f => f != null && File.Exists(f))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList()!;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException)
        {
            notes.Add($"The game's DLL list could not be read ({e.Message}). Run as administrator.");
            return [];
        }
    }

    static bool IsSystemFolder(string path)
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return path.StartsWith(win + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Strings from a list file: one per line; blank lines and # comments are skipped (Cheat String Finder files load as they are).</summary>
    public static List<string> ReadStringList(string path) =>
        File.ReadLines(path).Select(l => l.Trim()).Where(l => l.Length >= 4 && !l.StartsWith('#')).Distinct(StringComparer.Ordinal).ToList();
}
