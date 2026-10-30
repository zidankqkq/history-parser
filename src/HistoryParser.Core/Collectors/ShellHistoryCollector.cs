using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Collectors;

/// <summary>
/// Everything a user typed or launched from a shell: PowerShell history (every host), Git Bash and
/// Python history, Windows Terminal's saved buffers, prompts still on screen in open console windows,
/// command lines of running shells, the Win+R Run box, Explorer's address bar and search box, and the
/// PowerShell / process-creation event logs. Anti-forensic commands are flagged.
/// </summary>
public sealed class ShellHistoryCollector : ICollector
{
    public string Name => "Command history";

    static readonly KeywordLists Defaults = KeywordLists.Default();

    /// <summary>Classifies with the default rules (kept for tests and callers without scan options).</summary>
    public static string? Classify(string line) => Defaults.Classify(line);

    KeywordLists _rules = Defaults;

    // "PS C:\Users\x> command" and "C:\Users\x>command" as they appear on screen.
    static readonly Regex PsPrompt = new(@"^\s*PS [A-Za-z]:\\[^>\r\n]{0,240}>\s?(?<cmd>\S.{0,2000})$", RegexOptions.Compiled);
    static readonly Regex CmdPrompt = new(@"^\s*[A-Za-z]:\\[^>\r\n<|""]{0,240}>(?<cmd>[^\s>].{0,2000})$", RegexOptions.Compiled);

    /// <summary>Extracts the command from a screen line that starts with a PowerShell or cmd prompt.</summary>
    public static (string Shell, string Command)? ParsePromptLine(string line)
    {
        line = line.TrimEnd();
        if (PsPrompt.Match(line) is { Success: true } ps) return ("PowerShell", ps.Groups["cmd"].Value.Trim());
        if (CmdPrompt.Match(line) is { Success: true } cmd) return ("cmd", cmd.Groups["cmd"].Value.Trim());
        return null;
    }

    readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    int _items;

    public int Collect(ScanContext ctx, CancellationToken ct)
    {
        _rules = ctx.Options.Keywords;
        foreach (var profile in JavaUsageCollector.UserProfiles())
        {
            ct.ThrowIfCancellationRequested();
            string user = Path.GetFileName(profile);
            PowerShellHistory(ctx, profile, user);
            PlainHistory(ctx, Path.Combine(profile, ".bash_history"), "Bash", "Git Bash history", user);
            PlainHistory(ctx, Path.Combine(profile, ".python_history"), "Bash", "Python history", user);
            TerminalBuffers(ctx, profile, user);
        }
        RegistryHistory(ctx);
        RunningShells(ctx);
        ConsoleScreens(ctx, ct);
        PowerShellEngineLog(ctx);
        ScriptBlockLog(ctx);
        ProcessCreationLog(ctx);
        return _items;
    }

    void Add(ScanContext ctx, string group, string source, string command, string user, DateTime? time, int order,
        string detail = "", bool dedupe = true)
    {
        command = command.Trim();
        if (command.Length == 0) return;
        // The History Parser launcher downloads and runs a script — exactly what the rules
        // look for — but it is this program, not the player.
        bool ours = Analysis.SelfTraces.IsOurCommand(command);
        // Judged on the whole text before it is shortened for display: padding a command must not push
        // the part that matters out of view.
        var hit = ours ? null : _rules.ClassifyAt(command);
        var full = command;
        if (command.Length > 4000) command = hit is { } at ? KeywordLists.Around(command, at.Index, at.Length, 4000) : command[..4000] + "…";
        if (dedupe && !_seen.Add(group + "\n" + source + "\n" + command)) return;
        if (ours) detail = (Analysis.SelfTraces.Label + ": the History Parser launcher. " + detail).Trim();
        ctx.Commands.Add(new CommandEntry
        {
            Group = group, Source = source, Command = command, User = user, TimeUtc = time, Order = order,
            Detail = detail, Suspicion = hit?.Meaning,
        });
        _items++;
        if (hit is { } h)
        {
            // Show the flagged part: a long script's first few hundred characters are usually boilerplate.
            ctx.Flag(Severity.Medium, FindingCategory.AntiForensics, $"Command that {h.Meaning}",
                $"{source} ({user}): \"{KeywordLists.Around(full, h.Index, h.Length, 300)}\"{(detail.Length > 0 ? $" — {detail}" : "")}.", timeUtc: time);
        }
    }

    // ---- files -----------------------------------------------------------------------------

    void PowerShellHistory(ScanContext ctx, string profile, string user)
    {
        var dir = Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine");
        if (!Directory.Exists(dir)) return;
        foreach (var file in Directory.GetFiles(dir, "*_history.txt"))
        {
            // ConsoleHost_history.txt, "Visual Studio Code Host_history.txt", ...
            string host = Path.GetFileName(file)[..^"_history.txt".Length];
            var lines = ReadLines(file);
            if (lines == null) continue;
            var written = File.GetLastWriteTimeUtc(file);
            for (int i = 0; i < lines.Length; i++)
            {
                bool last = i == lines.Length - 1;
                Add(ctx, "PowerShell", $"PowerShell history · {host}", lines[i], user, null, i,
                    last ? $"most recent entry; history file last written {Util.When.L(written)}" : $"entry {i + 1} of {lines.Length}",
                    dedupe: false);
            }
        }
    }

    void PlainHistory(ScanContext ctx, string file, string group, string source, string user)
    {
        var lines = ReadLines(file);
        if (lines == null) return;
        for (int i = 0; i < lines.Length; i++)
            Add(ctx, group, source, lines[i], user, null, i, $"entry {i + 1} of {lines.Length}", dedupe: false);
    }

    /// <summary>Windows Terminal (1.21+) saves each tab's screen when "restore previous session" is on.</summary>
    void TerminalBuffers(ScanContext ctx, string profile, string user)
    {
        var packages = Path.Combine(profile, @"AppData\Local\Packages");
        if (!Directory.Exists(packages)) return;
        string[] dirs;
        try { dirs = Directory.GetDirectories(packages, "Microsoft.WindowsTerminal*"); }
        catch (UnauthorizedAccessException) { return; }
        foreach (var pkg in dirs)
        {
            var state = Path.Combine(pkg, "LocalState");
            if (!Directory.Exists(state)) continue;
            foreach (var file in Directory.GetFiles(state, "buffer_*.txt"))
            {
                var lines = ReadLines(file);
                if (lines == null) continue;
                var written = File.GetLastWriteTimeUtc(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (ParsePromptLine(lines[i]) is not { } p) continue;
                    Add(ctx, "CMD / Terminal", $"Windows Terminal saved tab ({p.Shell})", p.Command, user, null, i,
                        $"{Path.GetFileName(file)}, saved {Util.When.L(written)}");
                }
            }
        }
    }

    static string[]? ReadLines(string file)
    {
        if (!File.Exists(file)) return null;
        try
        {
            return TextDecoding.Decode(SafeFile.ReadAllBytesShared(file, 32 << 20))
                .Split('\n').Select(l => l.TrimEnd('\r', '\0')).Where(l => l.Trim().Length > 0).ToArray();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { return null; }
    }

    // ---- registry -----------------------------------------------------------------------------

    void RegistryHistory(ScanContext ctx)
    {
        foreach (var sid in WinApi.LoadedUserSids())
        {
            string user = WinApi.SidToName(sid);
            const string explorer = @"Software\Microsoft\Windows\CurrentVersion\Explorer";

            using (var run = Registry.Users.OpenSubKey($@"{sid}\{explorer}\RunMRU"))
            {
                if (run != null)
                {
                    var order = (run.GetValue("MRUList") as string) ?? "";
                    var written = WinApi.GetKeyLastWriteUtc(run);
                    foreach (var name in run.GetValueNames().Where(n => n.Length == 1))
                    {
                        if (run.GetValue(name) is not string cmd) continue;
                        if (cmd.EndsWith(@"\1", StringComparison.Ordinal)) cmd = cmd[..^2];
                        int pos = order.IndexOf(name, StringComparison.Ordinal);
                        bool newest = pos == 0;
                        Add(ctx, "Run box", "Win+R Run box", cmd, user, newest ? written : null,
                            order.Length - Math.Max(pos, 0),
                            newest ? "most recent Run entry (time = when the list last changed)" : $"Run history position {pos + 1}");
                    }
                }
            }

            using (var typed = Registry.Users.OpenSubKey($@"{sid}\{explorer}\TypedPaths"))
            {
                if (typed != null)
                {
                    var written = WinApi.GetKeyLastWriteUtc(typed);
                    foreach (var name in typed.GetValueNames())
                        if (typed.GetValue(name) is string path && int.TryParse(name.AsSpan(3), out int n))
                            Add(ctx, "Explorer", "Explorer address bar", path, user, n == 1 ? written : null, 100 - n,
                                n == 1 ? "most recently typed path" : $"typed path #{n}");
                }
            }

            using (var search = Registry.Users.OpenSubKey($@"{sid}\{explorer}\WordWheelQuery"))
            {
                if (search != null)
                {
                    foreach (var name in search.GetValueNames().Where(n => n != "MRUListEx"))
                        if (search.GetValue(name) is byte[] raw)
                            Add(ctx, "Explorer", "Explorer search box", Encoding.Unicode.GetString(raw).TrimEnd('\0'), user, null,
                                int.TryParse(name, out int idx) ? idx : 0, "searched in File Explorer");
                }
            }
        }
    }

    // ---- live processes ------------------------------------------------------------------------

    static readonly string[] ShellNames =
        ["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "javaw", "java", "bash", "wsl"];

    void RunningShells(ScanContext ctx)
    {
        foreach (var name in ShellNames)
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                using (p)
                {
                    if (WinApi.GetCommandLine(p.Id) is not { } cmd) continue;
                    Add(ctx, "Running", $"Running process: {name}.exe (pid {p.Id})", cmd, "", WinApi.GetProcessStartUtc(p.Id), 0,
                        "command line of a process that is running now (time = process start)");
                }
            }
        }
    }

    /// <summary>
    /// Console windows keep their screen text in the host process (conhost / OpenConsole / Windows
    /// Terminal). Lines that start with a prompt show commands typed in tabs that are still open —
    /// the only place cmd.exe history exists at all.
    /// </summary>
    void ConsoleScreens(ScanContext ctx, CancellationToken ct)
    {
        if (!ctx.Options.ScanProcessMemory) return;
        foreach (var name in new[] { "conhost", "OpenConsole", "WindowsTerminal" })
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                using (p)
                {
                    try
                    {
                        ProcessMemoryCollector.ScanProcess(p.Id, 256L << 20, ct, s =>
                        {
                            // Screen rows are stored back to back and padded with spaces.
                            foreach (var line in ScreenRows.Split(s))
                                if (ParsePromptLine(line) is { } prompt && prompt.Command.Length >= 2)
                                    Add(ctx, "CMD / Terminal", $"Open console window ({prompt.Shell}, {name}.exe)", prompt.Command, "",
                                        null, 0, $"read from the screen text of {name}.exe pid {p.Id}");
                        }, StringExtractor.PromptNeedlesAscii, StringExtractor.PromptNeedlesWide);
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
    }

    // ---- event logs ----------------------------------------------------------------------------

    static readonly Regex ScreenRows = new(@"\r?\n| {6,}", RegexOptions.Compiled);

    static readonly Regex HostApplication = new(@"HostApplication=(?<cmd>[^\r\n]+)", RegexOptions.Compiled);

    /// <summary>"Windows PowerShell" event 400: the command line each PowerShell engine started with.</summary>
    void PowerShellEngineLog(ScanContext ctx)
    {
        foreach (var r in Recent("Windows PowerShell", "*[System[EventID=400]]", 3000))
        {
            var text = string.Join("\n", r.Properties.Select(p => p.Value as string ?? ""));
            if (HostApplication.Match(text) is not { Success: true } m) continue;
            Add(ctx, "Event log", "PowerShell started (event 400)", m.Groups["cmd"].Value, "",
                r.TimeCreated?.ToUniversalTime(), 0, "how a PowerShell session was launched");
        }
    }

    /// <summary>Event 4104 script blocks. Interactive input has no script path; files are only kept when suspicious.</summary>
    void ScriptBlockLog(ScanContext ctx)
    {
        // Long scripts are logged in several parts (MessageNumber / MessageTotal, same ScriptBlockId): judge them whole too.
        var parts = new Dictionary<string, (SortedList<int, string> Texts, string User, DateTime? Time, string? Path)>();
        var flagged = new HashSet<string>();
        void Clicker(string text, string id, string user, DateTime? time, string? path)
        {
            if (ScriptInput.Judge(text) is not { } v || !flagged.Add(id)) return;
            ctx.Flag(v.High ? Severity.High : Severity.Medium, FindingCategory.Process, v.Title,
                $"{v.Why} PowerShell script block log (4104){(string.IsNullOrEmpty(path) ? ", typed or pasted" : $", from {path}")} ({user}): " +
                $"\"{KeywordLists.Around(text, v.Index, v.Length, 300)}\".", timeUtc: time);
        }

        foreach (var r in Recent("Microsoft-Windows-PowerShell/Operational", "*[System[EventID=4104]]", 5000))
        {
            var script = r.Properties.Count > 2 ? r.Properties[2].Value as string : null;
            var path = r.Properties.Count > 4 ? r.Properties[4].Value as string : null;
            if (string.IsNullOrWhiteSpace(script)) continue;
            string user = r.UserId?.Value is { } who ? WinApi.SidToName(who) : "";
            string id = r.Properties.Count > 3 ? r.Properties[3].Value?.ToString() ?? "" : "";
            Clicker(script, id.Length > 0 ? id : script, user, r.TimeCreated?.ToUniversalTime(), path);
            if (id.Length > 0 && r.Properties[0].Value is int n && r.Properties[1].Value is int total && total > 1)
            {
                if (!parts.TryGetValue(id, out var p)) parts[id] = p = (new SortedList<int, string>(), user, r.TimeCreated?.ToUniversalTime(), path);
                p.Texts[n] = script;
            }
            bool interactive = string.IsNullOrEmpty(path);
            if (!interactive && _rules.Classify(script) == null) continue;
            var shown = interactive ? script : script.Split('\n').FirstOrDefault(l => _rules.Classify(l) != null)?.Trim() ?? script;
            Add(ctx, "Event log", interactive ? "PowerShell typed command (4104)" : $"PowerShell script (4104): {Path.GetFileName(path)}",
                shown, user, r.TimeCreated?.ToUniversalTime(), 0,
                interactive ? "script block logging" : $"from {path}");
        }
        foreach (var (id, p) in parts)
            if (p.Texts.Count > 1) Clicker(string.Concat(p.Texts.Values), id, p.User, p.Time, p.Path);
    }

    /// <summary>Security 4688 with command lines (only present when process-creation auditing is on).</summary>
    void ProcessCreationLog(ScanContext ctx)
    {
        foreach (var r in Recent("Security", "*[System[EventID=4688]]", 5000))
        {
            var xml = XDocument.Parse(r.ToXml());
            string Data(string n) => xml.Descendants().FirstOrDefault(e => e.Name.LocalName == "Data" && (string?)e.Attribute("Name") == n)?.Value ?? "";
            var cmd = Data("CommandLine");
            if (cmd.Length == 0) continue;
            Add(ctx, "Event log", "Process created (Security 4688)", cmd, Data("SubjectUserName"), r.TimeCreated?.ToUniversalTime(), 0,
                $"parent {Path.GetFileName(Data("ParentProcessName"))}");
        }
    }

    static IEnumerable<EventRecord> Recent(string log, string xpath, int max)
    {
        EventLogReader reader;
        try { reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true }); }
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
}
