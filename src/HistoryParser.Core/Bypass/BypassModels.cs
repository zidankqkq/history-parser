using System.Text;
using System.Text.Json.Serialization;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Bypass;

/// <summary>State of one Windows event log channel.</summary>
public sealed record LogChannelInfo
{
    public required string Channel { get; init; }
    public bool? Enabled { get; init; }
    public long? RecordCount { get; init; }
    public long? MaxSizeBytes { get; init; }
    public long? FileSizeBytes { get; init; }
    public DateTime? OldestUtc { get; init; }
    public DateTime? NewestUtc { get; init; }
    public DateTime? LastWriteUtc { get; init; }
    public int RecordGaps { get; init; }
    public long MissingRecords { get; init; }
    public CheckState State { get; init; } = CheckState.Ok;
    public string Note { get; init; } = "";
}

/// <summary>Event record numbers are consecutive; a jump means records were removed from the middle of the log.</summary>
public sealed record RecordGap(string Channel, long AfterRecordId, long BeforeRecordId, DateTime? AfterTimeUtc, DateTime? BeforeTimeUtc)
{
    public long Missing => BeforeRecordId - AfterRecordId - 1;
}

public sealed record ServiceRow
{
    public required string Name { get; init; }
    public string Role { get; init; } = "";
    public string StartType { get; init; } = "";
    public string State { get; init; } = "";
    public DateTime? ProcessStartUtc { get; init; }
    /// <summary>Last write of the service's registry key: when its configuration last changed.</summary>
    public DateTime? ConfigChangedUtc { get; init; }
    public CheckState Status { get; init; } = CheckState.Ok;
    public string Note { get; init; } = "";
}

public sealed record ServiceEvent
{
    public DateTime? TimeUtc { get; init; }
    public required string Service { get; init; }
    public required string Change { get; init; }
    public int EventId { get; init; }
    public bool Suspicious { get; init; }
}

public sealed record UsbDevice
{
    public required string Name { get; init; }
    public string Serial { get; init; } = "";
    public string Kind { get; init; } = "USB storage";
    public string DriveLetter { get; init; } = "";
    public DateTime? FirstConnectedUtc { get; init; }
    public DateTime? LastConnectedUtc { get; init; }
    public DateTime? LastRemovedUtc { get; init; }
    public bool ConnectedNow { get; init; }
    public string InstanceId { get; init; } = "";
}

public sealed record UsbEvent
{
    public DateTime? TimeUtc { get; init; }
    public required string Device { get; init; }
    public string Serial { get; init; } = "";
    public required string Action { get; init; }
    public string Detail { get; init; } = "";
}

public sealed record ArgumentHit
{
    public required string Program { get; init; }
    public int? Pid { get; init; }
    public required string CommandLine { get; init; }
    public required string Source { get; init; }
    public DateTime? TimeUtc { get; init; }
    /// <summary>Why it was flagged (rule meanings), empty when nothing matched.</summary>
    public string Reasons { get; init; } = "";
    public bool Flagged => Reasons.Length > 0;
}

public sealed record DriverRow
{
    public required string Name { get; init; }
    public string Path { get; init; } = "";
    public string Note { get; init; } = "";
    public bool Flagged { get; init; }
}

public sealed record TaskRow
{
    public required string Name { get; init; }
    public DateTime? CreatedUtc { get; init; }
    public DateTime? ModifiedUtc { get; init; }
    public string Command { get; init; } = "";
    public string Note { get; init; } = "";
    public bool Flagged { get; init; }
}

public sealed record SoftwareRow
{
    public required string Name { get; init; }
    public string Version { get; init; } = "";
    public string Publisher { get; init; } = "";
    public DateTime? TimeUtc { get; init; }
    public required string Action { get; init; }
    public string Note { get; init; } = "";
    public bool Flagged { get; init; }
}

/// <summary>A forensic artifact (log, prefetch, history, shortcut …) that was deleted, emptied or changed.</summary>
public sealed record ArtifactChange
{
    public DateTime? TimeUtc { get; init; }
    public required string Artifact { get; init; }
    public required string Change { get; init; }
    public string Path { get; init; } = "";
    public string Detail { get; init; } = "";
    public bool Suspicious { get; init; }
}

public sealed record DefenderChange
{
    public DateTime? TimeUtc { get; init; }
    public required string Setting { get; init; }
    public string NewValue { get; init; } = "";
    public string OldValue { get; init; } = "";
    public bool Suspicious { get; init; }
}

/// <summary>One whole scan: the execution history plus the tampering and bypass checks.</summary>
/// <summary>
/// One thing checked on a way code can get into the game without being an ordinary program run:
/// boot settings, hardware, launch hooks, Java settings, and the running game process itself.
/// </summary>
public sealed record RouteCheck
{
    /// <summary>Boot, Hardware, Remote access, Launch hooks, Java, Startup, Game process, Handles.</summary>
    public required string Area { get; init; }
    public required string Item { get; init; }
    public string Value { get; init; } = "";
    public CheckState State { get; init; }
    public string Detail { get; init; } = "";
    public string Path { get; init; } = "";
    public DateTime? TimeUtc { get; init; }
}

public sealed class BypassReport
{
    public required ScanResult History { get; init; }
    public required List<Finding> Findings { get; init; }
    public List<LogChannelInfo> Logs { get; init; } = new();
    public List<RecordGap> RecordGaps { get; init; } = new();
    public List<ServiceRow> Services { get; init; } = new();
    public List<ServiceEvent> ServiceEvents { get; init; } = new();
    public List<UsbDevice> UsbDevices { get; init; } = new();
    public List<UsbEvent> UsbEvents { get; init; } = new();
    public List<ArgumentHit> Arguments { get; init; } = new();
    public List<DriverRow> Drivers { get; init; } = new();
    public List<TaskRow> Tasks { get; init; } = new();
    public List<SoftwareRow> Software { get; init; } = new();
    public List<ArtifactChange> Artifacts { get; init; } = new();
    public List<DefenderChange> Defender { get; init; } = new();
    public List<RouteCheck> Routes { get; init; } = new();
    public List<SourceStatus> Sources { get; init; } = new();
    public bool PrivateDetailsHidden { get; init; }
}

/// <summary>A program argument that gets flagged: <c>program: pattern =&gt; why</c>.</summary>
public sealed record ArgumentRule(string Program, CommandRule Rule)
{
    /// <summary>"*" matches every program; otherwise the executable file name, case-insensitive.</summary>
    public bool AppliesTo(string program) =>
        Program == "*" || string.Equals(Program, program, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Path.GetFileNameWithoutExtension(Program), Path.GetFileNameWithoutExtension(program), StringComparison.OrdinalIgnoreCase);
}

public sealed class ArgumentRules
{
    public IReadOnlyList<ArgumentRule> Rules { get; }

    public ArgumentRules(IEnumerable<ArgumentRule> rules) => Rules = rules.ToArray();

    static readonly string[] DefaultText =
    [
        "javaw.exe: -javaagent => loads a Java agent (can inject code into Minecraft)",
        "java.exe: -javaagent => loads a Java agent (can inject code into Minecraft)",
        "javaw.exe: /-agent(path|lib):(?!jdwp)/ => loads a native JVM agent",
        "java.exe: /-agent(path|lib):(?!jdwp)/ => loads a native JVM agent",
        "javaw.exe: /-agentlib:jdwp/ => opens a debugger port into the game",
        "javaw.exe: -Xbootclasspath => changes the boot class path (classic injection trick)",
        "java.exe: -Xbootclasspath => changes the boot class path (classic injection trick)",
        "javaw.exe: /-noverify\\b|-Xverify:none/ => turns off bytecode verification (common with injected clients)",
        "java.exe: /-noverify\\b|-Xverify:none/ => turns off bytecode verification (common with injected clients)",
        "javaw.exe: -Djava.system.class.loader => replaces the system class loader",
        "javaw.exe: -XX:+DisableAttachMechanism => blocks tools that inspect the running game",
        "javaw.exe: /-Dfabric\\.addMods|-Dfml\\.coreMods\\.load|-Dfml\\.customModList/ => adds mods through launch flags",
        "powershell.exe: /\\s-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+\\/=]{16,}/ => runs an encoded PowerShell command",
        "pwsh.exe: /\\s-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+\\/=]{16,}/ => runs an encoded PowerShell command",
        "powershell.exe: /-w(indowstyle)?\\s+hidden/ => starts PowerShell with a hidden window",
        "*: /\\b(inject|injector|selfdestruct|self-destruct)\\b/ => suspicious word in the arguments",
        "mavinject.exe: /INJECTRUNNING/ => injects a DLL into a running program (Microsoft's App-V tool used as an injector)",
        "mavinject64.exe: /INJECTRUNNING/ => injects a DLL into a running program (Microsoft's App-V tool used as an injector)",
        "wmic.exe: /process\\s+call\\s+create/ => starts a program through WMI (keeps it out of Explorer's history)",
    ];

    public static ArgumentRules Default() => Parse(string.Join("\n", DefaultText));

    /// <summary>
    /// A rules file holds the execution rules ([cheats], [tools], [commands]) and the program-argument rules
    /// ([arguments]). This takes the [arguments] section out; its lines are blanked rather than removed so the
    /// line numbers in <see cref="KeywordLists"/> error messages still match the file. A file with no sections
    /// whose every line is an argument rule (an old Log Parser rules file) is all [arguments].
    /// </summary>
    public static (string Keywords, string? Arguments) SplitRulesFile(string text)
    {
        var lines = text.Replace("\r", "").Split('\n');
        var entries = lines.Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        if (entries.Count > 0 && !entries.Any(IsSection) && entries.All(l => l.Contains("=>") && ParseLine(l, out _, out _)))
            return ("", string.Join(Environment.NewLine, lines).Trim());

        var arguments = new List<string>();
        bool inArguments = false, found = false;
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (IsSection(line))
            {
                inArguments = line[1..^1].Trim().Equals("arguments", StringComparison.OrdinalIgnoreCase);
                found |= inArguments;
            }
            else if (inArguments) arguments.Add(lines[i]);
            if (inArguments) lines[i] = "";
        }
        return (string.Join('\n', lines), found ? string.Join(Environment.NewLine, arguments).Trim() : null);

        static bool IsSection(string line) => line.StartsWith('[') && line.EndsWith(']');
    }

    /// <summary>One rule per line: <c>program: pattern =&gt; why</c>; <c>#</c> lines are comments.</summary>
    public static ArgumentRules Parse(string text)
    {
        var (rules, errors) = TryParse(text);
        if (errors.Count > 0) throw new FormatException(string.Join(Environment.NewLine, errors));
        return rules!;
    }

    public static (ArgumentRules? Rules, List<string> Errors) TryParse(string text)
    {
        var rules = new List<ArgumentRule>();
        var errors = new List<string>();
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (ParseLine(line, out var rule, out var error)) rules.Add(rule!);
            else errors.Add($"Line {i + 1}: {error}");
        }
        return errors.Count > 0 ? (null, errors) : (new ArgumentRules(rules), errors);
    }

    public static bool ParseLine(string line, out ArgumentRule? rule, out string? error)
    {
        rule = null;
        int colon = line.IndexOf(':');
        if (colon <= 0)
        {
            error = "expected \"program: pattern => why\" (e.g. \"javaw.exe: -javaagent => loads an agent\").";
            return false;
        }
        var program = line[..colon].Trim();
        if (program != "*" && !System.Text.RegularExpressions.Regex.IsMatch(program, @"^[\w.\- ]+$"))
        {
            error = $"\"{program}\" is not a program name (use a file name like javaw.exe, or * for every program).";
            return false;
        }
        if (!KeywordLists.ParseCommand(line[(colon + 1)..].Trim(), out var command, out error)) return false;
        rule = new ArgumentRule(program, command!);
        return true;
    }

    public string ToText()
    {
        var sb = new StringBuilder();
        foreach (var r in Rules) sb.AppendLine(Line(r));
        return sb.ToString();
    }

    public static string Line(ArgumentRule r) => $"{r.Program}: {KeywordLists.CommandLine(r.Rule)}";

    /// <summary>Meanings of every rule that matches this program's command line.</summary>
    public List<string> Match(string program, string commandLine, bool includeWildcard = true)
    {
        var reasons = new List<string>();
        foreach (var r in Rules)
        {
            if (!r.AppliesTo(program) || (!includeWildcard && r.Program == "*")) continue;
            try
            {
                if (r.Rule.IsMatch(commandLine) && !reasons.Contains(r.Rule.Meaning)) reasons.Add(r.Rule.Meaning);
            }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException) { }
        }
        return reasons;
    }
}
