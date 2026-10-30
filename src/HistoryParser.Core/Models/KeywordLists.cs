using System.Text;
using System.Text.RegularExpressions;

namespace HistoryParser.Core.Models;

/// <summary>A command pattern that gets flagged, with the reason shown to staff.</summary>
public sealed record CommandRule(string Pattern, string Meaning, Regex Regex)
{
    public bool IsMatch(string command) => Regex.IsMatch(command);

    /// <summary>
    /// Plain text matches anywhere in the command (case-insensitive). Text wrapped in slashes,
    /// like <c>/fsutil\s+usn/</c>, is a regular expression.
    /// </summary>
    public static CommandRule Create(string pattern, string meaning)
    {
        pattern = pattern.Trim();
        bool regex = pattern.Length > 2 && pattern[0] == '/' && pattern[^1] == '/';
        var body = regex ? pattern[1..^1] : Regex.Escape(pattern);
        return new CommandRule(pattern, meaning.Trim(),
            new Regex(body, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250)));
    }
}

/// <summary>
/// The command rules a scan flags - commands that erase or tamper with the execution records (clearing logs,
/// deleting the USN journal, stopping a recording service, changing the clock). History Parser judges by what a
/// command does to the records, never by program or cheat names. Staff can use the defaults, edit them on the start
/// screen, or load a rules file (same format as <see cref="ToText"/>).
/// </summary>
public sealed class KeywordLists
{
    public IReadOnlyList<CommandRule> Commands { get; }

    public KeywordLists(IEnumerable<CommandRule>? commands = null)
    {
        Commands = (commands ?? DefaultCommands()).ToArray();
    }

    static readonly (string Pattern, string Meaning)[] DefaultCommandText =
    [
        (@"/fsutil(\.exe)?\s+usn\s+deletejournal/", "deletes the USN journal"),
        (@"/wevtutil(\.exe)?\s+(cl|clear-log)\b/", "clears an event log"),
        (@"/Clear-EventLog|Remove-EventLog/", "clears an event log"),
        (@"/\bprefetch\b/", "touches the Prefetch folder"),
        (@"/\bSet-Date\b|^\s*(date|time)\s+\d|\bSetSystemTime\b|\btimedate\.cpl\b/", "changes the system clock"),
        (@"/Services\\bam|\\bam\\State/", "touches BAM records"),
        (@"/\b(sc(\.exe)?|net)\s+(stop|config)\s+(sysmain|dps|pcasvc|eventlog|diagtrack|bam)\b/", "stops or reconfigures a forensic service"),
        (@"/(Stop|Set)-Service\b.*\b(sysmain|dps|pcasvc|eventlog|diagtrack)\b/", "stops or reconfigures a forensic service"),
        (@"/vssadmin(\.exe)?\s+delete|cipher(\.exe)?\s+\/w|\bsdelete\b/", "wipes data"),
        (@"/reg(\.exe)?\s+delete\b.*(userassist|bam|appcompat|muicache|shimcache)/", "deletes execution records from the registry"),
        (@"/\bEnablePrefetcher\b/", "changes the Prefetch setting"),
        (@"/\$Recycle\.Bin|\\appcompat\\pca/", "touches evidence folders"),
        (@"/Clear-History|Remove-Item.*ConsoleHost_history|Set-PSReadLineOption.*HistorySaveStyle/", "erases shell history"),
    ];

    public static IEnumerable<CommandRule> DefaultCommands() =>
        DefaultCommandText.Select(c => CommandRule.Create(c.Pattern, c.Meaning));

    public static KeywordLists Default() => new(DefaultCommands());

    /// <summary>The reason a command is flagged, or null.</summary>
    public string? Classify(string command) => ClassifyAt(command)?.Meaning;

    /// <summary>The reason a command is flagged and where in it the rule matched, or null.</summary>
    public (string Meaning, int Index, int Length)? ClassifyAt(string command)
    {
        foreach (var rule in Commands)
        {
            try
            {
                if (rule.Regex.Match(command) is { Success: true } m) return (rule.Meaning, m.Index, m.Length);
            }
            catch (RegexMatchTimeoutException) { }
        }
        return null;
    }

    /// <summary>
    /// At most <paramref name="max"/> characters of <paramref name="text"/> that include the part at
    /// <paramref name="index"/> - so a long script shows the line that was flagged, not just its start.
    /// </summary>
    public static string Around(string text, int index, int length, int max)
    {
        if (text.Length <= max) return text;
        int start = Math.Clamp(index - max / 3, 0, text.Length - max);
        if (length > max - (index - start)) start = Math.Clamp(index, 0, text.Length - max);
        int end = start + max;
        return (start > 0 ? "…" : "") + text[start..end] + (end < text.Length ? "…" : "");
    }

    // ---- text format ----------------------------------------------------------------------

    /// <summary>
    /// A <c>[commands]</c> section, one <c>pattern =&gt; why it is flagged</c> per line; lines starting with <c>#</c>
    /// are comments. Older files may also have <c>[cheats]</c> / <c>[tools]</c> sections (name lists) - History Parser
    /// no longer matches names, so those sections are ignored. A file without a <c>[commands]</c> section keeps the defaults.
    /// </summary>
    public static KeywordLists Parse(string text)
    {
        var (lists, errors) = TryParse(text);
        if (errors.Count > 0) throw new FormatException(string.Join(Environment.NewLine, errors));
        return lists!;
    }

    public static (KeywordLists? Lists, List<string> Errors) TryParse(string text)
    {
        List<CommandRule>? commands = null;
        var errors = new List<string>();
        string section = "commands";
        var lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim().ToLowerInvariant();
                if (section == "commands") commands ??= new List<CommandRule>();
                else if (section is not ("cheats" or "tools")) errors.Add($"Line {i + 1}: unknown section [{section}].");
                continue;
            }
            // [cheats] / [tools] from an older file are read and ignored - names are no longer matched.
            if (section == "commands")
            {
                if (ParseCommand(line, out var rule, out var error)) commands!.Add(rule!);
                else errors.Add($"Line {i + 1}: {error}");
            }
        }
        return errors.Count > 0 ? (null, errors) : (new KeywordLists(commands ?? DefaultCommands().ToList()), errors);
    }

    public static bool ParseCommand(string line, out CommandRule? rule, out string? error)
    {
        rule = null;
        error = null;
        int arrow = line.LastIndexOf("=>", StringComparison.Ordinal);
        string pattern = arrow >= 0 ? line[..arrow].Trim() : line.Trim();
        string meaning = arrow >= 0 ? line[(arrow + 2)..].Trim() : "";
        if (pattern.Length == 0)
        {
            error = "the pattern before \"=>\" is empty.";
            return false;
        }
        if (meaning.Length == 0) meaning = $"matches the custom rule \"{pattern}\"";
        try
        {
            rule = CommandRule.Create(pattern, meaning);
            return true;
        }
        catch (ArgumentException e)
        {
            error = $"\"{pattern}\" is not a valid regular expression ({e.Message}).";
            return false;
        }
    }

    /// <summary>The rules in the file format above, ready to save or edit.</summary>
    public string ToText()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# History Parser command rules");
        sb.AppendLine("# [commands]: pattern => why it is flagged. These catch commands that erase or tamper with the");
        sb.AppendLine("#   execution records. Plain text matches anywhere (case-insensitive); wrap a pattern in slashes");
        sb.AppendLine("#   for a regular expression, e.g. /fsutil\\s+usn/ => deletes the USN journal");
        sb.AppendLine();
        sb.AppendLine("[commands]");
        foreach (var c in Commands) sb.AppendLine(CommandLine(c));
        return sb.ToString();
    }

    public static string CommandLine(CommandRule c) => $"{c.Pattern} => {c.Meaning}";

    public static KeywordLists LoadOrDefault(string path)
    {
        try
        {
            return File.Exists(path) ? Parse(File.ReadAllText(path)) : Default();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException) { return Default(); }
    }
}
