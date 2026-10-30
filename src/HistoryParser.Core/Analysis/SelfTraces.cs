using System.Diagnostics;
using HistoryParser.Core.Models;

namespace HistoryParser.Core.Analysis;

/// <summary>
/// Traces this screenshare suite leaves itself: the runs of History Parser, Program Checker, Client Parser,
/// Malware Checker and Cheat String Finder (Prefetch, BAM, Amcache …), the .NET runtime files a single-file
/// app unpacks to %TEMP%\.net, the one-line launcher in PowerShell history and logs, and memory-read handles
/// on the game. These must never count against the player, so they are labelled "by this program", dropped
/// to Info and hidden unless asked for.
///
/// Names and version text can be copied by anything, so a file only counts as ours when it is byte-for-byte
/// the program running now or one of its sibling tools in the same folder, and unpacked runtime files only
/// when Microsoft validly signed them. Anything that merely looks like us keeps its normal severity and gets
/// a note instead - so a cheat renamed to ProgramChecker.exe, or run from a folder named like ours, still shows.
/// </summary>
public static class SelfTraces
{
    public const string Label = "By this program";
    const string Repo = "zidankqkq/history-parser";

    /// <summary>The suite's programs. LogParser.exe is an older release, now part of History Parser.</summary>
    static readonly string[] Apps = ["HistoryParser", "historyparser-cli", "ProgramChecker", "ClientParser", "MalwareChecker", "CheatStringFinder", "LogParser"];
    static readonly string[] Names = Apps.Select(a => a + ".exe").ToArray();
    static readonly string[] Products = ["History Parser", "Program Checker", "Client Parser", "Malware Checker", "Cheat String Finder", "Log Parser"];
    /// <summary>Where .NET single-file apps unpack their runtime (only Microsoft-signed files there count).</summary>
    static readonly string[] RuntimeFolders = Apps.Select(a => $@"\.net\{a}\").ToArray();

    /// <summary>The suite's programs in plain words, for notes.</summary>
    const string SuiteText = "this screenshare suite (History Parser, Program Checker, Client Parser, Malware Checker or Cheat String Finder)";

    /// <summary>Yes = verified copy of this program; Unverified = claims to be it (version text only); NameOnly = gone, name only.</summary>
    public enum Match { No, Yes, Unverified, NameOnly }

    public static Match Classify(string? path)
    {
        if (string.IsNullOrEmpty(path)) return Match.No;
        string name = Path.GetFileName(path);
        // Browsers save a second download as "HistoryParser (1).exe"; the version info below still has to agree.
        bool ourName = Names.Contains(System.Text.RegularExpressions.Regex.Replace(name, @" \(\d+\)(?=\.exe$)", ""), StringComparer.OrdinalIgnoreCase);
        bool runtimeFolder = RuntimeFolders.Any(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));
        if (!ourName && !runtimeFolder) return Match.No;
        if (!File.Exists(path)) return ourName ? Match.NameOnly : Match.No;
        if (!ourName)
        {
            // The runtime .NET unpacks for us is Microsoft's own, validly signed. Version text can be forged; a signature cannot.
            return FileInspector.Verify(path) == SignatureStatus.Signed &&
                   (FileInspector.SignerName(path) ?? "").Contains("Microsoft", StringComparison.OrdinalIgnoreCase)
                ? Match.Yes : Match.No;
        }
        // Our own copy is byte-for-byte the program running now or one of the suite's programs from the same
        // release. Anything that only claims to be one of them in its version info stays visible as "unverified".
        if (TrustedHashes.Value.Contains(Sha256(path) ?? "")) return Match.Yes;
        try { return Products.Contains(FileVersionInfo.GetVersionInfo(path).ProductName) ? Match.Unverified : Match.No; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return Match.No; }
    }

    /// <summary>
    /// SHA-256 of the running program, and of the suite's other programs from the same release: publish.ps1 builds
    /// them first and writes their hashes into this assembly. Files are never trusted for sitting next to us - the
    /// player chooses that folder, and could have put a cheat named ClientParser.exe there beforehand.
    /// </summary>
    static readonly Lazy<HashSet<string>> TrustedHashes = new(() =>
    {
        var set = new HashSet<string>(SuiteHashes(), StringComparer.OrdinalIgnoreCase);
        if (Environment.ProcessPath is { } self && Sha256(self) is { } own) set.Add(own);
        return set;
    });

    /// <summary>The hashes built in by publish.ps1 (none in a developer build).</summary>
    internal static IEnumerable<string> SuiteHashes() =>
        (typeof(SelfTraces).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyMetadataAttribute), false)
            .Cast<System.Reflection.AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == "SuiteHashes")?.Value ?? "")
        .Split('_', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Where(h => h.Length == 64 && h.All(Uri.IsHexDigit));

    static string? Sha256(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return fs.Length > 512L * 1024 * 1024 ? null : Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    static readonly System.Text.RegularExpressions.Regex OneLiner = new(
        @"^\s*(irm|Invoke-RestMethod)\s+(-Uri\s+)?['""]?https://github\.com/zidankqkq/history-parser/releases/(latest/download|download/v[\d.]+)/run(-logparser)?\.ps1['""]?\s*\|\s*(iex|Invoke-Expression)\s*;?\s*$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>Every line of the published launcher scripts, embedded at build time so they never drift.</summary>
    static readonly HashSet<string> LauncherLines = LoadLauncherLines();

    static HashSet<string> LoadLauncherLines()
    {
        var lines = new HashSet<string>(StringComparer.Ordinal);
        var asm = typeof(SelfTraces).Assembly;
        foreach (var name in new[] { "launcher.run.ps1", "launcher.run-logparser.ps1" })
        {
            using var s = asm.GetManifestResourceStream(name);
            if (s == null) continue;
            using var reader = new StreamReader(s);
            foreach (var line in reader.ReadToEnd().Split('\n')) lines.Add(line.Trim());
        }
        return lines;
    }

    /// <summary>
    /// The one-line launcher exactly, or a script made only of lines from the published launcher scripts.
    /// Merely mentioning the repository is not enough: anything added to the command keeps it the player's.
    /// </summary>
    public static bool IsOurCommand(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (OneLiner.IsMatch(text)) return true;
        if (!text.Contains(Repo, StringComparison.OrdinalIgnoreCase) || LauncherLines.Count == 0) return false;
        return text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).All(LauncherLines.Contains);
    }

    /// <summary>History Parser: tag files and their findings, and findings about our launcher command.</summary>
    public static void Mark(IEnumerable<FileRecord> files, List<Finding> findings)
    {
        var ours = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in files)
        {
            switch (Classify(r.Path))
            {
                case Match.Yes:
                    r.IsThisTool = true;
                    r.StatusDetail = $"{Label} ({SuiteText}, or the runtime it unpacks; the same file as the one next to the running program). {r.StatusDetail}".Trim();
                    ours.Add(r.Path);
                    break;
                // A name or version text can be copied by anything, so these keep their severity; the note explains.
                case Match.NameOnly:
                    Note(r, $"Named like {SuiteText}, but the file is gone, so that cannot be confirmed " +
                            "(screensharers often delete their copy — or something used the name to blend in).");
                    break;
                case Match.Unverified:
                    Note(r, $"Says it is part of {SuiteText}, but it is not the same file as the copy next to the running program — " +
                            "an older version, a copy kept in another folder, or something pretending to be it. Not treated as this program.");
                    break;
            }
        }
        for (int i = 0; i < findings.Count; i++)
            if (IsOurs(findings[i], ours)) findings[i] = Tag(findings[i]);
        foreach (var r in files.Where(f => f.IsThisTool))
            for (int i = 0; i < r.Findings.Count; i++) r.Findings[i] = Tag(r.Findings[i]);
    }

    /// <summary>The tampering checks: the same for their findings (handle holders, command lines, drivers …).</summary>
    public static List<Finding> Mark(IEnumerable<Finding> findings, IEnumerable<FileRecord> files)
    {
        var ours = files.Where(f => f.IsThisTool).Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return findings.Select(f => f.ByThisTool || IsOurs(f, ours) || (f.Path != null && Classify(f.Path) == Match.Yes) ? Tag(f) : f).ToList();
    }

    static void Note(FileRecord r, string text) => r.StatusDetail = (r.StatusDetail + " " + text).Trim();

    // Only a verified file or our exact launcher command makes a finding ours. A finding that merely mentions one
    // of our folders is not enough: anything can be put in (or deleted from) a folder named like ours.
    static bool IsOurs(Finding f, HashSet<string> ours) =>
        f.ByThisTool || (f.Path != null && ours.Contains(f.Path)) || IsOurCommand(f.Detail);

    static Finding Tag(Finding f) => f.ByThisTool ? f : f with
    {
        Severity = Severity.Info,
        ByThisTool = true,
        Detail = $"{Label}: this trace was left by {SuiteText} itself, not by the player. Original finding ({f.Severity}): {f.Detail}",
    };
}
