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
    static readonly string[] Apps = ["HistoryParser", "historyparser-cli", "ProgramChecker", "ClientParser", "MalwareChecker", "CheatStringFinder", "MinecraftScanner", "LogParser"];
    static readonly string[] Names = Apps.Select(a => a + ".exe").ToArray();
    static readonly string[] Products = ["History Parser", "Program Checker", "Client Parser", "Malware Checker", "Cheat String Finder", "Minecraft Scanner", "Log Parser"];
    /// <summary>The suite's separate parser programs: not verified by hash here, but they unpack the same runtime.</summary>
    static readonly string[] Parsers = ["Correlator", "DataFileParser", "EventLogParser", "LiveParser", "NtfsParser", "RegistryParser", "TotalParser", "RatChecker"];
    /// <summary>
    /// Where .NET single-file apps unpack their runtime: %TEMP%\.net\&lt;program name&gt;\&lt;build id&gt;\. The folder is named after
    /// the file as it was run, so a second download ("HistoryParser (3).exe") gets "HistoryParser (3)". Only Microsoft-signed
    /// libraries that are still there count, so the name of the folder decides nothing by itself.
    /// </summary>
    static readonly System.Text.RegularExpressions.Regex RuntimeFolder = new(
        @"\\\.net\\(?:" + string.Join("|", Apps.Concat(Parsers).Select(System.Text.RegularExpressions.Regex.Escape)) + @")(?: \(\d+\))?\\",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>The suite's programs in plain words, for notes.</summary>
    const string SuiteText = "this screenshare suite (History Parser, Program Checker, Client Parser, Malware Checker, Cheat String Finder or Minecraft Scanner)";

    /// <summary>Yes = verified copy of this program; Unverified = claims to be it (version text only); NameOnly = gone, name only.</summary>
    public enum Match { No, Yes, Unverified, NameOnly }

    public static Match Classify(string? path)
    {
        if (string.IsNullOrEmpty(path)) return Match.No;
        string name = Path.GetFileName(path);
        // Browsers save a second download as "HistoryParser (1).exe"; the version info below still has to agree.
        bool ourName = Names.Contains(System.Text.RegularExpressions.Regex.Replace(name, @" \(\d+\)(?=\.exe$)", ""), StringComparer.OrdinalIgnoreCase);
        bool runtimeFolder = InRuntimeFolder(path);
        if (!ourName && !runtimeFolder) return Match.No;
        if (!File.Exists(path)) return ourName ? Match.NameOnly : Match.No;
        if (!ourName)
        {
            // The runtime .NET unpacks for us is Microsoft's own libraries, validly signed, with a chain that ends in Microsoft's
            // root. Only libraries: nothing we unpack is a program, so a Microsoft-signed program copied into a folder named like
            // ours (a Java runtime, PowerShell) is the player's, and what it ran stays in the records.
            return path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && SignatureTrust.Of(path).IsMicrosoft ? Match.Yes : Match.No;
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
        if (OwnHash is { } own) set.Add(own);
        return set;
    });

    /// <summary>
    /// SHA-256 of the file this program was started from, in lower case as a release's SHA256SUMS.txt writes it; null when the
    /// file cannot be read. Shown so the reader can tell which build is on screen. It is the program's word about itself: a
    /// changed build can show any hash, so the check that counts is Windows hashing the file (certutil -hashfile).
    /// </summary>
    public static string? OwnHash => Own.Value;
    static readonly Lazy<string?> Own = new(() => Environment.ProcessPath is { } self ? Sha256(self)?.ToLowerInvariant() : null);

    /// <summary>
    /// True when the program's code is inside the file it was started from, as in a published build. A developer build keeps
    /// its code in libraries beside the launcher, so the launcher's hash says nothing about what runs.
    /// </summary>
    public static bool OneFile => !File.Exists(Path.Combine(AppContext.BaseDirectory, typeof(SelfTraces).Assembly.GetName().Name + ".dll"));

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
    /// <param name="loadedByVerifiedCopy">
    /// Runtime files a hash-verified copy of this suite loaded, as Windows recorded in that copy's Prefetch file. Such a file is
    /// ours even after it is deleted: the proof is Windows' record of what our program opened, not the name of the folder.
    /// </param>
    public static void Mark(IEnumerable<FileRecord> files, List<Finding> findings, IEnumerable<string>? loadedByVerifiedCopy = null)
    {
        var ours = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var loaded = new HashSet<string>(loadedByVerifiedCopy ?? [], StringComparer.OrdinalIgnoreCase);
        foreach (var r in files)
        {
            switch (Classify(r.Path))
            {
                case Match.No when InRuntimeFolder(r.Path) && !File.Exists(r.Path) && loaded.Contains(r.Path) &&
                                   r.Path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase):
                    r.IsThisTool = true;
                    r.StatusDetail = $"{Label} (a runtime library a verified copy of {SuiteText} unpacked and loaded, by its own Prefetch record; since deleted). {r.StatusDetail}".Trim();
                    ours.Add(r.Path);
                    break;
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
                // Earlier runs leave their unpacked runtime behind, and it is later deleted. Gone, nothing can say whose it was, so it stays as it is.
                case Match.No when InRuntimeFolder(r.Path) && !File.Exists(r.Path):
                    Note(r, $"In a folder named like the one {SuiteText} unpacks its runtime to, likely from an earlier run. " +
                            "The file is gone, so that cannot be confirmed, and anything can be put in a folder of that name.");
                    break;
            }
        }
        // Windows writes a Prefetch file for each run of this program. One is ours only when Prefetch itself ties it to a verified copy:
        // a .pf named like ours proves nothing.
        var ownPrefetch = files.Where(f => f.IsThisTool).SelectMany(f => f.Evidence)
            .Where(e => e.Source == EvidenceSource.Prefetch && e.Origin is { Length: > 0 }).Select(e => e.Origin!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var r in files.Where(f => !f.IsThisTool && IsPrefetchFile(f.Path) && ownPrefetch.Contains(Path.GetFileName(f.Path))))
        {
            r.IsThisTool = true;
            r.StatusDetail = $"{Label} (the Prefetch file Windows keeps for a verified copy of {SuiteText}). {r.StatusDetail}".Trim();
            ours.Add(r.Path);
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

    internal static bool InRuntimeFolder(string path) => RuntimeFolder.IsMatch(path);

    static bool IsPrefetchFile(string path) =>
        path.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) && Path.GetDirectoryName(path) is { } folder && folder.EndsWith(@"\Windows\Prefetch", StringComparison.OrdinalIgnoreCase);

    /// <summary>Adds a sentence to what the file's row says, after whatever it says already.</summary>
    internal static void Note(FileRecord r, string text)
    {
        string said = (r.StatusDetail ?? "").Trim();
        r.StatusDetail = said.Length == 0 ? text : said + (said[^1] is '.' or '!' or '?' or ':' ? " " : ". ") + text;
    }

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
