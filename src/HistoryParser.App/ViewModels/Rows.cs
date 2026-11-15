using HistoryParser.Core.Models;
using HistoryParser.Core.Util;

namespace HistoryParser.App.ViewModels;

public static class Labels
{
    public static string Source(EvidenceSource s) => Display.Source(s);

    public static string Kind(EvidenceKind k) => k switch
    {
        EvidenceKind.Execution => "Executed",
        EvidenceKind.LoadedModule => "Loaded",
        EvidenceKind.Presence => "Seen",
        EvidenceKind.Created => "Created",
        EvidenceKind.Deleted => "Deleted",
        EvidenceKind.Renamed => "Renamed",
        EvidenceKind.Modified => "Modified",
        EvidenceKind.TimestampChanged => "Times changed",
        EvidenceKind.Recycled => "Recycled",
        EvidenceKind.HardLinked => "Hard link",
        _ => k.ToString(),
    };

    public static string Type(FileType t) => t switch
    {
        FileType.Exe => "EXE",
        FileType.Dll => "DLL",
        FileType.Jar => "JAR",
        FileType.Script => "Script",
        _ => "Other",
    };
}

public sealed class FileRow
{
    public FileRow(FileRecord r)
    {
        Record = r;
        SourcesText = string.Join(" · ", r.Sources.Select(Labels.Source));
        SearchText = (r.Path + " " + SourcesText + " " + r.Sha256).ToLowerInvariant();
        Evidence = r.Evidence.Select(e => new EvidenceRow(e, false)).ToList();
        HowText = How(r);
        SearchText += " " + HowText.ToLowerInvariant();

        Severity = r.MaxSeverity;
        SeverityRank = Severity is { } s ? (int)s + 1 : 0;
        Ran = r.WasExecutedDirectly || r.WasLoaded;
        SourceCount = r.Sources.Count;
    }

    /// <summary>
    /// How the file came to be in the records, in the table's words. A file listed with a time did not necessarily run by
    /// itself: Windows also records every file a program opened as it started. So the table says which it was - "Ran" (started
    /// as a program), "Run by Java" (a jar Java opened), "Run by python.exe" (a script its interpreter opened), or
    /// "Opened by x.exe" for a jar some other program merely opened. Those last ones stay listed on purpose: a Java runtime
    /// under another name would look exactly like that.
    /// </summary>
    static string How(FileRecord r)
    {
        if (r.WasExecutedDirectly) return "Ran";
        // A driver the kernel lists has no start time on record: what is known is that it is loaded as the scan runs.
        if (r.Evidence.Any(e => e.Source == EvidenceSource.LoadedDriver)) return "Loaded now";
        if (!r.WasLoaded) return "Seen";
        var by = r.Evidence.Where(e => e.Kind == EvidenceKind.LoadedModule && !string.IsNullOrEmpty(e.Origin))
            .Select(e => e.Origin!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (by.Count == 0) return "Loaded";
        // Prefetch names programs in capitals (JAVAW.EXE); shown the way they are written everywhere else.
        static string Plain(string program) => program.EndsWith(".EXE", StringComparison.Ordinal) ? program.ToLowerInvariant() : program;
        bool java = by.Any(b => b.StartsWith("JAVA", StringComparison.OrdinalIgnoreCase));
        string first = Plain(by.FirstOrDefault(b => !b.StartsWith("JAVA", StringComparison.OrdinalIgnoreCase)) ?? by[0]);
        string more = by.Count > 1 ? $" +{by.Count - 1}" : "";
        return r.Type switch
        {
            FileType.Jar => java ? "Run by Java" : $"Opened by {first}{more}",
            FileType.Script => $"Run by {Plain(by[0])}{more}",
            _ => $"Loaded by {Plain(by[0])}{more}",
        };
    }

    public FileRecord Record { get; }
    public string Name => Record.Name;
    public string Path => Record.Path;
    /// <summary>The folder the file is in: the second line of its row.</summary>
    public string Folder => System.IO.Path.GetDirectoryName(Record.Path) ?? "";
    public FileType Type => Record.Type;
    /// <summary>A kernel driver (.sys): listed on its own page, not among the libraries programs load.</summary>
    public bool IsDriver => Record.Path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
    public string TypeText => IsDriver ? "Driver" : Display.Type(Record.Type);
    public DateTime? LastRun => Record.LastExecutionUtc;
    public DateTime? LastActivity => Record.LastActivityUtc;
    /// <summary>Sort keys: a file that never ran sorts as oldest, so newest-first puts it at the bottom.</summary>
    public DateTime LastRunKey => Record.LastExecutionUtc ?? DateTime.MinValue;
    public DateTime LastActivityKey => Record.LastActivityUtc ?? DateTime.MinValue;
    public int? RunCount => Record.RunCount;
    public string SourcesText { get; }
    public int SourceCount { get; }
    public string HowText { get; }
    public FileStatus Status => Record.Status;
    public string StatusDetail => Record.Routine is { } why ? $"{Record.StatusDetail} Routine: {why}".Trim() : Record.StatusDetail;
    public SignatureStatus Signature => Record.Signature;
    public string? Signer => Record.Signer;
    public string? Sha256 => Record.Sha256;
    public string SizeText => Record.Size is { } s ? $"{s:N0} bytes" : "—";
    /// <summary>What the file says it is: built-in name, company and description from its version info.</summary>
    public string? VersionText => string.Join(" · ", new[] { Record.OriginalName, Record.Company, Record.Description }
        .Where(s => !string.IsNullOrWhiteSpace(s))) is { Length: > 0 } v ? v : null;
    /// <summary>NTFS keeps two sets of dates; tools that fake dates usually only change the first (shown) set.</summary>
    public string? NtfsText => Record.Ntfs is { } n
        ? $"Created  {Local(n.SiCreated)}  (name record {Local(n.FnCreated)})\nModified {Local(n.SiModified)}  (name record {Local(n.FnModified)})"
        : null;
    static string Local(DateTime? t) => t is { } v ? v.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "—";
    public Severity? Severity { get; }
    /// <summary>Sort key: High=3 … none=0.</summary>
    public int SeverityRank { get; }
    /// <summary>Started as a process or loaded by one (not only seen in a cache or memory).</summary>
    public bool Ran { get; }
    /// <summary>
    /// Verified as routine (on disk, validly signed by Microsoft or a known publisher, built name) - or, in a report saved by
    /// an older version, inside the Windows folder.
    /// </summary>
    public bool IsRoutine => Record.Routine != null || Record.IsWindowsFile;
    /// <summary>Kept out of the way by default: routine, and nothing worth a look was found on it. A lead always stays in view.</summary>
    public bool Folded => IsRoutine && (Severity ?? Core.Models.Severity.Info) < Core.Models.Severity.Medium;
    public bool IsThisTool => Record.IsThisTool;
    /// <summary>A program or library with no signature, or one that does not verify (changed since signing, or not trusted).</summary>
    public bool IsUnsigned => Record.Signature is SignatureStatus.Unsigned or SignatureStatus.Invalid or SignatureStatus.Untrusted;

    /// <summary>The other places this same library is, folded under this row (see Core.Analysis.Repeats). Empty for most rows.</summary>
    public IReadOnlyList<FileRow> Copies { get; private set; } = [];
    public bool HasCopies => Copies.Count > 0;
    /// <summary>"×12": this row and its copies.</summary>
    public string CopiesText => HasCopies ? $"×{Copies.Count + 1}" : "";
    /// <summary>What makes the copies the same file as this one.</summary>
    public string CopiesWhy { get; private set; } = "";
    /// <summary>Folded under another row as a copy of it: out of view unless copies are shown or a search finds it.</summary>
    public bool IsCopy { get; private set; }

    internal void Fold(IReadOnlyList<FileRow> copies, string why)
    {
        Copies = copies;
        CopiesWhy = $"{why}: this row and {copies.Count} more.";
        foreach (var copy in copies) copy.IsCopy = true;
    }
    public bool IsGone => Record.Status is FileStatus.Deleted or FileStatus.InRecycleBin or FileStatus.Renamed
        or FileStatus.Missing or FileStatus.DriveNotConnected;
    public IReadOnlyList<Finding> Findings => Record.Findings;
    public IReadOnlyList<EvidenceRow> Evidence { get; }
    public string SearchText { get; }
}

public sealed class EvidenceRow
{
    /// <param name="folded">The record this belongs to is kept out of the way by default (see <see cref="FileRow.Folded"/>).</param>
    public EvidenceRow(Evidence e, bool folded = false)
    {
        Item = e;
        IsWindows = folded;
        SearchText = (e.Path + " " + e.Detail + " " + e.Origin + " " + Labels.Source(e.Source)).ToLowerInvariant();
    }

    public Evidence Item { get; }
    public DateTime? Time => Item.TimeUtc;
    public string SourceText => Labels.Source(Item.Source);
    public string KindText => Labels.Kind(Item.Kind);
    public string Path => Item.Path;
    public string Detail => Item.Detail;
    public string? Origin => Item.Origin;
    public bool IsWindows { get; }
    /// <summary>A record of one of this suite's own files (see <see cref="FileRow.IsThisTool"/>): what the scan itself left behind.</summary>
    public bool IsThisTool { get; init; }
    public string SearchText { get; }
    public string Name => System.IO.Path.GetFileName(Path) is { Length: > 0 } name && IsFile ? name : Path;
    bool IsFile => Path.Length > 3 && Path[1] == ':' && Path[2] == '\\';
    /// <summary>The folder the file is in; records that are not about a file on a drive (an event, a registry value) share one group.</summary>
    public string Folder => IsFile && System.IO.Path.GetDirectoryName(Path) is { Length: > 0 } folder ? folder : NotAFile;
    public const string NotAFile = "(not a file)";
}

/// <summary>One folder of the timeline: how many records it has of each kind, the newest, and the records themselves.</summary>
public sealed class FolderRow
{
    public FolderRow(string folder, List<EvidenceRow> rows)
    {
        Folder = folder;
        Rows = rows;
        Ran = rows.Count(r => r.Item.Kind is EvidenceKind.Execution or EvidenceKind.LoadedModule);
        Deleted = rows.Count(r => r.Item.Kind is EvidenceKind.Deleted or EvidenceKind.Recycled);
        Changed = rows.Count(r => r.Item.Kind is EvidenceKind.Created or EvidenceKind.Renamed or EvidenceKind.Modified or EvidenceKind.TimestampChanged or EvidenceKind.HardLinked);
        Files = rows.Select(r => r.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        Latest = rows.Max(r => r.Time);
    }

    public string Folder { get; }
    public IReadOnlyList<EvidenceRow> Rows { get; }
    public int Records => Rows.Count;
    public int Files { get; }
    public int Ran { get; }
    public int Deleted { get; }
    public int Changed { get; }
    public DateTime? Latest { get; }
}

public sealed class CommandRow
{
    public CommandRow(CommandEntry c)
    {
        Item = c;
        SearchText = (c.Command + " " + c.Source + " " + c.User + " " + c.Detail + " " + c.Suspicion).ToLowerInvariant();
    }

    public CommandEntry Item { get; }
    public string Group => Item.Group;
    public string Source => Item.Source;
    public string Command => Item.Command;
    public string User => Item.User;
    public DateTime? Time => Item.TimeUtc;
    public string Detail => Item.Detail;
    public string? Suspicion => Item.Suspicion;
    public bool IsSuspicious => Item.Suspicion != null;
    public string SearchText { get; }
}

/// <summary>One line of the Integrity page's service history; Ok is false for stops and changes worth a look.</summary>
public sealed record ServiceHistoryRow(DateTime? TimeUtc, string Service, string Change, bool Ok);
