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
        HowText = r.WasExecutedDirectly ? "Executed" : r.WasLoaded ? "Loaded" : "Seen";

        Severity = r.MaxSeverity;
        SeverityRank = Severity is { } s ? (int)s + 1 : 0;
        Ran = r.WasExecutedDirectly || r.WasLoaded;
        SourceCount = r.Sources.Count;
    }

    public FileRecord Record { get; }
    public string Name => Record.Name;
    public string Path => Record.Path;
    public FileType Type => Record.Type;
    public string TypeText => Display.Type(Record.Type);
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
    public string StatusDetail => Record.StatusDetail;
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
    public bool IsWindows => Record.IsWindowsFile;
    public bool IsThisTool => Record.IsThisTool;
    public bool IsGone => Record.Status is FileStatus.Deleted or FileStatus.InRecycleBin or FileStatus.Renamed
        or FileStatus.Missing or FileStatus.DriveNotConnected;
    public IReadOnlyList<Finding> Findings => Record.Findings;
    public IReadOnlyList<EvidenceRow> Evidence { get; }
    public string SearchText { get; }
}

public sealed class EvidenceRow
{
    public EvidenceRow(Evidence e, bool computeWindows = true)
    {
        Item = e;
        IsWindows = computeWindows && FileTypes.IsWindowsFile(e.Path);
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
    public string SearchText { get; }
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
