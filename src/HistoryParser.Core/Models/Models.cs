namespace HistoryParser.Core.Models;

/// <summary>Where a piece of evidence came from.</summary>
public enum EvidenceSource
{
    Prefetch,
    Bam,
    Dam,
    Pca,
    UserAssist,
    ShimCache,
    MuiCache,
    JavaUsage,
    RecycleBin,
    UsnJournal,
    EventLog,
    ProcessMemory,
    ShellHistory,
    Amcache,
    RecentShortcut,
    FeatureUsage,
    CompatAssistant,
    CrashReport,
    Defender,
    CapabilityAccess,
    JumpList,
}

/// <summary>What the evidence says happened to the file.</summary>
public enum EvidenceKind
{
    /// <summary>The file itself was started as a process.</summary>
    Execution,
    /// <summary>The file was loaded by another process (DLLs, jars run through javaw, ...).</summary>
    LoadedModule,
    /// <summary>The file is referenced, but the source carries no run time.</summary>
    Presence,
    Created,
    Deleted,
    Renamed,
    Modified,
    TimestampChanged,
    Recycled,
    /// <summary>A hard link (second name for the same file) was added or removed under this name.</summary>
    HardLinked,
}

public enum FileType { Exe, Dll, Jar, Script, Other }

public enum FileStatus { Exists, Deleted, InRecycleBin, Renamed, Missing, DriveNotConnected, Unknown }

/// <summary>Invalid = the contents changed after signing (the only failure that proves tampering); Untrusted = signed, but the certificate is expired, unknown, revoked or distrusted.</summary>
public enum SignatureStatus { NotChecked, Signed, Unsigned, Invalid, WindowsFile, NotApplicable, Untrusted }

public enum Severity { Info, Low, Medium, High }

public enum FindingCategory
{
    Integrity,
    ClockTampering,
    TimelineInconsistency,
    Deletion,
    AntiForensics,
    Driver,
    LogTampering,
    ServiceTampering,
    Usb,
    Arguments,
    Process,
    Defender,
    Persistence,
    Boot,
    Hardware,
    Injection,
}

public enum CheckState { Ok, Warning, Bad, Unknown }

public sealed record Evidence
{
    public required EvidenceSource Source { get; init; }
    public required EvidenceKind Kind { get; init; }
    /// <summary>Normalized full path (drive-letter form) when known. Pseudo entries start with '['.</summary>
    public required string Path { get; init; }
    public DateTime? TimeUtc { get; init; }
    public string Detail { get; init; } = "";
    /// <summary>Which record/process/user produced this (prefetch file name, SID, process name ...).</summary>
    public string? Origin { get; init; }
    public int? RunCount { get; init; }
    /// <summary>File last-modified time as recorded by the source (ShimCache).</summary>
    public DateTime? FileModifiedUtc { get; init; }
    /// <summary>What the file really is when its content says otherwise than its name (a jar renamed to .png).</summary>
    public FileType? ActualType { get; init; }
    /// <summary>Other side of a rename.</summary>
    public string? RelatedPath { get; init; }
}

public sealed record Finding
{
    public required Severity Severity { get; init; }
    public required FindingCategory Category { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public string? Path { get; init; }
    public DateTime? TimeUtc { get; init; }
    /// <summary>Left by this screenshare suite itself, not by the player (see SelfTraces).</summary>
    public bool ByThisTool { get; init; }
}

public sealed record IntegrityCheck(string Area, string Name, CheckState State, string Detail);

public sealed record SourceStatus(string Name, bool Success, int Items, string Message, TimeSpan Duration);

/// <summary>A detected change of the system clock (from an event, or inferred from out-of-order records).</summary>
public sealed record ClockChange
{
    public required string Source { get; init; }
    public required DateTime OldTimeUtc { get; init; }
    public required DateTime NewTimeUtc { get; init; }
    public string Detail { get; init; } = "";
    /// <summary>How suspicious this change is on its own (a time-service correction is not a user moving the clock).</summary>
    public Severity Severity { get; init; } = Severity.Medium;
    public TimeSpan Delta => NewTimeUtc - OldTimeUtc;
    public bool IsRollback => NewTimeUtc < OldTimeUtc;
}

public sealed record MemoryHit
{
    public required string Process { get; init; }
    public required int Pid { get; init; }
    public required string Path { get; init; }
    /// <summary>Timestamp text embedded in the string (DPS format), exactly as recorded.</summary>
    public string? RecordedTime { get; init; }
    public string Raw { get; init; } = "";
}

/// <summary>One command typed or run by a user (shell history, Run box, terminal buffers, event logs ...).</summary>
public sealed record CommandEntry
{
    /// <summary>Grouping for filters: PowerShell, CMD / Terminal, Run box, Explorer, Bash, Event log, Running.</summary>
    public required string Group { get; init; }
    /// <summary>Where exactly it came from (file, key, log).</summary>
    public required string Source { get; init; }
    public required string Command { get; init; }
    public string User { get; init; } = "";
    /// <summary>Exact time when the source records one; most histories only keep order.</summary>
    public DateTime? TimeUtc { get; init; }
    /// <summary>Position within its source, newest = highest, so order is kept when there is no time.</summary>
    public int Order { get; init; }
    public string Detail { get; init; } = "";
    /// <summary>Why the command is suspicious (anti-forensics), or null.</summary>
    public string? Suspicion { get; init; }
}

public sealed record MachineInfo
{
    public string ComputerName { get; init; } = "";
    public string UserName { get; init; } = "";
    public string OsVersion { get; init; } = "";
    public DateTime BootTimeUtc { get; init; }
    public DateTime? OsInstallUtc { get; init; }
    public string TimeZone { get; init; } = "";
    public bool IsElevated { get; init; }
    public string ToolVersion { get; init; } = "";
}

public sealed class FileRecord
{
    public required string Path { get; set; }
    public required string Name { get; set; }
    public FileType Type { get; set; }
    public bool IsWindowsFile { get; set; }
    [System.Text.Json.Serialization.JsonObjectCreationHandling(System.Text.Json.Serialization.JsonObjectCreationHandling.Populate)]
    public List<Evidence> Evidence { get; } = new();
    [System.Text.Json.Serialization.JsonObjectCreationHandling(System.Text.Json.Serialization.JsonObjectCreationHandling.Populate)]
    public List<Finding> Findings { get; } = new();

    /// <summary>Latest time the file was started or loaded.</summary>
    public DateTime? LastExecutionUtc { get; set; }
    /// <summary>Latest timestamp of any kind.</summary>
    public DateTime? LastActivityUtc { get; set; }
    public int? RunCount { get; set; }
    public bool WasExecutedDirectly { get; set; }
    public bool WasLoaded { get; set; }
    /// <summary>Where the file was downloaded from (its Zone.Identifier stream), when known.</summary>
    public string? DownloadedFrom { get; set; }
    /// <summary>A trace this screenshare suite left itself (verified by exact hash or Microsoft signature; see SelfTraces).</summary>
    public bool IsThisTool { get; set; }

    public FileStatus Status { get; set; } = FileStatus.Unknown;
    public string StatusDetail { get; set; } = "";
    public DateTime? DeletedUtc { get; set; }

    public long? Size { get; set; }
    public string? Sha256 { get; set; }
    public SignatureStatus Signature { get; set; } = SignatureStatus.NotChecked;
    public string? Signer { get; set; }
    /// <summary>Both NTFS timestamp sets (administrator scans only).</summary>
    public Parsers.NtfsTimes? Ntfs { get; set; }
    /// <summary>Version-resource fields built into the program: who it claims to be.</summary>
    public string? Company { get; set; }
    public string? OriginalName { get; set; }
    public string? Description { get; set; }

    public IReadOnlyCollection<EvidenceSource> Sources => Evidence.Select(e => e.Source).Distinct().OrderBy(s => s).ToArray();
    /// <summary>Strongest finding; Info (this program's own traces) does not make a file "flagged".</summary>
    public Severity? MaxSeverity => Findings.Where(f => f.Severity > Severity.Info).Select(f => (Severity?)f.Severity).Max();
}

/// <summary>
/// A folder Explorer recorded as opened (ShellBags) — kept even after the folder is deleted. Also archives browsed
/// like folders (a .zip / modpack) and folders inside them.
/// </summary>
public sealed record FolderVisit
{
    /// <summary>Full path; starts with "…\" when Explorer only kept the last part of it.</summary>
    public required string Path { get; init; }
    public required string User { get; init; }
    /// <summary>When it was opened, if it is the most recently opened folder inside its parent (only that one is dated).</summary>
    public DateTime? OpenedUtc { get; init; }
    /// <summary>When Explorer last updated its record of this folder: it, or a folder inside it, was being opened then.</summary>
    public DateTime? RecordUpdatedUtc { get; init; }
    /// <summary>The folder's own modified time when Explorer recorded it.</summary>
    public DateTime? FolderModifiedUtc { get; init; }
    /// <summary>"Folder", "Archive" (a .zip / modpack opened like a folder) or "Inside archive".</summary>
    public string What { get; init; } = "Folder";
    /// <summary>Whether it is still there; null when that cannot be checked (inside an archive, partial path, drive not present).</summary>
    public bool? Exists { get; init; }
    /// <summary>Where in the registry it was read.</summary>
    public string Source { get; init; } = "";

    public DateTime? LastActivityUtc => OpenedUtc > RecordUpdatedUtc || RecordUpdatedUtc == null ? OpenedUtc : RecordUpdatedUtc;
    public string State => Exists switch { true => "Exists", false => "Gone", null => "Unknown" };
}

public sealed class ScanResult
{
    public required MachineInfo Machine { get; init; }
    public required DateTime StartedUtc { get; init; }
    public required DateTime FinishedUtc { get; init; }
    public required List<FileRecord> Files { get; init; }
    public required List<Finding> Findings { get; init; }
    public required List<IntegrityCheck> Checks { get; init; }
    public required List<SourceStatus> Sources { get; init; }
    public required List<ClockChange> ClockChanges { get; init; }
    public required List<MemoryHit> MemoryHits { get; init; }
    public List<CommandEntry> Commands { get; init; } = new();
    /// <summary>Starts, stops, start-type changes and kills of evidence-recording services.</summary>
    public List<Bypass.ServiceEvent> ServiceEvents { get; init; } = new();
    /// <summary>Folders (and archives) opened in Explorer, from the ShellBags; most recent first.</summary>
    public List<FolderVisit> Folders { get; init; } = new();
    /// <summary>True for a copy made with "Hide private details" (names masked, personal history removed).</summary>
    public bool PrivateDetailsHidden { get; init; }
    /// <summary>The time range chosen before the scan; only things from <see cref="SinceUtc"/> on are kept.</summary>
    public TimeWindow Window { get; init; } = TimeWindow.All;
    public DateTime? SinceUtc { get; init; }
    /// <summary>Every evidence item, newest first.</summary>
    public required List<Evidence> Timeline { get; init; }
}

public sealed class ScanOptions
{
    public bool ScanProcessMemory { get; set; } = true;
    public bool ReadUsnJournal { get; set; } = true;
    /// <summary>Walk the whole System event log to look for out-of-order timestamps (slower).</summary>
    public bool CheckEventLogOrdering { get; set; } = true;
    public bool InspectFiles { get; set; } = true;
    /// <summary>Also record USN changes to forensic artifact files (logs, shortcuts, histories). Used by the tampering checks.</summary>
    public bool IncludeArtifactFiles { get; set; }
    /// <summary>Tampering checks: read Minecraft and launcher logs for launch arguments (the slowest audit).</summary>
    public bool ReadGameLogs { get; set; } = true;
    /// <summary>How far apart two timestamps for the same event may be before they count as disagreeing.</summary>
    public TimeSpan Tolerance { get; set; } = TimeSpan.FromMinutes(2);
    public KeywordLists Keywords { get; set; } = KeywordLists.Default();
    /// <summary>Which period to show. Everything is still read and cross-checked; older items are dropped afterwards.</summary>
    public TimeWindow Window { get; set; } = TimeWindow.All;
    /// <summary>False keeps the full history in the result (Log Parser trims after its own audits).</summary>
    public bool TrimToWindow { get; set; } = true;
}

public sealed record ScanProgress(string Message, int Completed, int Total);

/// <summary>How far back a scan's results go.</summary>
public enum TimeWindow { ThisBoot, Day, ThreeDays, Week, Month, All }

public static class TimeWindows
{
    /// <summary>Start of the window, or null for everything.</summary>
    public static DateTime? Since(TimeWindow w, DateTime nowUtc, DateTime bootUtc) => w switch
    {
        TimeWindow.ThisBoot => bootUtc,
        TimeWindow.Day => nowUtc.AddDays(-1),
        TimeWindow.ThreeDays => nowUtc.AddDays(-3),
        TimeWindow.Week => nowUtc.AddDays(-7),
        TimeWindow.Month => nowUtc.AddDays(-30),
        _ => null,
    };

    public static string Label(TimeWindow w) => w switch
    {
        TimeWindow.ThisBoot => "since the last boot",
        TimeWindow.Day => "last 24 hours",
        TimeWindow.ThreeDays => "last 3 days",
        TimeWindow.Week => "last 7 days",
        TimeWindow.Month => "last 30 days",
        _ => "everything",
    };

    /// <summary>Command-line spelling: boot, 24h, 3d, 7d, 30d, all.</summary>
    public static TimeWindow? Parse(string s) => s.ToLowerInvariant() switch
    {
        "boot" => TimeWindow.ThisBoot, "24h" or "1d" => TimeWindow.Day, "3d" => TimeWindow.ThreeDays,
        "7d" or "1w" => TimeWindow.Week, "30d" => TimeWindow.Month, "all" => TimeWindow.All, _ => null,
    };

    /// <summary>
    /// Undated findings describe the PC's state now (a service disabled, a log turned off) and always stay;
    /// dated ones stay when they fall in the window; ones about a file stay when that file is kept.
    /// </summary>
    public static bool Keep(Finding f, DateTime since, ISet<string>? keptFiles = null) =>
        f.TimeUtc is { } t ? t >= since : f.Path == null || keptFiles == null || keptFiles.Contains(f.Path);
}
