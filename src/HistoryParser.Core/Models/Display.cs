namespace HistoryParser.Core.Models;

/// <summary>User-facing wording, shared by the app and every export so they always match.</summary>
public static class Display
{
    public static string Category(FindingCategory c) => c switch
    {
        FindingCategory.Integrity => "Integrity",
        FindingCategory.ClockTampering => "Clock tampering",
        FindingCategory.TimelineInconsistency => "Date mismatch",
        FindingCategory.Deletion => "Deletion",
        FindingCategory.AntiForensics => "Anti-forensics",
        FindingCategory.Driver => "Driver",
        FindingCategory.LogTampering => "Log tampering",
        FindingCategory.ServiceTampering => "Service tampering",
        FindingCategory.Usb => "USB",
        FindingCategory.Arguments => "Arguments",
        FindingCategory.Process => "Process",
        FindingCategory.Defender => "Defender",
        FindingCategory.Persistence => "Scheduled task / install",
        FindingCategory.Boot => "Boot & kernel",
        FindingCategory.Hardware => "Hardware",
        FindingCategory.Injection => "Injection",
        _ => c.ToString(),
    };

    public static string Status(FileStatus s) => s switch
    {
        FileStatus.Exists => "Present",
        FileStatus.Deleted => "Deleted",
        FileStatus.InRecycleBin => "Recycle Bin",
        FileStatus.Renamed => "Renamed",
        FileStatus.Missing => "Missing",
        FileStatus.DriveNotConnected => "Drive absent",
        _ => "Unknown",
    };

    public static string Signature(SignatureStatus s) => s switch
    {
        SignatureStatus.Signed => "Signed",
        SignatureStatus.Unsigned => "Unsigned",
        SignatureStatus.Invalid => "Changed after signing",
        SignatureStatus.Untrusted => "Signed, not trusted",
        SignatureStatus.WindowsFile => "Windows",
        _ => "—",
    };

    public static string Source(EvidenceSource s) => s switch
    {
        EvidenceSource.Prefetch => "Prefetch",
        EvidenceSource.Bam => "BAM",
        EvidenceSource.Dam => "DAM",
        EvidenceSource.Pca => "PCA",
        EvidenceSource.UserAssist => "UserAssist",
        EvidenceSource.ShimCache => "ShimCache",
        EvidenceSource.MuiCache => "MuiCache",
        EvidenceSource.JavaUsage => "Java",
        EvidenceSource.RecycleBin => "Recycle Bin",
        EvidenceSource.UsnJournal => "USN",
        EvidenceSource.EventLog => "Event log",
        EvidenceSource.ProcessMemory => "Memory",
        EvidenceSource.ShellHistory => "History",
        EvidenceSource.Amcache => "Amcache",
        EvidenceSource.RecentShortcut => "Recent shortcut",
        EvidenceSource.FeatureUsage => "Taskbar usage",
        EvidenceSource.CompatAssistant => "Compatibility",
        EvidenceSource.CrashReport => "Crash report",
        EvidenceSource.Defender => "Defender",
        EvidenceSource.CapabilityAccess => "Privacy access",
        EvidenceSource.JumpList => "Jump list",
        _ => s.ToString(),
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
