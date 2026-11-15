using System.Collections.Concurrent;
using HistoryParser.Core.Models;
using HistoryParser.Core.Util;

namespace HistoryParser.Core.Collectors;

/// <summary>A source of evidence. Collectors only read; they never change the machine.</summary>
public interface ICollector
{
    string Name { get; }
    /// <returns>Number of evidence items produced.</returns>
    int Collect(ScanContext ctx, CancellationToken ct);
}

/// <summary>Shared, thread-safe sink that the collectors (which run in parallel) write into.</summary>
public sealed class ScanContext
{
    public ScanContext(ScanOptions options, PathNormalizer paths, DateTime nowUtc, DateTime bootUtc)
    {
        Options = options;
        Paths = paths;
        NowUtc = nowUtc;
        BootUtc = bootUtc;
    }

    public ScanOptions Options { get; }
    public PathNormalizer Paths { get; }
    public DateTime NowUtc { get; }
    public DateTime BootUtc { get; set; }
    public DateTime? OsInstallUtc { get; set; }
    /// <summary>When the user of this session signed in; null when Windows does not say.</summary>
    public DateTime? SignInUtc { get; set; }
    /// <summary>The games running at the scan, earliest start first.</summary>
    public IReadOnlyList<GameStart> Games { get; set; } = [];
    /// <summary>Java programs running at the scan that are not recognisably the game.</summary>
    public IReadOnlyList<GameStart> OtherJava { get; set; } = [];
    /// <summary>When the desktop shell started; set by the system-state check.</summary>
    public DateTime? ShellStartUtc { get; set; }

    public ConcurrentBag<Evidence> Evidence { get; } = new();
    public ConcurrentBag<Finding> Findings { get; } = new();
    public ConcurrentBag<IntegrityCheck> Checks { get; } = new();
    public ConcurrentBag<ClockChange> ClockChanges { get; } = new();
    public ConcurrentBag<MemoryHit> MemoryHits { get; } = new();
    public ConcurrentBag<CommandEntry> Commands { get; } = new();
    public ConcurrentBag<Bypass.ServiceEvent> ServiceEvents { get; } = new();
    public ConcurrentBag<FolderVisit> Folders { get; } = new();

    /// <summary>Number of .pf files present; set by the Prefetch collector.</summary>
    public int PrefetchFileCount { get; set; } = -1;

    /// <summary>
    /// Runtime files a hash-verified copy of this suite loaded, by what Windows wrote in that copy's own Prefetch file. Kept so
    /// that once such a file is deleted it is still known to have been ours - by Windows' record, not by the folder's name.
    /// </summary>
    public ConcurrentDictionary<string, byte> OwnRuntimeFiles { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>When this program started. Everything Windows recorded from then on happened while the scan was running.</summary>
    public DateTime ScanProcessStartUtc { get; } = OwnStart();

    static DateTime OwnStart()
    {
        try { using var self = System.Diagnostics.Process.GetCurrentProcess(); return self.StartTime.ToUniversalTime(); }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { return DateTime.UtcNow; }
    }

    public void Add(Evidence e) => Evidence.Add(e);

    public void Check(string area, string name, CheckState state, string detail) =>
        Checks.Add(new IntegrityCheck(area, name, state, detail));

    public void Flag(Severity severity, FindingCategory category, string title, string detail,
        string? path = null, DateTime? timeUtc = null) =>
        Findings.Add(new Finding
        {
            Severity = severity, Category = category, Title = title, Detail = detail, Path = path, TimeUtc = timeUtc,
        });
}
