using HistoryParser.Core.Models;

namespace HistoryParser.Core.Analysis;

/// <summary>
/// Rows that repeat another row: the same library sitting in many folders. A build writes one DLL into dozens of output
/// folders, an updater leaves a folder per version, a single-file program unpacks the same five runtime libraries on every
/// new build. On a PC where that happens the list of libraries is those copies, and the few that matter are lost in them.
/// <para>
/// Folded, never dropped: one of them stays in the list with a count, the others are listed under it, and a search looks
/// through all of them.
/// </para>
/// <para>
/// What may fold is limited to what cannot be used to hide something:
/// only a library (programs, jars, scripts and drivers always keep their own rows - where each one sits is the point);
/// only one that never ran and was never loaded, so every load keeps its row;
/// only under a file with the same name and the same contents (same SHA-256), or, for files that are gone and have no
/// contents left to compare, the same name in folders side by side, three or more of them;
/// never a file with a finding of any kind: a row that carries a mark keeps it in view.
/// The row that stays is the one that was loaded, else the newest. Since a copy only ever folds under its own name, the
/// name on screen is never a stand-in someone picked: copying a file ten times to bury it gets one row, under that name, that says "×10".
/// </para>
/// </summary>
public static class Repeats
{
    /// <param name="Lead">The path of the row that stays in the list.</param>
    /// <param name="Copies">The paths folded under it.</param>
    /// <param name="Why">What makes them the same file, for the reader.</param>
    public sealed record Group(string Lead, IReadOnlyList<string> Copies, string Why);

    public const string SameContents = "The same file, byte for byte";
    public const string SameNameGone = "The same name in folders side by side, all gone";

    public static List<Group> Find(IEnumerable<FileRecord> files)
    {
        // Routine files and this suite's own are folded already, each under its own switch.
        var libraries = files.Where(f => f.Type == FileType.Dll && !f.IsThisTool && f.Routine == null && !f.IsWindowsFile &&
                                         !f.Path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)).ToList();
        var groups = new List<Group>();
        var folded = new HashSet<FileRecord>();

        // Same contents under another name is not a copy for this purpose: folding it would let the name in view be chosen.
        foreach (var same in libraries.Where(f => !string.IsNullOrEmpty(f.Sha256)).GroupBy(f => (f.Sha256!.ToUpperInvariant(), f.Name.ToUpperInvariant())))
        {
            var lead = Lead(same);
            var copies = same.Where(f => f != lead && MayFold(f)).OrderByDescending(f => f.LastActivityUtc ?? DateTime.MinValue).ToList();
            if (copies.Count == 0) continue;
            folded.UnionWith(copies);
            groups.Add(new Group(lead.Path, copies.Select(c => c.Path).ToList(), SameContents));
        }

        foreach (var siblings in libraries.Where(f => string.IsNullOrEmpty(f.Sha256) && IsGone(f) && MayFold(f) && !folded.Contains(f))
                     .GroupBy(f => SiblingKey(f.Path), StringComparer.OrdinalIgnoreCase).Where(g => g.Key.Length > 0 && g.Count() >= 3))
        {
            var lead = Lead(siblings);
            groups.Add(new Group(lead.Path,
                siblings.Where(f => f != lead).OrderByDescending(f => f.LastActivityUtc ?? DateTime.MinValue).Select(f => f.Path).ToList(), SameNameGone));
        }
        return groups;
    }

    /// <summary>Never ran, never loaded, and nothing was found about it (a finding of any level keeps its row; this suite's own notes do not count).</summary>
    static bool MayFold(FileRecord f) => !f.WasExecutedDirectly && !f.WasLoaded && f.MaxSeverity == null;

    static bool IsGone(FileRecord f) => f.Status is FileStatus.Deleted or FileStatus.InRecycleBin or FileStatus.Renamed or FileStatus.Missing or FileStatus.DriveNotConnected;

    /// <summary>The one that was loaded (the latest load), else the one with the newest record of any kind.</summary>
    static FileRecord Lead(IEnumerable<FileRecord> same) => same
        .OrderByDescending(f => f.WasExecutedDirectly || f.WasLoaded)
        .ThenByDescending(f => f.LastExecutionUtc ?? DateTime.MinValue)
        .ThenByDescending(f => f.LastActivityUtc ?? DateTime.MinValue)
        .ThenBy(f => f.Path, StringComparer.OrdinalIgnoreCase).First();

    /// <summary>"C:\a\b\1234\x.dll" → "c:\a\b\*\x.dll": the same name one folder over. Empty when the path is too short to have that.</summary>
    internal static string SiblingKey(string path)
    {
        var folder = Path.GetDirectoryName(path);
        var parent = folder == null ? null : Path.GetDirectoryName(folder);
        return string.IsNullOrEmpty(parent) ? "" : $@"{parent.TrimEnd('\\')}\*\{Path.GetFileName(path)}";
    }
}
