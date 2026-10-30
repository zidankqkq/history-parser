using HistoryParser.Core.Bypass;
using HistoryParser.Core.Models;

namespace HistoryParser.App.Tampering;

public sealed record DetailField(string Label, string Value, bool Mono = false);
public sealed record DetailRelated(DateTime? TimeUtc, string What, string Detail);

/// <summary>Everything about one selected row: its fields in full, findings about the same path, and related records.</summary>
public sealed record DetailView(string Title, string Subtitle, IReadOnlyList<DetailField> Fields, IReadOnlyList<Finding> Findings,
    string RelatedTitle, IReadOnlyList<DetailRelated> Related)
{
    static string T(DateTime? t) => t is { } v ? v.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "—";

    /// <summary>Shown above the fields when the row's file is in a Temp folder.</summary>
    public string? Note { get; init; }

    public const string TempNote =
        "This is temporary: either a Temp folder, where installers, updaters and launchers unpack files and which Windows clears " +
        "on its own, or one of Windows' own saves through a temporary copy (recognised by Windows' exact naming, folder and " +
        "order, not just a .tmp name). Being in Temp does not make a file harmless: cheats and loaders often run from Temp to " +
        "leave less behind, so judge it by what it is and its findings. Flagged rows are never hidden.";

    /// <summary>
    /// A row about a temporary file: something in a Temp folder, or one of Windows' own saves through a temporary copy
    /// (recognised by its exact name pattern, folder and sequence, see FileTypes.IsWindowsSaveCopy). A file merely
    /// named *.tmp does not count.
    /// </summary>
    public static bool IsTempRow(object? o) =>
        PathOf(o) is { } path && TempFolder.IsMatch(path) ||
        o is ArtifactChange a && a.Change.StartsWith(SavedByWindows, StringComparison.Ordinal);
    const string SavedByWindows = "Saved by Windows";
    static readonly System.Text.RegularExpressions.Regex TempFolder = new(@"\\(Temp|Tmp)\\|%TEMP%|%TMP%",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>The file a row is about (a command line counts when it runs something from Temp).</summary>
    public static string? PathOf(object? o) => o switch
    {
        Finding f => f.Path,
        ArtifactChange a => a.Path,
        ArgumentHit a => a.CommandLine,
        DriverRow d => d.Path,
        TaskRow t => t.Command,
        RouteCheck c => c.Path,
        _ => null,
    };

    public static DetailView? For(object? row, BypassReport r) =>
        Build(row, r) is not { } view ? null : IsTempRow(row) ? view with { Note = TempNote } : view;

    static DetailView? Build(object? row, BypassReport r) => row switch
    {
        ArgumentHit a => new(a.Program, a.Source,
            [new("Time", T(a.TimeUtc)), new("Process id", a.Pid?.ToString() ?? "—"), new("Why flagged", a.Reasons.Length > 0 ? a.Reasons : "Not flagged"),
             new("Command line", a.CommandLine, true)],
            [], "Other command lines of this program",
            r.Arguments.Where(o => o != a && o.Program.Equals(a.Program, StringComparison.OrdinalIgnoreCase)).Take(50)
                .Select(o => new DetailRelated(o.TimeUtc, o.Source, o.CommandLine)).ToList()),

        ArtifactChange c => new(c.Artifact, c.Change,
            [new("Time", T(c.TimeUtc)), new("Path", c.Path, true), new("Detail", c.Detail)],
            FindingsAbout(c.Path, r), "Everything recorded about this file", Timeline(c.Path, r)),

        UsbDevice d => new(d.Name, d.ConnectedNow ? "Plugged in now" : "Not plugged in now",
            [new("Serial", d.Serial, true), new("Drive letter", d.DriveLetter.Length > 0 ? d.DriveLetter : "—"),
             new("First connected", T(d.FirstConnectedUtc)), new("Last connected", T(d.LastConnectedUtc)), new("Last removed", T(d.LastRemovedUtc))],
            [], "Connect and disconnect history",
            r.UsbEvents.Where(e => e.Serial.Equals(d.Serial, StringComparison.OrdinalIgnoreCase))
                .Select(e => new DetailRelated(e.TimeUtc, e.Action, e.Detail)).ToList()),

        DriverRow d => new(d.Name, d.Flagged ? d.Note : "Kernel driver loaded now",
            [new("Path", d.Path, true), new("Note", d.Note.Length > 0 ? d.Note : "—")],
            FindingsAbout(d.Path, r), "Everything recorded about this file", Timeline(d.Path, r)),

        TaskRow t => new(t.Name, t.Flagged ? "Flagged" : "Scheduled task",
            [new("Created", T(t.CreatedUtc)), new("Last changed", T(t.ModifiedUtc)), new("Runs", t.Command, true), new("Note", t.Note.Length > 0 ? t.Note : "—")],
            [], "", []),

        SoftwareRow s => new(s.Name, s.Action,
            [new("Time", T(s.TimeUtc)), new("Version", s.Version), new("Publisher", s.Publisher), new("Note", s.Note.Length > 0 ? s.Note : "—")],
            [], "", []),

        DefenderChange d => new(d.Setting, d.Suspicious ? "Flagged" : "Defender change",
            [new("Time", T(d.TimeUtc)), new("New value", d.NewValue, true), new("Old value", d.OldValue, true)],
            [], "", []),

        RouteCheck c => new(c.Item, c.Area,
            [new("Result", c.Value, true), new("Time", T(c.TimeUtc)), new("Detail", c.Detail.Length > 0 ? c.Detail : "—"), new("Path", c.Path.Length > 0 ? c.Path : "—", true)],
            c.Path.Length > 0 ? FindingsAbout(c.Path, r) : [], c.Path.Length > 0 ? "Everything recorded about this file" : "",
            c.Path.Length > 0 ? Timeline(c.Path, r) : []),

        _ => null,
    };

    static List<Finding> FindingsAbout(string path, BypassReport r) =>
        r.Findings.Where(f => string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase)).ToList();

    static List<DetailRelated> Timeline(string path, BypassReport r) =>
        r.History.Timeline.Where(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase)).Take(100)
            .Select(e => new DetailRelated(e.TimeUtc, $"{Display.Source(e.Source)} · {e.Kind}", e.Detail)).ToList();
}
