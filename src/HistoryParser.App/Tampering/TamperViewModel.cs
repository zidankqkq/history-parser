using System.Collections;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using HistoryParser.App.ViewModels;
using HistoryParser.Core;
using HistoryParser.Core.Bypass;
using HistoryParser.Core.Export;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.App.Tampering;

/// <summary>
/// The tampering and bypass half of History Parser's one scan: its pages, tables and the program-argument rules.
/// The main view model runs the scan, opens and saves reports, and hands the result over with <see cref="Load"/>.
/// </summary>
public sealed class TamperViewModel : ObservableObject
{
    readonly DispatcherTimer _filterTimer;

    public TamperViewModel()
    {
        _filterTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(160) };
        _filterTimer.Tick += (_, _) => { _filterTimer.Stop(); RefreshCurrent(); };

        ExportCsvCommand = new RelayCommand(ExportCsv, () => Report != null);
        NavigateCommand = new RelayCommand(p => { if (p is string page) Page = page; });
        CopyCommand = new RelayCommand(p => Copy(p as string), p => !string.IsNullOrEmpty(p as string));

        _argumentsText = ArgumentRules.Default().ToText().TrimEnd();
        foreach (var key in Pages.Keys) _views[key] = new ListCollectionView(new List<object>());
    }

    // ---- pages ----------------------------------------------------------------------------------
    /// <summary>Each page's views: the main table, and an optional second table underneath.</summary>
    static readonly Dictionary<string, (string Title, string Subtitle)> Pages = new()
    {
        ["Findings"] = ("Tampering findings", "Every tampering and bypass lead, strongest first. All findings, at the top of the sidebar, has these together with the execution findings."),
        ["Logs"] = ("Event logs", "Whether each log is enabled, how big it may grow, how far back it goes, and whether records were deleted from it."),
        ["Gaps"] = ("", ""),
        ["Services"] = ("Services", "Services that record evidence: their state now, when their settings last changed, and every stop or start-type change."),
        ["ServiceEvents"] = ("", ""),
        ["Usb"] = ("USB devices", "Every USB storage device ever connected — even ones unplugged now — and each connect and disconnect."),
        ["UsbEvents"] = ("", ""),
        ["Arguments"] = ("Program arguments", "Command lines of running programs, process-creation logs and Minecraft / launcher logs, checked against the argument rules."),
        ["Evidence"] = ("Evidence files", "Event logs, prefetch, Amcache, recent items, jump lists and shell history that were deleted, emptied or turned off."),
        ["Clock"] = ("Clock & integrity", "Clock changes and the health of every evidence source."),
        ["Checks"] = ("", ""),
    };

    readonly Dictionary<string, ListCollectionView> _views = new();
    public ListCollectionView FindingsView => _views["Findings"];
    public ListCollectionView LogsView => _views["Logs"];
    public ListCollectionView GapsView => _views["Gaps"];
    public ListCollectionView ServicesView => _views["Services"];
    public ListCollectionView ServiceEventsView => _views["ServiceEvents"];
    public ListCollectionView UsbView => _views["Usb"];
    public ListCollectionView UsbEventsView => _views["UsbEvents"];
    public ListCollectionView ArgumentsView => _views["Arguments"];
    public ListCollectionView EvidenceView => _views["Evidence"];
    public ListCollectionView ClockView => _views["Clock"];
    public ListCollectionView ChecksView => _views["Checks"];

    /// <summary>Second table shown on the same page.</summary>
    static string? Companion(string page) => page switch
    {
        "Logs" => "Gaps", "Services" => "ServiceEvents", "Usb" => "UsbEvents", "Clock" => "Checks", _ => null,
    };

    string _page = "Overview";
    public string Page
    {
        get => _page;
        set
        {
            if (!Set(ref _page, value)) return;
            _search = "";
            OnPropertyChanged(nameof(Search));
            OnPropertyChanged(nameof(PageTitle));
            OnPropertyChanged(nameof(PageSubtitle));
            OnPropertyChanged(nameof(IsTablePage));
            _selectedRow = _selectedByPage.GetValueOrDefault(value);
            OnPropertyChanged(nameof(SelectedRow));
            OnPropertyChanged(nameof(Details));
            OnPropertyChanged(nameof(HasDetailsPanel));
            OnPropertyChanged(nameof(ShowTempToggle));
            RefreshCurrent();
        }
    }
    public string PageTitle => Pages.TryGetValue(Page, out var p) ? p.Title : "";
    /// <summary>Pages that show the shared title / search / "flagged only" bar above their tables.</summary>
    public bool IsTablePage => Page != "Overview";
    public string PageSubtitle => Pages.TryGetValue(Page, out var p) ? p.Subtitle : "";


    // ---- details panel ------------------------------------------------------------------------------
    /// <summary>Pages whose rows open a details panel. Services, logs and the clock page say everything in the row.</summary>
    static readonly HashSet<string> DetailPages = ["Evidence", "Arguments", "Usb"];
    public bool HasDetailsPanel => DetailPages.Contains(Page);

    readonly Dictionary<string, object> _selectedByPage = new();
    object? _selectedRow;
    /// <summary>The row clicked on the current page (set by the view, remembered per page).</summary>
    public object? SelectedRow
    {
        get => _selectedRow;
        set
        {
            if (!Set(ref _selectedRow, value)) return;
            if (value != null) _selectedByPage[Page] = value; else _selectedByPage.Remove(Page);
            OnPropertyChanged(nameof(Details));
        }
    }
    public DetailView? Details => Report == null ? null : DetailView.For(SelectedRow, Report);
    // ---- state ------------------------------------------------------------------------------------
    /// <summary>The loaded scan; null until one is loaded, and for an old report that has only executions.</summary>
    public BypassReport? Report { get; private set; }
    public bool HasResults => Report != null;

    // ---- filters ------------------------------------------------------------------------------------
    string _search = "";
    public string Search { get => _search; set { if (Set(ref _search, value)) { _filterTimer.Stop(); _filterTimer.Start(); } } }
    // On by default: most rows say "checked, fine"; the count of hidden ones is shown and one click brings them back.
    bool _flaggedOnly = true;
    public bool FlaggedOnly { get => _flaggedOnly; set { if (Set(ref _flaggedOnly, value)) RefreshCurrent(); } }
    bool _hideTemp;
    /// <summary>Hide unflagged rows whose file is in a Temp folder (only offered on pages where such rows appear).</summary>
    public bool HideTemp { get => _hideTemp; set { if (Set(ref _hideTemp, value)) RefreshCurrent(); } }
    static readonly HashSet<string> TempPages = ["Findings", "Evidence", "Arguments"];
    public bool ShowTempToggle => TempPages.Contains(Page);

    /// <summary>Rows that are suspicious on their own.</summary>
    static bool IsFlagged(object o) => o switch
    {
        Finding f => f.Severity >= Severity.Medium,
        LogChannelInfo l => l.State != CheckState.Ok,
        RecordGap => true,
        ServiceRow s => s.Status != CheckState.Ok,
        ServiceEvent e => e.Suspicious,
        UsbDevice => true,
        UsbEvent => true,
        ArgumentHit a => a.Flagged,
        DriverRow d => d.Flagged,
        TaskRow t => t.Flagged,
        SoftwareRow s => s.Flagged,
        ArtifactChange a => a.Suspicious,
        DefenderChange d => d.Suspicious,
        ClockChange => true,
        IntegrityCheck c => c.State is CheckState.Bad or CheckState.Warning,
        RouteCheck r => r.State is CheckState.Bad or CheckState.Warning,
        _ => true,
    };

    bool Filter(object o)
    {
        if (FlaggedOnly && !IsFlagged(o)) return false;
        // Flagged rows always stay: being in Temp must never be a way to slip past the screensharer.
        if (HideTemp && !IsFlagged(o) && DetailView.IsTempRow(o)) return false;
        // Records print every property, so searching their text searches every column.
        return Search.Length == 0 || o.ToString()!.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    void RefreshCurrent()
    {
        foreach (var key in new[] { Page, Companion(Page) })
            if (key != null && _views.TryGetValue(key, out var view)) view.Refresh();
        OnPropertyChanged(nameof(VisibleRows));
        OnPropertyChanged(nameof(HiddenRows));
        OnPropertyChanged(nameof(HiddenText));
    }

    public int VisibleRows => _views.TryGetValue(Page, out var v) ? v.Count : 0;
    /// <summary>Rows on this page that "Flagged only" hides (checked and fine).</summary>
    public int HiddenRows => FlaggedOnly && _views.TryGetValue(Page, out var v) && v.SourceCollection is System.Collections.ICollection all ? all.Count - v.Count : 0;
    public string HiddenText => HiddenRows > 0 ? $"{HiddenRows:N0} more checked and fine - turn off Flagged only to see them" : "";

    // ---- summary ------------------------------------------------------------------------------------
    public string MachineLine => Report == null ? "" :
        $"{Report.History.Machine.ComputerName}  ·  {Report.History.Machine.OsVersion}  ·  {Report.History.Machine.UserName}";
    public string ScanLine => Report == null ? "" :
        $"Scanned {Report.History.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  ·  booted {Report.History.Machine.BootTimeUtc.ToLocalTime():yyyy-MM-dd HH:mm}" +
        $"  ·  {Report.History.Machine.TimeZone}  ·  showing {TimeWindows.Label(Report.History.Window)}" + (Report.History.Machine.IsElevated ? "" : "  ·  NOT ELEVATED — results are incomplete");
    public int HighCount => Report?.Findings.Count(f => f.Severity == Severity.High) ?? 0;
    public int MediumCount => Report?.Findings.Count(f => f.Severity == Severity.Medium) ?? 0;
    public int LowCount => Report?.Findings.Count(f => f.Severity == Severity.Low) ?? 0;
    public int FlaggedFindingCount => HighCount + MediumCount;
    public long DeletedRecords => Report?.RecordGaps.Sum(g => g.Missing) ?? 0;
    public int UsbCount => Report?.UsbDevices.Count ?? 0;
    public int FlaggedArguments => Report?.Arguments.Count(a => a.Flagged) ?? 0;
    public int ProblemLogs => Report?.Logs.Count(l => l.State != CheckState.Ok) ?? 0;
    public int ProblemServices => Report?.Services.Count(s => s.Status != CheckState.Ok) ?? 0;
    public int FlaggedEvidence => Report?.Artifacts.Count(a => a.Suspicious) ?? 0;
    public int ClockChangeCount => Report?.History.ClockChanges.Count ?? 0;
    /// <summary>The evidence services as they are now, for the Integrity &amp; services page.</summary>
    public IReadOnlyList<ServiceRow> ServicesList => Report?.Services ?? [];
    public IReadOnlyList<Finding> TopFindings => Report?.Findings.Take(8).ToList() ?? [];
    public bool ShowingRedactedReport => Report?.PrivateDetailsHidden == true;
    public string AppVersion => "v" + Scanner.Version;

    // ---- scan options & rules (edited on History Parser's start screen) -----------------------------
    /// <summary>Read Minecraft and launcher logs for launch arguments.</summary>
    public bool ReadGameLogs { get; set; } = true;

    string _rulesMode = "Default";
    public string RulesMode
    {
        get => _rulesMode;
        set { if (Set(ref _rulesMode, value)) RulesError = null; }
    }

    string _argumentsText;
    public string ArgumentsText
    {
        get => _argumentsText;
        set { if (Set(ref _argumentsText, value)) { RulesError = null; OnPropertyChanged(nameof(ArgumentRuleCount)); } }
    }
    public int ArgumentRuleCount => ArgumentsText.Split('\n').Count(l => l.Trim().Length > 0 && !l.Trim().StartsWith('#'));

    string? _rulesError;
    public string? RulesError { get => _rulesError; set => Set(ref _rulesError, value); }

    /// <summary>The program-argument rules to scan with (built-in, or the edited ones); null when the edited ones have a mistake.</summary>
    public ArgumentRules? CurrentArgumentRules() => BuildRules();

    ArgumentRules? BuildRules()
    {
        if (RulesMode != "Custom") return ArgumentRules.Default();
        var (rules, errors) = ArgumentRules.TryParse(ArgumentsText);
        RulesError = errors.Count > 0 ? string.Join(Environment.NewLine, errors) : null;
        return rules;
    }

    // ---- commands ----------------------------------------------------------------------------------
    public RelayCommand ExportCsvCommand { get; }
    public RelayCommand NavigateCommand { get; }
    public RelayCommand CopyCommand { get; }

    /// <summary>Shows a scan's tampering half; null empties every page (an old report with executions only).</summary>
    public void Load(BypassReport? report)
    {
        Report = report;
        _page = "Overview";
        _search = "";
        BuildViews();
        CommandManager.InvalidateRequerySuggested();
    }

    /// <summary>Builds every table from <see cref="Report"/>.</summary>
    void BuildViews()
    {
        _selectedByPage.Clear();
        _selectedRow = null;
        void Bind(string key, IEnumerable rows) =>
            _views[key] = new ListCollectionView(rows.Cast<object>().ToList()) { Filter = Filter };
        if (Report is not { } report)
        {
            foreach (var key in Pages.Keys) Bind(key, Array.Empty<object>());
            OnPropertyChanged(string.Empty);
            return;
        }
        Bind("Findings", report.Findings);
        Bind("Logs", report.Logs);
        Bind("Gaps", report.RecordGaps);
        Bind("Services", report.Services);
        Bind("ServiceEvents", report.ServiceEvents);
        Bind("Usb", report.UsbDevices);
        Bind("UsbEvents", report.UsbEvents);
        Bind("Arguments", report.Arguments);
        Bind("Evidence", report.Artifacts);
        Bind("Clock", report.History.ClockChanges);
        Bind("Checks", report.History.Checks
            .OrderByDescending(c => c.State switch { CheckState.Bad => 3, CheckState.Warning => 2, CheckState.Unknown => 1, _ => 0 }).ToList());
        OnPropertyChanged(string.Empty);
    }

    // ---- actions -----------------------------------------------------------------------------------

    static void Copy(string? text)
    {
        if (string.IsNullOrEmpty(text)) return;
        try { Clipboard.SetText(text); }
        catch (System.Runtime.InteropServices.COMException) { }
    }

    bool _hidePrivate;
    public bool HidePrivate { get => _hidePrivate; set => Set(ref _hidePrivate, value); }

    string DefaultFileName(string suffix, string ext) => HidePrivate || ShowingRedactedReport
        ? $"HistoryParser-{Report!.History.StartedUtc.ToLocalTime():yyyyMMdd-HHmm}{suffix}-private-hidden.{ext}"
        : $"HistoryParser-{Report!.History.Machine.ComputerName}-{Report.History.StartedUtc.ToLocalTime():yyyyMMdd-HHmm}{suffix}.{ext}";

    /// <summary>The main table of the current page, exactly as filtered on screen.</summary>
    void ExportCsv()
    {
        if (Report == null || !_views.TryGetValue(Page, out var view)) return;
        var rows = view.Cast<object>().ToList();
        if (rows.Count == 0) return;
        var clean = HidePrivate ? Redactor.CreateCleaner(Report.History) : null;
        var props = rows[0].GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(string) || p.PropertyType.IsValueType).ToList();
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", props.Select(p => Csv(BypassExport.Header(p.Name)))));
        foreach (var row in rows)
        {
            if (HidePrivate && row is ArgumentHit { Flagged: false }) continue;
            sb.AppendLine(string.Join(",", props.Select(p =>
            {
                var v = p.GetValue(row);
                var text = v is DateTime t ? t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : v?.ToString() ?? "";
                return Csv(clean == null ? text : clean(text));
            })));
        }
        var dialog = new SaveFileDialog { FileName = DefaultFileName("-" + Page.ToLowerInvariant(), "csv"), Filter = "CSV (*.csv)|*.csv" };
        if (dialog.ShowDialog() != true) return;
        try { File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show($"Could not save the CSV: {e.Message}", "History Parser", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        static string Csv(string s)
        {
            if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@') s = "'" + s;
            return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        }
    }
}
