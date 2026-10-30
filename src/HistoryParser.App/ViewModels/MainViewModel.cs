using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using HistoryParser.Core;
using HistoryParser.Core.Export;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;

namespace HistoryParser.App.ViewModels;

public enum AppState { Ready, Scanning, Results }

public sealed class MainViewModel : ObservableObject
{
    /// <summary>Sidebar pages that show the file table, with the preset each one applies.</summary>
    static readonly Dictionary<string, (string Title, string Subtitle)> FilePages = new()
    {
        ["Programs"] = ("All programs ran", "Everything that was started on this PC — executables, scripts and jars run through Java. Flagged first, then most recently run; click a column to sort."),
        ["Executables"] = ("Executables", "Every .exe any source mentions: run, loaded, or only seen in a cache or in memory."),
        ["Dlls"] = ("DLLs", "Every .dll loaded by a program (from Prefetch) or seen in memory and caches. Injected cheat modules show up here."),
        ["Jars"] = ("Java archives", "Every .jar — launched with javaw/java, loaded by Minecraft, or seen in memory and caches."),
        ["Deleted"] = ("Deleted programs", "Files that ran or loaded and are now deleted, recycled, renamed or missing."),
    };

    static readonly HashSet<FindingCategory> InconsistencyCategories =
        [FindingCategory.ClockTampering, FindingCategory.TimelineInconsistency];

    readonly DispatcherTimer _filterTimer;
    CancellationTokenSource? _cts;
    List<FileRow> _files = new();

    public MainViewModel()
    {
        IsElevated = WinApi.IsElevated();
        Tamper.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is not (nameof(Tamper.Page) or "" or null)) return;
            OnPropertyChanged(nameof(NavPage));
        };
        _filterTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(160) };
        _filterTimer.Tick += (_, _) => { _filterTimer.Stop(); RefreshFilters(); };

        StartScanCommand = new RelayCommand(StartScan, () => State != AppState.Scanning);
        // Sidebar button: before a scan it starts one; after a scan it returns to the rules screen
        // so a rescan can use different rules.
        PrimaryActionCommand = new RelayCommand(() => { if (HasResults) NewScan(); else StartScan(); }, () => State != AppState.Scanning);
        BackToResultsCommand = new RelayCommand(() => { Page = "Overview"; State = AppState.Results; }, () => State == AppState.Ready && Result != null);
        CancelScanCommand = new RelayCommand(() => _cts?.Cancel(), () => State == AppState.Scanning);
        ExportHtmlCommand = new RelayCommand(() => Export("html"), () => Result != null);
        ExportJsonCommand = new RelayCommand(() => Export("json"), () => Result != null);
        ExportCsvCommand = new RelayCommand(ExportCsv, () => Result != null);
        OpenReportCommand = new RelayCommand(OpenReport, () => State != AppState.Scanning);
        RestartElevatedCommand = new RelayCommand(RestartElevated, () => !IsElevated);
        ShowFileCommand = new RelayCommand(p => ShowFile(p as string), p => p is string path && _filePaths.Contains(path));
        NavigateCommand = new RelayCommand(p => Navigate(p as string));
        CopyCommand = new RelayCommand(p => Copy(p as string), p => !string.IsNullOrEmpty(p as string));
        OpenLocationCommand = new RelayCommand(p => OpenLocation(p as string), p => p is string s && s.Length > 2 && s[1] == ':');
        VirusTotalCommand = new RelayCommand(p => LookUp(p as string), p => !string.IsNullOrEmpty(p as string));
        CheckRecentCommand = new RelayCommand(CheckRecent, () => _files.Count > 0);
        LoadRulesCommand = new RelayCommand(LoadRules);
        SaveRulesCommand = new RelayCommand(SaveRules);
        ResetRulesCommand = new RelayCommand(ResetRules);

        FilesView = new ListCollectionView(new List<FileRow>());
        TimelineView = new ListCollectionView(new List<EvidenceRow>());
        FindingsView = new ListCollectionView(new List<Finding>());
        InconsistencyView = new ListCollectionView(new List<Finding>());
        MemoryView = new ListCollectionView(new List<MemoryHit>());
        CommandsView = new ListCollectionView(new List<CommandRow>());
        InitRules();
    }

    // ---- state ------------------------------------------------------------------------------
    AppState _state = AppState.Ready;
    public AppState State
    {
        get => _state;
        set
        {
            if (!Set(ref _state, value)) return;
            OnPropertyChanged(nameof(IsReady));
            OnPropertyChanged(nameof(IsScanning));
            OnPropertyChanged(nameof(HasResults));
            CommandManager.InvalidateRequerySuggested();
        }
    }
    public bool IsReady => State == AppState.Ready;
    public bool IsScanning => State == AppState.Scanning;
    public bool HasResults => State == AppState.Results;
    public bool IsElevated { get; }

    string _page = "Overview";

    /// <summary>
    /// The selected section in the one sidebar: an execution page ("Programs"), or a tampering page as
    /// "Tamper:Logs" - shown in the Tampering area with that page selected.
    /// </summary>
    public string NavPage
    {
        get => Page == "Tamper" ? "Tamper:" + Tamper.Page : Page;
        set
        {
            if (value.StartsWith("Tamper:", StringComparison.Ordinal))
            {
                Tamper.Page = value["Tamper:".Length..];
                Page = "Tamper";
            }
            else Page = value;
            OnPropertyChanged(nameof(NavPage));
            OnPropertyChanged(nameof(FilesNav));
        }
    }

    public string Page
    {
        get => _page;
        set
        {
            if (!Set(ref _page, value)) return;
            OnPropertyChanged(nameof(NavPage));
            OnPropertyChanged(nameof(FilesNav));
            OnPropertyChanged(nameof(IsFilePage));
            OnPropertyChanged(nameof(FilePageTitle));
            OnPropertyChanged(nameof(FilePageSubtitle));
            OnPropertyChanged(nameof(ShowGoneToggle));
            if (IsFilePage)
            {
                // The five file pages share one view whose filter depends on the page.
                SelectedFile = null;
                _stale.Add("Files");
            }
            RefreshCurrent();
        }
    }
    public bool IsFilePage => FilePages.ContainsKey(Page);

    /// <summary>One sidebar entry for the five file pages; the kind of file is picked with chips on the page.</summary>
    public bool FilesNav { get => IsFilePage; set { if (value && !IsFilePage) Page = "Programs"; } }

    public string FilePageTitle => FilePages.TryGetValue(Page, out var p) ? p.Title : "";
    public string FilePageSubtitle => FilePages.TryGetValue(Page, out var p) ? p.Subtitle : "";
    public bool ShowGoneToggle => Page != "Deleted";

    public ScanResult? Result { get; private set; }

    string? _loadedFrom;
    /// <summary>Set when viewing a report opened from disk rather than a live scan.</summary>
    public string? LoadedFrom { get => _loadedFrom; set => Set(ref _loadedFrom, value); }

    string? _error;
    public string? Error { get => _error; set => Set(ref _error, value); }

    // ---- scan options -------------------------------------------------------------------------
    public bool ScanMemory { get; set; } = true;
    public bool InspectFiles { get; set; } = true;
    /// <summary>Tampering half: read launch arguments from Minecraft and launcher logs.</summary>
    public bool ReadGameLogs { get => Tamper.ReadGameLogs; set => Tamper.ReadGameLogs = value; }
    /// <summary>Start-screen option: write the HTML and JSON report as soon as the scan ends.</summary>
    public bool AutoSave { get; set; }
    public static string ReportFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Screenshare reports");
    string? _autoSaveStatus;
    /// <summary>Shown in the title bar after an automatic save (or why it failed).</summary>
    public string? AutoSaveStatus { get => _autoSaveStatus; set => Set(ref _autoSaveStatus, value); }

    /// <summary>The whole scan: execution history and the tampering audits. Null for an old executions-only report.</summary>
    public Core.Bypass.BypassReport? Combined { get; private set; }

    /// <summary>Shows one combined result in both halves of the program.</summary>
    public void LoadCombined(Core.Bypass.BypassReport report, string? fromFile)
    {
        Combined = report;
        Load(report.History, fromFile);
        Tamper.Load(report);
        OnPropertyChanged(nameof(IntegrityProblems));
        OnPropertyChanged(nameof(IntegrityChecks));
    }

    /// <summary>Opens a saved report: a combined one, or an older executions-only History Parser report.</summary>
    public void OpenFile(string path)
    {
        Core.Bypass.BypassReport? combined = null;
        try { combined = JsonExporter.ReadBypass(path); } catch (System.Text.Json.JsonException) { }
        if (combined?.History != null) LoadCombined(combined, Path.GetFileName(path));
        else
        {
            Combined = null;
            Tamper.Load(null);
            Load(JsonExporter.Read(path), Path.GetFileName(path));
        }
    }

    void WriteReport(string kind, string path)
    {
        if (Combined != null)
        {
            var data = HidePrivate ? Core.Export.BypassExport.Redact(Combined) : Combined;
            if (kind == "html") CombinedExport.WriteHtml(data, path);
            else JsonExporter.Write(data, path);
        }
        else
        {
            var data = HidePrivate ? Redactor.Redact(Result!) : Result!;
            if (kind == "html") HtmlExporter.Write(data, path);
            else JsonExporter.Write(data, path);
        }
    }

    void SaveReportNow()
    {
        try
        {
            Directory.CreateDirectory(ReportFolder);
            WriteReport("html", Path.Combine(ReportFolder, DefaultFileName("", "html")));
            WriteReport("json", Path.Combine(ReportFolder, DefaultFileName("", "json")));
            AutoSaveStatus = $@"Report saved to Desktop\{Path.GetFileName(ReportFolder)}";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AutoSaveStatus = $"Could not save the report: {e.Message}";
        }
    }


    // ---- detection rules ----------------------------------------------------------------------
    // "Default" uses the built-in lists (or keywords.txt next to the exe); "Custom" uses the three
    // editable lists on the start screen. Nothing is saved on this PC unless "Save rules" is used.

    KeywordLists _baseRules = KeywordLists.Default();
    Core.Bypass.ArgumentRules _baseArguments = Core.Bypass.ArgumentRules.Default();
    string? _rulesUsed;

    string _rulesSourceLabel = "Built-in defaults";
    public string RulesSourceLabel { get => _rulesSourceLabel; private set => Set(ref _rulesSourceLabel, value); }

    /// <summary>Time range chosen on the start screen (a <see cref="TimeWindow"/> name).</summary>
    /// <summary>Paths that have a file record, so a finding only offers "open file" when there is one to open.</summary>
    HashSet<string> _filePaths = new(StringComparer.OrdinalIgnoreCase);
    string _scanWindow = nameof(TimeWindow.ThisBoot);
    /// <summary>Period to show, chosen before the scan. Everything is still read and cross-checked.</summary>
    public string ScanWindow
    {
        get => _scanWindow;
        set => Set(ref _scanWindow, value);
    }
    TimeWindow SelectedWindow => Enum.TryParse<TimeWindow>(ScanWindow, out var w) ? w : TimeWindow.ThisBoot;
    public string BootText => HistoryParser.Core.Native.BootInfo.Describe();

    string _rulesMode = "Default";
    public string RulesMode
    {
        get => _rulesMode;
        set
        {
            if (!Set(ref _rulesMode, value)) return;
            Tamper.RulesMode = value; // one rules choice covers the program-argument rules too
            OnPropertyChanged(nameof(IsCustomRules));
            RulesError = null;
        }
    }
    public bool IsCustomRules => RulesMode == "Custom";

    string _commandsText = "";
    public string CommandsText { get => _commandsText; set { if (Set(ref _commandsText, value)) RulesChanged(); } }

    public int CommandRuleCount => Entries(CommandsText).Count();
    public string DefaultRulesSummary =>
        $"{_baseRules.Commands.Count} command rules · {_baseArguments.Rules.Count} program-argument rules";

    string? _rulesError;
    public string? RulesError { get => _rulesError; set => Set(ref _rulesError, value); }

    static IEnumerable<(int Line, string Text)> Entries(string text) =>
        text.Split('\n').Select((l, i) => (i + 1, l.Trim())).Where(e => e.Item2.Length > 0 && !e.Item2.StartsWith('#'));

    void RulesChanged()
    {
        RulesError = null;
        OnPropertyChanged(nameof(CommandRuleCount));
    }

    /// <summary>Loads keywords.txt next to the exe (if any) as the default rules and fills the editor.</summary>
    public void InitRules()
    {
        var file = Path.Combine(AppContext.BaseDirectory, "keywords.txt");
        if (File.Exists(file))
        {
            try
            {
                var (keywords, arguments) = SplitArguments(File.ReadAllText(file));
                var baseRules = KeywordLists.Parse(keywords);
                var baseArguments = arguments == null ? _baseArguments : Core.Bypass.ArgumentRules.Parse(arguments);
                (_baseRules, _baseArguments) = (baseRules, baseArguments);
                RulesSourceLabel = "keywords.txt next to the exe";
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException)
            {
                RulesError = $"keywords.txt next to the exe could not be used, so the built-in defaults are loaded: {e.Message}";
            }
        }
        FillEditor(_baseRules, _baseArguments);
        OnPropertyChanged(nameof(DefaultRulesSummary));
    }

    void FillEditor(KeywordLists rules, Core.Bypass.ArgumentRules? arguments)
    {
        CommandsText = string.Join(Environment.NewLine, rules.Commands.Select(KeywordLists.CommandLine));
        if (arguments != null) Tamper.ArgumentsText = arguments.ToText().TrimEnd();
    }

    static (string Keywords, string? Arguments) SplitArguments(string text) => Core.Bypass.ArgumentRules.SplitRulesFile(text);

    /// <summary>The rules to scan with, or null (with <see cref="RulesError"/> set) if the custom lists are invalid.</summary>
    KeywordLists? BuildRules()
    {
        if (RulesMode != "Custom") return _baseRules;
        var errors = new List<string>();
        var commands = new List<CommandRule>();
        foreach (var (line, text) in Entries(CommandsText))
        {
            if (KeywordLists.ParseCommand(text, out var rule, out var error)) commands.Add(rule!);
            else errors.Add($"Flagged commands, line {line}: {error}");
        }
        if (errors.Count > 0)
        {
            RulesError = string.Join(Environment.NewLine, errors);
            return null;
        }
        RulesError = null;
        return new KeywordLists(commands);
    }

    /// <summary>Loads a rules file into the editor and switches to custom rules.</summary>
    public bool LoadRulesFrom(string path)
    {
        try
        {
            var (keywords, arguments) = SplitArguments(File.ReadAllText(path));
            RulesMode = "Custom";
            if (arguments != null) Tamper.ArgumentsText = arguments;
            if (Tamper.CurrentArgumentRules() == null) return false; // its error is shown under the editor
            // A file with only argument rules keeps the execution lists as they are.
            if (keywords.Trim().Length == 0) return true;
            var (rules, errors) = KeywordLists.TryParse(keywords);
            if (rules == null)
            {
                RulesError = $"{Path.GetFileName(path)}: " + string.Join(Environment.NewLine, errors);
                return false;
            }
            FillEditor(rules, null);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            RulesMode = "Custom";
            RulesError = $"Could not read {Path.GetFileName(path)}: {e.Message}";
            return false;
        }
    }

    void LoadRules()
    {
        var dialog = new OpenFileDialog { Filter = "Rules file (*.txt)|*.txt|All files|*.*" };
        if (dialog.ShowDialog() == true) LoadRulesFrom(dialog.FileName);
    }

    void SaveRules()
    {
        if (BuildRules() is not { } rules || Tamper.CurrentArgumentRules() is not { } arguments) return;
        var dialog = new SaveFileDialog { FileName = "historyparser-rules.txt", Filter = "Rules file (*.txt)|*.txt" };
        if (dialog.ShowDialog() != true) return;
        var text = rules.ToText() + Environment.NewLine
            + "# [arguments]: program: pattern => why it is flagged. program is a file name like javaw.exe, or * for every program." + Environment.NewLine
            + "[arguments]" + Environment.NewLine + arguments.ToText();
        try { File.WriteAllText(dialog.FileName, text, new UTF8Encoding(false)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { RulesError = $"Could not save: {e.Message}"; }
    }

    void ResetRules()
    {
        FillEditor(KeywordLists.Default(), Core.Bypass.ArgumentRules.Default());
        RulesError = null;
        Tamper.RulesError = null;
    }

    // ---- progress -----------------------------------------------------------------------------
    string _progressText = "";
    public string ProgressText { get => _progressText; set => Set(ref _progressText, value); }
    double _progress;
    public double Progress { get => _progress; set => Set(ref _progress, value); }
    public ObservableCollection<string> ProgressLog { get; } = new();

    // ---- summary ------------------------------------------------------------------------------
    public string MachineLine => Result == null ? "" :
        $"{Result.Machine.ComputerName}  ·  {Result.Machine.OsVersion}  ·  {Result.Machine.UserName}";
    public string AppVersion => "v" + Scanner.Version;

    public string ScanLine => Result == null ? "" :
        $"Scanned {Result.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} in {(Result.FinishedUtc - Result.StartedUtc).TotalSeconds:0.0}s  ·  " +
        $"booted {Result.Machine.BootTimeUtc.ToLocalTime():yyyy-MM-dd HH:mm}  ·  {Result.Machine.TimeZone}  ·  showing {TimeWindows.Label(Result.Window)}" +
        (LoadedFrom == null && _rulesUsed != null ? $"  ·  {_rulesUsed}" : "") +
        (Result.Machine.IsElevated ? "" : "  ·  NOT ELEVATED — results are incomplete");
    public int HighCount { get; private set; }
    public int MediumCount { get; private set; }
    public int LowCount { get; private set; }
    public int InconsistencyCount { get; private set; }
    public int ProgramCount { get; private set; }
    public int ExeCount { get; private set; }
    public int DllCount { get; private set; }
    public int JarCount { get; private set; }
    public int DeletedCount { get; private set; }
    public int CommandCount { get; private set; }
    public int SuspiciousCommandCount { get; private set; }
    public int ProblemCheckCount { get; private set; }
    /// <summary>Integrity &amp; services page: sources with a problem plus evidence services that are off or were tampered with.</summary>
    public int IntegrityProblems => ProblemCheckCount + Tamper.ProblemServices;
    public int FlaggedFindingCount => HighCount + MediumCount;
    public IReadOnlyList<Finding> TopFindings { get; private set; } = [];
    public IReadOnlyList<IntegrityCheck> ProblemChecks { get; private set; } = [];
    public IReadOnlyList<IntegrityCheck> Checks { get; private set; } = [];
    /// <summary>
    /// The checks on the Integrity &amp; services page: problems first, and services left out when the services table below
    /// lists them already.
    /// </summary>
    public IReadOnlyList<IntegrityCheck> IntegrityChecks => Checks
        .Where(c => !(Tamper.HasResults && c.Area == "Services"))
        .OrderBy(c => c.State switch { CheckState.Bad => 0, CheckState.Warning => 1, CheckState.Unknown => 2, _ => 3 }).ThenBy(c => c.Area).ToList();
    public IReadOnlyList<SourceStatus> Sources { get; private set; } = [];
    public IReadOnlyList<ClockChange> ClockChanges { get; private set; } = [];
    /// <summary>Stops, start-type changes and kills of the evidence services, newest first (Ok = nothing unusual).</summary>
    public IReadOnlyList<ServiceHistoryRow> ServiceHistory { get; private set; } = [];

    // ---- views --------------------------------------------------------------------------------
    public ListCollectionView FilesView { get; private set; }
    public ListCollectionView TimelineView { get; private set; }
    public ListCollectionView FindingsView { get; private set; }
    public ListCollectionView InconsistencyView { get; private set; }
    public ListCollectionView MemoryView { get; private set; }
    public ListCollectionView CommandsView { get; private set; }

    int _visibleFiles, _visibleTimeline, _visibleCommands;
    public int VisibleFiles { get => _visibleFiles; private set => Set(ref _visibleFiles, value); }
    public int VisibleTimeline { get => _visibleTimeline; private set => Set(ref _visibleTimeline, value); }
    public int VisibleCommands { get => _visibleCommands; private set => Set(ref _visibleCommands, value); }

    FileRow? _selectedFile;
    public FileRow? SelectedFile { get => _selectedFile; set => Set(ref _selectedFile, value); }

    // File filters (shared by the five file pages)
    string _fileSearch = "";
    public string FileSearch { get => _fileSearch; set { if (Set(ref _fileSearch, value)) Debounce(); } }
    bool _flaggedOnly;
    public bool FlaggedOnly { get => _flaggedOnly; set { if (Set(ref _flaggedOnly, value)) RefreshFilters(); } }
    bool _goneOnly;
    public bool GoneOnly { get => _goneOnly; set { if (Set(ref _goneOnly, value)) RefreshFilters(); } }
    bool _ranOnly;
    public bool RanOnly { get => _ranOnly; set { if (Set(ref _ranOnly, value)) RefreshFilters(); } }
    bool _includeWindows;
    public bool IncludeWindows { get => _includeWindows; set { if (Set(ref _includeWindows, value)) RefreshFilters(); } }
    bool _showOwnTraces;
    /// <summary>Show the traces this suite left itself (hidden by default; never counted).</summary>
    public bool ShowOwnTraces { get => _showOwnTraces; set { if (Set(ref _showOwnTraces, value)) RefreshFilters(); } }
    public int OwnTraceCount { get; private set; }

    // Findings filters
    // High + Medium by default: Low findings are context, one click away.
    string _findingSeverity = "Leads";
    public string FindingSeverity { get => _findingSeverity; set { if (Set(ref _findingSeverity, value)) RefreshFilters(); } }
    string _findingSearch = "";
    public string FindingSearch { get => _findingSearch; set { if (Set(ref _findingSearch, value)) Debounce(); } }

    // Commands filters
    string _commandGroup = "All";
    public string CommandGroup { get => _commandGroup; set { if (Set(ref _commandGroup, value)) RefreshFilters(); } }
    string _commandSearch = "";
    public string CommandSearch { get => _commandSearch; set { if (Set(ref _commandSearch, value)) Debounce(); } }
    bool _suspiciousOnly;
    public bool SuspiciousOnly { get => _suspiciousOnly; set { if (Set(ref _suspiciousOnly, value)) RefreshFilters(); } }

    // Timeline / memory filters
    string _timelineSearch = "";
    public string TimelineSearch { get => _timelineSearch; set { if (Set(ref _timelineSearch, value)) Debounce(); } }
    bool _timelineWindows;
    public bool TimelineIncludeWindows { get => _timelineWindows; set { if (Set(ref _timelineWindows, value)) RefreshFilters(); } }
    string _memorySearch = "";
    public string MemorySearch { get => _memorySearch; set { if (Set(ref _memorySearch, value)) Debounce(); } }

    bool MemoryFilter(MemoryHit h) =>
        MemorySearch.Length == 0 || h.Path.Contains(MemorySearch, StringComparison.OrdinalIgnoreCase) ||
        h.Process.Contains(MemorySearch, StringComparison.OrdinalIgnoreCase);


    // ---- commands -----------------------------------------------------------------------------
    public RelayCommand StartScanCommand { get; }
    public RelayCommand PrimaryActionCommand { get; }
    public RelayCommand BackToResultsCommand { get; }
    public bool HasPreviousResults => Result != null;
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand ExportHtmlCommand { get; }
    public RelayCommand ExportJsonCommand { get; }
    public RelayCommand ExportCsvCommand { get; }
    public RelayCommand OpenReportCommand { get; }
    public RelayCommand RestartElevatedCommand { get; }
    public RelayCommand ShowFileCommand { get; }
    public RelayCommand NavigateCommand { get; }
    public RelayCommand CopyCommand { get; }
    public RelayCommand OpenLocationCommand { get; }
    public RelayCommand VirusTotalCommand { get; }
    public RelayCommand LoadRulesCommand { get; }
    public RelayCommand SaveRulesCommand { get; }
    public RelayCommand ResetRulesCommand { get; }

    public RelayCommand CheckRecentCommand { get; }

    /// <summary>How many of the most recently run files "Check recent files" hands to the Program Checker.</summary>
    public int CheckRecentCount { get; set; } = 50;

    /// <summary>
    /// Opens the Program Checker (ProgramChecker.exe next to this program) on the most recently run programs, jars and
    /// scripts that still exist, so each is checked for malware and cheat code. The checker is a separate program on
    /// purpose: History Parser itself carries no malware indicators.
    /// </summary>
    void CheckRecent()
    {
        string checker = Path.Combine(AppContext.BaseDirectory, "ProgramChecker.exe");
        if (!File.Exists(checker))
        {
            MessageBox.Show("Put ProgramChecker.exe in the same folder as this program, then try again. It checks each file for malware and cheat code.",
                "History Parser", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var checkable = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".jar", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".ahk", ".scr" };
        var files = _files.Where(f => f.LastRun != null && checkable.Contains(Path.GetExtension(f.Path)) && File.Exists(f.Path) &&
                                      !f.Path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.LastRunKey).Select(f => f.Path).Distinct(StringComparer.OrdinalIgnoreCase).Take(CheckRecentCount).ToList();
        if (files.Count == 0)
        {
            MessageBox.Show("None of the programs that ran (outside Windows' own folder) still exist on disk.", "History Parser", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(checker) { UseShellExecute = false };
            foreach (var f in files) psi.ArgumentList.Add(f);
            System.Diagnostics.Process.Start(psi);
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            MessageBox.Show($"The Program Checker could not be started: {e.Message}", "History Parser", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public async void StartScan() => await ScanAsync();

    /// <summary>The tampering and bypass half of the scan, shown in the Tampering section of the sidebar.</summary>
    public Tampering.TamperViewModel Tamper { get; } = new();

    /// <summary>Back to the start screen so the next scan can use different rules or options.</summary>
    void NewScan()
    {
        Error = null;
        Page = "Overview";
        State = AppState.Ready;
        OnPropertyChanged(nameof(HasPreviousResults));
    }

    public async Task ScanAsync()
    {
        Error = null;
        if (BuildRules() is not { } rules)
        {
            // Show the editor with the problem instead of scanning with rules the user did not intend.
            State = AppState.Ready;
            Page = "Overview";
            return;
        }
        _rulesUsed = RulesMode == "Custom" ? "custom rules" : RulesSourceLabel.ToLowerInvariant();
        if ((RulesMode == "Custom" ? Tamper.CurrentArgumentRules() : _baseArguments) is not { } argumentRules)
        {
            State = AppState.Ready; // the mistake is shown under the program-argument rules
            Page = "Overview";
            return;
        }
        Page = "Overview"; // leave Help so the progress screen is visible
        ProgressLog.Clear();
        Progress = 0;
        ProgressText = "Starting…";
        State = AppState.Scanning;
        _cts = new CancellationTokenSource();
        var options = new ScanOptions
        {
            ScanProcessMemory = ScanMemory,
            InspectFiles = InspectFiles,
            Keywords = rules,
            Window = SelectedWindow,
            ReadGameLogs = Tamper.ReadGameLogs,
        };
        var progress = new Progress<ScanProgress>(p =>
        {
            ProgressText = p.Message;
            Progress = p.Total == 0 ? 0 : Math.Min(1, (double)p.Completed / p.Total);
            if (p.Message.StartsWith("Finished ", StringComparison.Ordinal)) ProgressLog.Insert(0, p.Message[9..]);
        });
        try
        {
            // One pass: the full execution history, then the tampering and bypass audits on top of it. Both halves of
            // the program show this one result, cut to the chosen period.
            var report = Core.Bypass.BypassScanner.Trim(await Core.Bypass.BypassScanner.RunAsync(options, argumentRules, progress, _cts.Token), SelectedWindow);
            LoadCombined(report, null);
            if (AutoSave) SaveReportNow();
        }
        catch (OperationCanceledException)
        {
            State = Result != null ? AppState.Results : AppState.Ready;
        }
        catch (Exception e)
        {
            Error = $"The scan failed: {e.Message}";
            State = AppState.Ready;
        }
    }

    public void Load(ScanResult result, string? fromFile)
    {
        Result = result;
        LoadedFrom = fromFile;
        AutoSaveStatus = null;
        BuildViews();
        Page = "Overview";
        State = AppState.Results;
        OnPropertyChanged(string.Empty);
    }

    /// <summary>Builds every table and count from <see cref="Result"/>.</summary>
    void BuildViews()
    {
        var result = Result!;
        // One findings list for the whole scan: the execution findings plus the tampering audits' own (the audits
        // repeat some execution findings; those are only listed once).
        var seen = result.Findings.Select(f => (f.Title, f.Path, f.TimeUtc)).ToHashSet();
        var findings = result.Findings.Concat(Combined?.Findings.Where(f => !seen.Contains((f.Title, f.Path, f.TimeUtc))) ?? [])
            .OrderByDescending(f => f.Severity).ThenByDescending(f => f.TimeUtc ?? DateTime.MinValue).ToList();

        _files = result.Files.Select(f => new FileRow(f)).ToList();
        _filePaths = _files.Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        FilesView = new ListCollectionView(_files) { Filter = o => FileFilter((FileRow)o) };


        TimelineView = new ListCollectionView(result.Timeline.Select(e => new EvidenceRow(e)).ToList())
        { Filter = o => TimelineFilter((EvidenceRow)o) };
        FindingsView = new ListCollectionView(findings.ToList()) { Filter = o => FindingFilter((Finding)o, false) };
        InconsistencyView = new ListCollectionView(findings.ToList()) { Filter = o => FindingFilter((Finding)o, true) };
        MemoryView = new ListCollectionView(result.MemoryHits.ToList()) { Filter = o => MemoryFilter((MemoryHit)o) };
        CommandsView = new ListCollectionView(result.Commands.Select(c => new CommandRow(c)).ToList())
        { Filter = o => CommandFilter((CommandRow)o) };

        HighCount = findings.Count(f => f.Severity == Severity.High);
        MediumCount = findings.Count(f => f.Severity == Severity.Medium);
        LowCount = findings.Count(f => f.Severity == Severity.Low);
        InconsistencyCount = findings.Count(f => InconsistencyCategories.Contains(f.Category) && !f.ByThisTool);
        var visible = _files.Where(f => !f.IsWindows && !f.IsThisTool).ToList();
        OwnTraceCount = _files.Count(f => f.IsThisTool) + findings.Count(f => f.ByThisTool && f.Path == null);
        ProgramCount = visible.Count(f => PagePreset("Programs", f));
        ExeCount = visible.Count(f => PagePreset("Executables", f));
        DllCount = visible.Count(f => PagePreset("Dlls", f));
        JarCount = visible.Count(f => PagePreset("Jars", f));
        DeletedCount = visible.Count(f => PagePreset("Deleted", f));
        CommandCount = result.Commands.Count;
        SuspiciousCommandCount = result.Commands.Count(c => c.Suspicion != null);
        TopFindings = findings.Where(f => !f.ByThisTool).Take(8).ToList();
        Checks = result.Checks
            .OrderByDescending(c => c.State switch { CheckState.Bad => 3, CheckState.Warning => 2, CheckState.Unknown => 1, _ => 0 })
            .ThenBy(c => c.Area).ToList();
        ProblemChecks = Checks.Where(c => c.State is CheckState.Bad or CheckState.Warning).ToList();
        ProblemCheckCount = ProblemChecks.Count;
        Sources = result.Sources;
        ClockChanges = result.ClockChanges;
        ServiceHistory = result.ServiceEvents.Take(200).Select(e => new ServiceHistoryRow(e.TimeUtc, e.Service, e.Change, !e.Suspicious)).ToList();
        SelectedFile = null;

        RefreshFilters();
        OnPropertyChanged(string.Empty);
    }

    // ---- filtering & sorting -----------------------------------------------------------------

    static bool PagePreset(string page, FileRow f) => page switch
    {
        "Programs" => f.Type != Core.Models.FileType.Dll &&
                      (f.Record.WasExecutedDirectly || (f.Type is Core.Models.FileType.Jar or Core.Models.FileType.Script && f.Record.WasLoaded)),
        "Executables" => f.Type == Core.Models.FileType.Exe,
        "Dlls" => f.Type == Core.Models.FileType.Dll,
        "Jars" => f.Type == Core.Models.FileType.Jar,
        "Deleted" => f.IsGone && f.Ran && f.Type != Core.Models.FileType.Other,
        _ => true,
    };

    bool FileFilter(FileRow f)
    {
        if (!PagePreset(Page, f)) return false;
        if (!IncludeWindows && f.IsWindows) return false;
        if (!ShowOwnTraces && f.IsThisTool) return false;
        if (FlaggedOnly && f.Severity == null) return false;
        if (GoneOnly && Page != "Deleted" && !f.IsGone) return false;
        if (RanOnly && !f.Ran) return false;
        return FileSearch.Length == 0 || f.SearchText.Contains(FileSearch.Trim().ToLowerInvariant(), StringComparison.Ordinal);
    }


    bool TimelineFilter(EvidenceRow e)
    {
        if (!TimelineIncludeWindows && e.IsWindows) return false;
        return TimelineSearch.Length == 0 || e.SearchText.Contains(TimelineSearch.Trim().ToLowerInvariant(), StringComparison.Ordinal);
    }

    bool FindingFilter(Finding f, bool inconsistenciesOnly)
    {
        if (inconsistenciesOnly && !InconsistencyCategories.Contains(f.Category)) return false;
        if (!ShowOwnTraces && f.ByThisTool) return false;
        if (FindingSeverity == "Leads" ? f.Severity < Severity.Medium : FindingSeverity != "All" && f.Severity.ToString() != FindingSeverity) return false;
        return FindingSearch.Length == 0 ||
               (f.Title + " " + f.Detail + " " + f.Path).Contains(FindingSearch.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    bool CommandFilter(CommandRow c)
    {
        if (SuspiciousOnly && !c.IsSuspicious) return false;
        if (CommandGroup != "All" && c.Group != CommandGroup) return false;
        return CommandSearch.Length == 0 || c.SearchText.Contains(CommandSearch.Trim().ToLowerInvariant(), StringComparison.Ordinal);
    }

    /// <summary>Files open sorted by Last run, newest first (rows that never ran last); a column click re-sorts as usual.
    /// Called by the view once the table has the new list, because a table resets the sort when its list changes.</summary>
    public void SortFilesByLastRun()
    {
        using (FilesView.DeferRefresh())
        {
            FilesView.SortDescriptions.Clear();
            FilesView.SortDescriptions.Add(new SortDescription(nameof(FileRow.LastRunKey), ListSortDirection.Descending));
            FilesView.SortDescriptions.Add(new SortDescription(nameof(FileRow.LastActivityKey), ListSortDirection.Descending));
        }
    }

    void Debounce()
    {
        _filterTimer.Stop();
        _filterTimer.Start();
    }

    // Refreshing a view makes WPF re-lay-out its table even while that page is hidden (over a second
    // for a few thousand rows), so only the visible page's view is refreshed; the rest are marked
    // stale and refreshed when their page is opened.
    readonly HashSet<string> _stale = new();

    ListCollectionView? ViewFor(string key) => key switch
    {
        "Files" => FilesView,
        "Timeline" => TimelineView,
        "Findings" => FindingsView,
        "Inconsistencies" => InconsistencyView,
        "Memory" => MemoryView,
        "Commands" => CommandsView,
        _ => null,
    };

    string ViewKey(string page) => FilePages.ContainsKey(page) ? "Files" : page;

    void RefreshFilters()
    {
        foreach (var key in new[] { "Files", "Timeline", "Findings", "Inconsistencies", "Memory", "Commands" }) _stale.Add(key);
        RefreshCurrent();
    }

    void RefreshCurrent()
    {
        var key = ViewKey(Page);
        if (_stale.Remove(key) && ViewFor(key) is { } view)
        {
            view.Refresh();
            if (key == "Files") VisibleFiles = view.Count;
            else if (key == "Timeline") VisibleTimeline = view.Count;
            else if (key == "Commands") VisibleCommands = view.Count;
        }
    }

    // ---- navigation ------------------------------------------------------------------------

    /// <summary>"Page" or "Page:Severity" (e.g. "Findings:High" from an overview card).</summary>
    void Navigate(string? target)
    {
        if (string.IsNullOrEmpty(target)) return;
        if (target == "Tamper" || target.StartsWith("Tamper:", StringComparison.Ordinal))
        {
            NavPage = target == "Tamper" ? "Tamper:Overview" : target;
            return;
        }
        var parts = target.Split(':');
        if (parts.Length == 2 && parts[0] is "Findings" or "Inconsistencies") FindingSeverity = parts[1];
        else if (parts[0] is "Findings") FindingSeverity = "Leads";
        else if (parts[0] is "Inconsistencies") FindingSeverity = "All";
        if (parts.Length == 2 && parts[0] == "Commands" && parts[1] == "Suspicious") SuspiciousOnly = true;
        Page = parts[0];
    }

    void ShowFile(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        var row = _files.FirstOrDefault(f => string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase));
        if (row == null) return;
        _fileSearch = "";
        _flaggedOnly = _goneOnly = _ranOnly = false;
        _includeWindows |= row.IsWindows;
        _showOwnTraces |= row.IsThisTool;
        foreach (var p in new[] { nameof(FileSearch), nameof(FlaggedOnly), nameof(GoneOnly), nameof(RanOnly), nameof(IncludeWindows), nameof(ShowOwnTraces) })
            OnPropertyChanged(p);
        string page = row.Type switch
        {
            Core.Models.FileType.Dll => "Dlls",
            Core.Models.FileType.Jar => "Jars",
            Core.Models.FileType.Exe => "Executables",
            _ => PagePreset("Programs", row) ? "Programs" : "Deleted",
        };
        Page = page;
        RefreshFilters();
        if (FilesView.Contains(row)) SelectedFile = row;
    }

    // ---- actions -----------------------------------------------------------------------------

    static void Copy(string? text)
    {
        if (string.IsNullOrEmpty(text)) return;
        try { Clipboard.SetText(text); }
        catch (System.Runtime.InteropServices.COMException) { /* clipboard busy; user can retry */ }
    }

    static void OpenLocation(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            if (File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            else if (Path.GetDirectoryName(path) is { } dir && Directory.Exists(dir)) Process.Start("explorer.exe", $"\"{dir}\"");
            else MessageBox.Show("Neither the file nor its folder exists any more.", "History Parser", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Win32Exception) { }
    }

    /// <summary>Opens the hash on VirusTotal in the default browser. Only on an explicit click.</summary>
    static void LookUp(string? sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return;
        try { Process.Start(new ProcessStartInfo($"https://www.virustotal.com/gui/file/{sha256}") { UseShellExecute = true }); }
        catch (Win32Exception) { }
    }

    // ---- private details ------------------------------------------------------------------------

    bool _hidePrivate;
    /// <summary>Exports mask the PC and user names and drop personal history (see <see cref="Redactor"/>).</summary>
    public bool HidePrivate { get => _hidePrivate; set { if (Set(ref _hidePrivate, value)) Tamper.HidePrivate = value; } }

    /// <summary>True when the loaded report was already saved with private details hidden.</summary>
    public bool ShowingRedactedReport => Result?.PrivateDetailsHidden == true;

    // With private details hidden the computer name stays out of the file name too.
    string DefaultFileName(string suffix, string ext) => HidePrivate || ShowingRedactedReport
        ? $"HistoryParser-{Result!.StartedUtc.ToLocalTime():yyyyMMdd-HHmm}{suffix}-private-hidden.{ext}"
        : $"HistoryParser-{Result!.Machine.ComputerName}-{Result.StartedUtc.ToLocalTime():yyyyMMdd-HHmm}{suffix}.{ext}";

    void Export(string kind)
    {
        if (Result == null) return;
        var dialog = new SaveFileDialog
        {
            FileName = DefaultFileName("", kind),
            Filter = kind == "html" ? "HTML report (*.html)|*.html" : "History Parser report (*.json)|*.json",
        };
        if (dialog.ShowDialog() != true) return;
        try { WriteReport(kind, dialog.FileName); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show($"Could not save the report: {e.Message}", "History Parser", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Exports exactly what the current page shows (after filters and sorting).</summary>
    void ExportCsv()
    {
        if (Result == null) return;
        if (Page == "Tamper")
        {
            Tamper.ExportCsvCommand.Execute(null); // the tampering page's own table
            return;
        }
        (string Name, string[] Header, IEnumerable<string?[]> Rows) table = Page switch
        {
            "Commands" => ("commands", ["Time (local)", "Group", "Source", "User", "Command", "Suspicious", "Detail"],
                CommandsView.Cast<CommandRow>().Select(c => new[]
                    { Local(c.Time), c.Group, c.Source, c.User, c.Command, c.Suspicion, c.Detail })),
            "Timeline" => ("timeline", ["Time (local)", "Source", "Event", "File / item", "Detail", "Origin"],
                TimelineView.Cast<EvidenceRow>().Select(e => new[] { Local(e.Time), e.SourceText, e.KindText, e.Path, e.Detail, e.Origin })),
            "Findings" or "Inconsistencies" => (Page.ToLowerInvariant(), ["Severity", "Category", "Title", "Time (local)", "Path", "Detail"],
                (Page == "Findings" ? FindingsView : InconsistencyView).Cast<Finding>().Select(f => new[]
                    { f.Severity.ToString(), Display.Category(f.Category), f.Title, Local(f.TimeUtc), f.Path, f.Detail })),
            "Memory" => ("memory", ["Process", "PID", "Path", "Recorded time", "Raw"],
                MemoryView.Cast<MemoryHit>().Select(m => new[] { m.Process, m.Pid.ToString(), m.Path, m.RecordedTime, m.Raw })),
            _ => (IsFilePage ? Page.ToLowerInvariant() : "files",
                ["Flag", "Name", "Type", "Last run (local)", "Run count", "Status", "Status detail", "Sources", "Signature", "Signer", "SHA-256", "Path"],
                (IsFilePage ? FilesView.Cast<FileRow>() : _files).Select(f => new[]
                {
                    f.Severity?.ToString(), f.Name, f.TypeText, Local(f.LastRun), f.RunCount?.ToString(), Display.Status(f.Status),
                    f.StatusDetail, f.SourcesText, Display.Signature(f.Signature), f.Signer, f.Sha256, f.Path,
                })),
        };

        if (HidePrivate)
        {
            // Same rules as the HTML/JSON redaction, applied to the rows on screen.
            var clean = Redactor.CreateCleaner(Result);
            var rows = Page switch
            {
                "Commands" => CommandsView.Cast<CommandRow>().Where(c => c.IsSuspicious).Select(c => new[]
                    { Local(c.Time), c.Group, c.Source, string.IsNullOrEmpty(c.User) ? "" : Redactor.UserMask, c.Command, c.Suspicion, c.Detail }),
                "Timeline" => TimelineView.Cast<EvidenceRow>().Where(e => !Redactor.IsTypedHistory(e.Item))
                    .Select(e => new[] { Local(e.Time), e.SourceText, e.KindText, e.Path, e.Detail, e.Origin }),
                "Memory" => MemoryView.Cast<MemoryHit>().Select(m => new[] { m.Process, m.Pid.ToString(), m.Path, m.RecordedTime, "" }),
                _ => table.Rows,
            };
            table = (table.Name, table.Header, rows.Select(r => r.Select(cell => cell == null ? null : clean(cell)).ToArray()));
        }

        var dialog = new SaveFileDialog { FileName = DefaultFileName("-" + table.Name, "csv"), Filter = "CSV (*.csv)|*.csv" };
        if (dialog.ShowDialog() != true) return;
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", table.Header.Select(Csv)));
        foreach (var row in table.Rows) sb.AppendLine(string.Join(",", row.Select(Csv)));
        try { File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show($"Could not save the CSV: {e.Message}", "History Parser", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        static string? Local(DateTime? t) => t?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        static string Csv(string? s)
        {
            s ??= "";
            // Leading = + - @ would be run as a formula by Excel; prefix a quote so the cell stays text.
            if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@') s = "'" + s;
            return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        }
    }

    void OpenReport()
    {
        var dialog = new OpenFileDialog { Filter = "History Parser report (*.json)|*.json" };
        if (dialog.ShowDialog() != true) return;
        try { OpenFile(dialog.FileName); }
        catch (Exception e)
        {
            Error = $"Could not open {Path.GetFileName(dialog.FileName)}: {e.Message}";
            MessageBox.Show(Error, "History Parser", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    static void RestartElevated()
    {
        if (App.TryRelaunchElevated()) Application.Current.Shutdown();
    }
}
