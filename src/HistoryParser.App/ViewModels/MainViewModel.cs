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
using HistoryParser.Core.Analysis;
using HistoryParser.Core.Export;
using HistoryParser.Core.Models;
using HistoryParser.Core.Native;
using HistoryParser.Core.Util;

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
        ["Jars"] = ("Java archives", "Every .jar — run by Java, opened by another program, or seen in memory and caches. The How column says which."),
        ["Scripts"] = ("Scripts", "Every script an interpreter opened or a source mentions: .bat, .cmd, .ps1, .vbs, .py, .ahk and the like."),
        ["Drivers"] = ("Drivers", "Kernel drivers (.sys): the ones loaded now, the ones installed as a service, and the ones the journal saw created or deleted."),
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
        SetPeriodCommand = new RelayCommand(p => SetPeriod(p as string), _ => State == AppState.Results);
        PickGameCommand = new RelayCommand(p => PickGame(p as string), _ => State == AppState.Results);
        CopyCommand = new RelayCommand(p => Copy(p as string), p => !string.IsNullOrEmpty(p as string));
        OpenLocationCommand = new RelayCommand(p => OpenLocation(p as string), p => p is string s && s.Length > 2 && s[1] == ':');
        VirusTotalCommand = new RelayCommand(p => LookUp(p as string), p => !string.IsNullOrEmpty(p as string));
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
        BuildRead = ReadBuild();
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
            OnPropertyChanged(nameof(FindingsNav));
            OnPropertyChanged(nameof(IsFindingPage));
            OnPropertyChanged(nameof(ActiveFindings));
            OnPropertyChanged(nameof(IsFilePage));
            OnPropertyChanged(nameof(FilePageTitle));
            OnPropertyChanged(nameof(FilePageSubtitle));
            OnPropertyChanged(nameof(ShowGoneToggle));
            OnPropertyChanged(nameof(ShowRanToggle));
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

    /// <summary>Every finding, and the ones about dates that disagree: two tabs of one list, so one sidebar entry.</summary>
    public bool IsFindingPage => Page is "Findings" or "Inconsistencies";
    public bool FindingsNav { get => IsFindingPage; set { if (value && !IsFindingPage) Page = "Findings"; } }
    /// <summary>The list the findings page shows for the tab picked.</summary>
    public ListCollectionView ActiveFindings => Page == "Inconsistencies" ? InconsistencyView : FindingsView;

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
        // What a change of period is cut from. A saved report holds only the period it was saved with.
        _full = report;
        _fullSince = report.History.SinceUtc;
        _gameStart = DefaultGame(report.History.Machine);
        Show(report, fromFile);
        MarkWhole();
    }

    /// <summary>The period on screen is the widest this scan holds: what a narrower one is measured against.</summary>
    void MarkWhole()
    {
        _wholeKey = Result?.Window.ToString() ?? "";
        _wholeFlagged = FlaggedFindingCount;
        _wholePrograms = ProgramCount;
        OnPropertyChanged(nameof(FlaggedEarlier));
        OnPropertyChanged(nameof(ProgramsEarlier));
        OnPropertyChanged(nameof(EarlierText));
        OnPropertyChanged(nameof(WholePeriodKey));
    }

    void Show(Core.Bypass.BypassReport report, string? fromFile)
    {
        Combined = report;
        Load(report.History, fromFile);
        Tamper.Load(report);
        BuildGames();
        BuildPeriods();
        OnPropertyChanged(string.Empty);
    }

    // ---- period -------------------------------------------------------------------------------
    // The scan reads and cross-checks everything; the period only decides what is listed. So a narrower period is cut from
    // the scan already made. A wider one than was scanned needs the scan again: files outside the scanned period were not
    // hashed or checked for a signature, and listing them unchecked would bury the list.

    /// <summary>The scan before a period cut it.</summary>
    Core.Bypass.BypassReport? _full;
    /// <summary>How far back <see cref="_full"/> goes with every file checked; null = all the way.</summary>
    DateTime? _fullSince;

    /// <param name="Instant">Cut from the scan already made; otherwise choosing it scans again.</param>
    public sealed record PeriodRow(string Key, string Label, string Start, bool IsCurrent, bool Instant, bool Enabled, string Tip)
    {
        /// <summary>Choosing it starts the scan again.</summary>
        public bool Rescans => Enabled && !Instant;
    }

    static readonly TimeWindow[] PeriodOrder =
        [TimeWindow.Game, TimeWindow.SignIn, TimeWindow.ThisBoot, TimeWindow.Day, TimeWindow.ThreeDays, TimeWindow.Week, TimeWindow.Month, TimeWindow.All];

    public IReadOnlyList<PeriodRow> Periods { get; private set; } = [];

    string _wholeKey = "";
    int _wholeFlagged;
    /// <summary>The widest period the scan on screen holds.</summary>
    public string WholePeriodKey => _wholeKey;
    /// <summary>
    /// Flagged findings the scan holds that the period on screen leaves out because they are dated before it. A narrower
    /// period is a way to read less at a time, never a way for older findings to go unseen: this count stays in the
    /// title bar on every page, and choosing it shows the whole scan again.
    /// </summary>
    public int FlaggedEarlier => Result == null || _full == null ? 0 : Math.Max(0, _wholeFlagged - FlaggedFindingCount);
    int _wholePrograms;
    /// <summary>
    /// Programs and files the scan lists that the period on screen leaves out (the same count as the Programs page). A
    /// program that ran before the period is usually not flagged, so the count of flagged findings alone would let it go
    /// unseen; restarting the game costs a player nothing.
    /// </summary>
    public int ProgramsEarlier => Result == null || _full == null ? 0 : Math.Max(0, _wholePrograms - ProgramCount);
    /// <summary>What the period on screen leaves out, for the title bar; empty when it leaves nothing out.</summary>
    public string EarlierText => (ProgramsEarlier, FlaggedEarlier) switch
    {
        (0, 0) => "",
        (0, var flagged) => $"{flagged} flagged before this period",
        (var ran, 0) => $"{ran:N0} {(ran == 1 ? "program" : "programs")} before this period",
        var (ran, flagged) => $"{ran:N0} {(ran == 1 ? "program" : "programs")}  ·  {flagged} flagged before this period",
    };

    // ---- a scan without administrator rights ----------------------------------------------------
    /// <summary>The scan on screen was made without administrator rights: its lists are incomplete, on every page.</summary>
    public bool ScanPartial => Result is { Machine.IsElevated: false };
    public string PartialText => Result == null ? "" :
        (LoadedFrom == null ? "Scanned without administrator rights." : "This report was made without administrator rights.") +
        $" Not read: {NotRead(Result)}. A program that ran can be missing from every list.";

    /// <summary>
    /// What a scan without administrator rights did not read: the sources that failed, by name, and the two that are read
    /// inside other checks and are closed to an ordinary user.
    /// </summary>
    static string NotRead(ScanResult result)
    {
        var unread = result.Sources.Where(s => !s.Success).Select(s => s.Name).ToList();
        return string.Join(", ", unread.Take(5).Concat(unread.Count > 5 ? [$"{unread.Count - 5} more sources"] : []).Concat(["the Security log", "service memory"]));
    }

    // ---- this program ---------------------------------------------------------------------------
    // Which build is on screen: its version and the SHA-256 of the file it was started from, at the end of the title bar on
    // every page. That is the program's word about itself: a changed build can show any hash, so it tells honest copies
    // apart and proves nothing more.

    string? _ownHash;
    /// <summary>SHA-256 of the file this program was started from, lower case; null until it has been read, and when it cannot be.</summary>
    public string? OwnHash => _ownHash;

    /// <summary>Done once the file has been hashed. It is tens of megabytes, so that is kept off the window's thread.</summary>
    public Task BuildRead { get; }

    bool _hashRead;

    async Task ReadBuild()
    {
        _ownHash = await Task.Run(() => SelfTraces.OwnHash);
        _hashRead = true;
        foreach (var name in new[] { nameof(OwnHash), nameof(OwnHashShort), nameof(OwnHashLines), nameof(OwnHashNote), nameof(ReportBuildText), nameof(ReportBuildLines) })
            OnPropertyChanged(name);
        CommandManager.InvalidateRequerySuggested();
    }

    public string OwnFile => Environment.ProcessPath ?? "";
    public string OwnFileName => Path.GetFileName(OwnFile);

    /// <summary>The title bar's chip: the first eight characters, enough to tell one release from another at a glance.</summary>
    public string OwnHashShort => OwnHash is { Length: >= 8 } hash ? hash[..8] : "";

    /// <summary>The whole hash in groups of eight, four to a line, so it can be compared with another by eye.</summary>
    public string OwnHashLines => Grouped(OwnHash);

    internal static string Grouped(string? hash) => string.IsNullOrEmpty(hash) ? "" :
        string.Join(Environment.NewLine, hash.Chunk(8).Select(group => new string(group)).Chunk(4).Select(line => string.Join(" ", line)));

    /// <summary>What limits the hash, when something does: a build whose code is not in the hashed file, or a file that could not be read.</summary>
    public string OwnHashNote =>
        !_hashRead ? "" :
        OwnHash == null ? "The program's file could not be read, so there is no hash to show." :
        SelfTraces.OneFile ? "" : "Developer build: its code is in libraries beside this file, which the hash does not cover.";

    /// <summary>The hash a saved report says its scan was made with; null for a scan made now, and for a report that does not say.</summary>
    string? ReportBuild => LoadedFrom != null && Result is { Machine.ToolSha256: { Length: > 0 } made } ? made : null;

    /// <summary>For a saved report: whether the build that made it is the one showing it.</summary>
    public string ReportBuildText => ReportBuild is not { } made ? "" :
        SelfTraces.OneFile && string.Equals(made, OwnHash, StringComparison.OrdinalIgnoreCase) ? "Says it was made by this build." : "Says it was made by another build:";
    public string ReportBuildLines => ReportBuildText.EndsWith(':') ? Grouped(ReportBuild) : "";

    public string PeriodLabel => Result == null ? "" :
        TimeWindows.Label(Result.Window) + (Result.Window == TimeWindow.Game && Result.SinceUtc is { } from ? $" {from.ToLocalTime():HH:mm}" : "");

    // ---- games --------------------------------------------------------------------------------
    // Every game the scan found is listed with what it was started with, so the reader can see which one a period is
    // measured from, and pick another. The earliest running game is the default: the widest choice.

    /// <summary>The start "since the game started" is measured from; null when no game is on record.</summary>
    DateTime? _gameStart;
    public DateTime? GameStartUtc => _gameStart;
    /// <summary>The program of the game picked, to find its own row in a list.</summary>
    public string GamePath => _full?.History.Machine.Games.FirstOrDefault(g => g.StartUtc == _gameStart)?.Path ?? "";

    public sealed record GameRow(string Key, string Time, string Title, string Detail, bool Running, bool IsPicked, bool Enabled, string Tip);
    public IReadOnlyList<GameRow> Games { get; private set; } = [];
    public RelayCommand PickGameCommand { get; }
    /// <summary>Raised to bring the game's start into view in the list on screen.</summary>
    public event Action? JumpToGameRequested;

    /// <summary>The earliest game that is running; with none running, the most recent start on record.</summary>
    static DateTime? DefaultGame(MachineInfo machine) => machine.GameStartUtc ?? machine.Games.FirstOrDefault(g => !g.Unrecognised)?.StartUtc;

    void BuildGames()
    {
        var machine = _full?.History.Machine;
        if (machine == null) { Games = []; return; }
        // A report saved before the games were listed still names the one it found.
        var games = machine.Games.Count > 0 ? machine.Games
            : machine.GameStartUtc is { } only ? [new GameStart { StartUtc = only, Program = machine.GameProgram, Pid = 0, How = "Running" }] : [];
        Games = games.Select(g =>
        {
            bool held = _fullSince == null || g.StartUtc >= _fullSince;
            string title = g.Pid is > 0 ? $"{g.Program}  ·  pid {g.Pid}" : g.Pid == null ? $"{g.Program}  ·  not running now" : g.Program;
            string detail = string.Join("  ·  ", new[]
            {
                g.Unrecognised ? "Java, not recognised as the game" : "", g.Runs.Length > 0 ? Path.GetFileName(g.Runs) : "", g.Version, g.Account, g.GameDir,
            }.Where(s => s.Length > 0));
            string tip = string.Join(Environment.NewLine, new[]
            {
                g.Path, g.Runs.Length > 0 ? "Runs: " + g.Runs : "", g.GameDir.Length > 0 ? "Game folder: " + g.GameDir : "", g.Version.Length > 0 ? "Version: " + g.Version : "",
                g.Account.Length > 0 ? "Account: " + g.Account : "",
                g.Unrecognised ? "A Java program running at the scan, without the game's arguments or its graphics library. Listed in case it is the game, started in a way that hides them."
                    : g.How == "Prefetch" ? "An earlier start, from Prefetch (it keeps the last eight runs of a program)." : "Running at the scan.",
                held ? "Click to list everything since this start." : "Before the period that was scanned: scan a wider period to list from it.",
            }.Where(s => s.Length > 0));
            return new GameRow(g.StartUtc.Ticks.ToString(), $"{g.StartUtc.ToLocalTime():d MMM  HH:mm}", title, detail, g.Pid != null,
                Result?.Window == TimeWindow.Game && _gameStart == g.StartUtc, held, tip);
        }).ToList();
    }

    void PickGame(string? key)
    {
        if (_full == null || Games.FirstOrDefault(g => g.Key == key) is not { Enabled: true, IsPicked: false } || !long.TryParse(key, out long ticks)) return;
        _gameStart = new DateTime(ticks, DateTimeKind.Utc);
        string page = NavPage;
        Show(Core.Bypass.BypassScanner.Trim(_full, TimeWindow.Game, _gameStart), LoadedFrom);
        NavPage = page;
    }

    public string PcName => Result?.Machine.ComputerName ?? "";
    public string ScannedAt => Result == null ? "" : $"scanned {Result.StartedUtc.ToLocalTime():HH:mm}";
    public RelayCommand SetPeriodCommand { get; }

    static string Capital(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];

    void BuildPeriods()
    {
        if (_full == null || Result == null) { Periods = []; return; }
        var machine = _full.History.Machine;
        var rows = new List<PeriodRow>();
        foreach (var window in PeriodOrder)
        {
            // "Since the game started" is measured from the game picked on the Overview: the earliest running one unless another was chosen.
            bool game = window == TimeWindow.Game;
            bool known = game ? _gameStart != null : TimeWindows.Effective(window, machine) == window;
            var since = game ? _gameStart : TimeWindows.Since(window, _full.History.StartedUtc, machine);
            bool held = _fullSince == null || since >= _fullSince;
            bool rescan = LoadedFrom == null;
            rows.Add(new PeriodRow(window.ToString(), Capital(TimeWindows.Label(window)),
                !known ? window == TimeWindow.Game ? "no game on record" : "not known" : since is { } s ? $"from {s.ToLocalTime():d MMM HH:mm}" : "",
                Result.Window == window, held, known && (held || rescan),
                !known ? "Its start is not known on this PC." :
                held ? "Cut from the scan already made." :
                rescan ? "Wider than the period that was scanned: choosing it scans again, so the older files are checked too."
                       : "The saved report does not hold this period."));
        }
        Periods = rows;
    }

    async void SetPeriod(string? key)
    {
        if (Periods.FirstOrDefault(p => p.Key == key) is not { Enabled: true, IsCurrent: false } row || !Enum.TryParse<TimeWindow>(key, out var window)) return;
        if (!row.Instant)
        {
            ScanWindow = row.Key;
            await ScanAsync();
            return;
        }
        // Stay on the page in view: the period changes what the page lists, not which page it is.
        string page = NavPage;
        Show(Core.Bypass.BypassScanner.Trim(_full!, window, _gameStart), LoadedFrom);
        NavPage = page;
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
            _full = null;
            _gameStart = null;
            Games = [];
            Periods = [];
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

    /// <summary>Which PC, which period and when, for the title bar: the three things a result means nothing without.</summary>
    public string ContextLine => Result == null ? "" :
        $"{Result.Machine.ComputerName}  ·  {TimeWindows.Label(Result.Window)}  ·  scanned {Result.StartedUtc.ToLocalTime():HH:mm}";

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
    public int ScriptCount { get; private set; }
    public int DriverCount { get; private set; }
    public int DeletedCount { get; private set; }
    public int CommandCount { get; private set; }
    public int SuspiciousCommandCount { get; private set; }
    public int ProblemCheckCount { get; private set; }
    /// <summary>Integrity &amp; services page: sources with a problem plus evidence services that are off or were tampered with.</summary>
    public int IntegrityProblems => ProblemCheckCount + Tamper.ProblemServices;
    public int FlaggedFindingCount => HighCount + MediumCount;
    public IReadOnlyList<Finding> TopFindings { get; private set; } = [];

    // ---- overview -----------------------------------------------------------------------------
    // One row per area of the scan, the session's reference times, and the period's activity in numbers. Each is a way in
    // to the page that holds the detail; none repeats that page.

    /// <summary>An area of the scan. Every kind of finding belongs to exactly one, so the rows together cover every finding.</summary>
    sealed record Area(string Key, string Name, string Target, FindingCategory[] Categories);

    static readonly Area[] AreaList =
    [
        new("recording", "Recording", "Integrity", [FindingCategory.Integrity, FindingCategory.ServiceTampering, FindingCategory.Boot, FindingCategory.Hardware]),
        new("logs", "Event logs", "Tamper:Logs", [FindingCategory.LogTampering]),
        new("clock", "Clock", "Integrity", [FindingCategory.ClockTampering]),
        new("antivirus", "Antivirus", "Tamper:Antivirus", [FindingCategory.Defender]),
        new("wiping", "Evidence wiping", "Findings:Area:wiping", [FindingCategory.AntiForensics]),
        new("programs", "Programs and files", "Findings:Area:programs",
            [FindingCategory.Deletion, FindingCategory.TimelineInconsistency, FindingCategory.Process, FindingCategory.Injection, FindingCategory.Driver, FindingCategory.Persistence]),
        new("arguments", "Arguments", "Tamper:Arguments", [FindingCategory.Arguments]),
        new("usb", "USB", "Tamper:Usb", [FindingCategory.Usb]),
    ];

    /// <summary>The area a kind of finding belongs to: typed in a findings search as "area:programs".</summary>
    internal static string AreaKey(FindingCategory category) => AreaList.FirstOrDefault(a => a.Categories.Contains(category))?.Key ?? "other";

    /// <summary>What a search of the findings looks through: the finding, its kind and its area.</summary>
    static string FindingText(Finding f) => $"{f.Title} {f.Detail} {f.Path} {Display.Category(f.Category)} area:{AreaKey(f.Category)}";

    public sealed record AreaRow(string Name, CheckState State, string Text, int Count, string Target);
    public sealed record MarkRow(string Time, string What, string Detail, CheckState State);
    public sealed record ActivityRow(string Label, int Count, string Unit, string Target);

    public IReadOnlyList<AreaRow> Areas { get; private set; } = [];
    public IReadOnlyList<MarkRow> SessionMarks { get; private set; } = [];
    public IReadOnlyList<ActivityRow> Activity { get; private set; } = [];

    static List<AreaRow> BuildAreas(ScanResult result, IReadOnlyList<Finding> findings)
    {
        var rows = new List<AreaRow>();
        var unread = result.Sources.Where(s => !s.Success).Select(s => s.Name).ToList();
        rows.Add(!result.Machine.IsElevated
            ? new AreaRow("Scan", CheckState.Bad, $"Not administrator · not read: {NotRead(result)}", unread.Count, "Integrity")
            : unread.Count > 0
                ? new AreaRow("Scan", CheckState.Warning, $"Could not be read: {string.Join(", ", unread.Take(4))}{(unread.Count > 4 ? " …" : "")}", unread.Count, "Integrity")
                : new AreaRow("Scan", CheckState.Ok, $"Administrator · all {result.Sources.Count} sources read", 0, "Integrity"));

        foreach (var area in AreaList)
        {
            // Findings are strongest first, so the first of an area is the one to name.
            var flagged = findings.Where(f => !f.ByThisTool && f.Severity >= Severity.Medium && area.Categories.Contains(f.Category)).ToList();
            int low = findings.Count(f => !f.ByThisTool && f.Severity == Severity.Low && area.Categories.Contains(f.Category));
            // Checks that came back with a problem but raised no finding (a source that could not be asked, a setting off
            // its default) belong to the recording row, so a row of green never hides one. The administrator check is the
            // Scan row's.
            var notes = area.Key != "recording" ? [] :
                result.Checks.Where(c => c.State is CheckState.Bad or CheckState.Warning && c.Name != "Running as administrator").ToList();
            string clear = "Nothing flagged" + (low > 0 ? $" · {low} low" : "") + (notes.Count > 0 ? $" · {notes.Count} {(notes.Count == 1 ? "check" : "checks")} with a note" : "");
            rows.Add(flagged.Count == 0
                ? new AreaRow(area.Name, notes.Any(c => c.State == CheckState.Bad) ? CheckState.Warning : CheckState.Ok, clear, 0, area.Target)
                : new AreaRow(area.Name, flagged[0].Severity == Severity.High ? CheckState.Bad : CheckState.Warning,
                    flagged[0].Title + (flagged.Count > 1 ? $"  ·  and {flagged.Count - 1} more" : ""), flagged.Count, area.Target));
        }
        return rows;
    }

    List<MarkRow> BuildMarks(ScanResult result)
    {
        var marks = Combined?.Session is { Count: > 0 } session ? session :
        [
            // A report saved before the session's times were gathered: the three it does hold.
            .. result.Machine.OsInstallUtc is { } installed ? new[] { new Core.Bypass.SessionMark { What = "Windows installed", TimeUtc = installed } } : [],
            new Core.Bypass.SessionMark { What = "PC started", TimeUtc = result.Machine.BootTimeUtc },
            new Core.Bypass.SessionMark { What = "Scanned", TimeUtc = result.StartedUtc },
        ];
        string When(DateTime? utc)
        {
            if (utc is not { } t) return "—";
            var local = t.ToLocalTime();
            return (result.StartedUtc - t).TotalDays > 300 ? local.ToString("d MMM yyyy") : local.ToString("d MMM  HH:mm");
        }
        return marks.Select(m => new MarkRow(When(m.TimeUtc), m.What, m.Detail, m.State)).ToList();
    }
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

    CommandRow? _selectedCommand;
    /// <summary>The command whose full text the panel beside the table shows: a row has room for one line of it.</summary>
    public CommandRow? SelectedCommand { get => _selectedCommand; set => Set(ref _selectedCommand, value); }

    Finding? _selectedFinding;
    /// <summary>The finding whose whole text the panel beside the list shows.</summary>
    public Finding? SelectedFinding { get => _selectedFinding; set => Set(ref _selectedFinding, value); }

    // ---- filters ------------------------------------------------------------------------------
    // One model on every page. A chip narrows the list to rows that are something ("Flagged", "Unsigned") and carries
    // how many rows that is, so it never has to be tried to see whether it is worth trying. What is kept out of the way
    // by default sits apart, behind one "N hidden" button that names each kind and how many, with a switch to show it.

    // File filters (shared by the file tabs)
    string _fileSearch = "";
    public string FileSearch { get => _fileSearch; set { if (Set(ref _fileSearch, value)) { _fileQuery = SearchQuery.Parse(value); Debounce(); } } }
    SearchQuery _fileQuery = SearchQuery.Empty;
    bool _flaggedOnly;
    public bool FlaggedOnly { get => _flaggedOnly; set { if (Set(ref _flaggedOnly, value)) RefreshFilters(); } }
    bool _unsignedOnly;
    /// <summary>Only programs and libraries with no signature, or one that does not verify.</summary>
    public bool UnsignedOnly { get => _unsignedOnly; set { if (Set(ref _unsignedOnly, value)) RefreshFilters(); } }
    bool _goneOnly;
    public bool GoneOnly { get => _goneOnly; set { if (Set(ref _goneOnly, value)) RefreshFilters(); } }
    bool _ranOnly;
    public bool RanOnly { get => _ranOnly; set { if (Set(ref _ranOnly, value)) RefreshFilters(); } }
    bool _includeWindows;
    public bool IncludeWindows { get => _includeWindows; set { if (Set(ref _includeWindows, value)) RefreshFilters(); } }
    bool _showOwnTraces;
    /// <summary>Show the traces this suite left itself (hidden by default; never counted).</summary>
    public bool ShowOwnTraces { get => _showOwnTraces; set { if (Set(ref _showOwnTraces, value)) RefreshFilters(); } }
    bool _showRepeats;
    /// <summary>Show every copy of a library on its own row, instead of one row with a count (see Core.Analysis.Repeats).</summary>
    public bool ShowRepeats { get => _showRepeats; set { if (Set(ref _showRepeats, value)) RefreshFilters(); } }
    public int OwnTraceCount { get; private set; }

    // How many rows of the tab in view each chip would leave, and how many each kind of hidden row is.
    int _flaggedFiles, _unsignedFiles, _goneFiles, _ranFiles, _routineCount, _ownFiles, _repeatFiles;
    public int FlaggedFiles { get => _flaggedFiles; private set => Set(ref _flaggedFiles, value); }
    public int UnsignedFiles { get => _unsignedFiles; private set => Set(ref _unsignedFiles, value); }
    public int GoneFiles { get => _goneFiles; private set => Set(ref _goneFiles, value); }
    public int RanFiles { get => _ranFiles; private set => Set(ref _ranFiles, value); }
    /// <summary>How many files of the tab in view are folded as routine (shown on the switch, so nothing is hidden silently).</summary>
    public int RoutineCount { get => _routineCount; private set => Set(ref _routineCount, value); }
    public int OwnFiles { get => _ownFiles; private set => Set(ref _ownFiles, value); }
    public int RepeatFiles { get => _repeatFiles; private set => Set(ref _repeatFiles, value); }
    /// <summary>Rows of this tab that are out of view right now, of every kind.</summary>
    public int HiddenFiles => (IncludeWindows ? 0 : RoutineCount) + (ShowOwnTraces ? 0 : OwnFiles) + (ShowRepeats ? 0 : RepeatFiles);
    /// <summary>"Ran" says nothing on the tabs that only list what ran.</summary>
    public bool ShowRanToggle => Page is not ("Programs" or "Deleted");

    // Findings filters: each severity on or off. High and Medium by default: Low findings are context, one click away.
    bool _showHigh = true, _showMedium = true, _showLow;
    public bool ShowHigh { get => _showHigh; set { if (Set(ref _showHigh, value)) RefreshFilters(); } }
    public bool ShowMedium { get => _showMedium; set { if (Set(ref _showMedium, value)) RefreshFilters(); } }
    public bool ShowLow { get => _showLow; set { if (Set(ref _showLow, value)) RefreshFilters(); } }
    void ShowSeverities(bool high, bool medium, bool low)
    {
        _showHigh = high; _showMedium = medium; _showLow = low;
        OnPropertyChanged(nameof(ShowHigh)); OnPropertyChanged(nameof(ShowMedium)); OnPropertyChanged(nameof(ShowLow));
        RefreshFilters();
    }
    int _highShown, _mediumShown, _lowShown, _hiddenFindings;
    /// <summary>Findings of each severity on the tab in view (all findings, or the ones about dates), after the search.</summary>
    public int HighOnTab { get => _highShown; private set => Set(ref _highShown, value); }
    public int MediumOnTab { get => _mediumShown; private set => Set(ref _mediumShown, value); }
    public int LowOnTab { get => _lowShown; private set => Set(ref _lowShown, value); }
    /// <summary>Findings about this suite's own traces on the tab in view.</summary>
    public int OwnFindings { get => _hiddenFindings; private set => Set(ref _hiddenFindings, value); }
    public int HiddenFindings => ShowOwnTraces ? 0 : OwnFindings;
    string _findingSearch = "";
    public string FindingSearch { get => _findingSearch; set { if (Set(ref _findingSearch, value)) { _findingQuery = SearchQuery.Parse(value); Debounce(); } } }
    SearchQuery _findingQuery = SearchQuery.Empty;

    // Commands filters
    string _commandGroup = "All";
    public string CommandGroup { get => _commandGroup; set { if (Set(ref _commandGroup, value)) RefreshFilters(); } }
    string _commandSearch = "";
    public string CommandSearch { get => _commandSearch; set { if (Set(ref _commandSearch, value)) { _commandQuery = SearchQuery.Parse(value); Debounce(); } } }
    SearchQuery _commandQuery = SearchQuery.Empty;
    bool _suspiciousOnly;
    public bool SuspiciousOnly { get => _suspiciousOnly; set { if (Set(ref _suspiciousOnly, value)) RefreshFilters(); } }
    int _flaggedCommands;
    /// <summary>Flagged commands on the tab in view, after the search.</summary>
    public int FlaggedCommands { get => _flaggedCommands; private set => Set(ref _flaggedCommands, value); }

    // Timeline / memory filters
    string _timelineSearch = "";
    public string TimelineSearch { get => _timelineSearch; set { if (Set(ref _timelineSearch, value)) { _timelineQuery = SearchQuery.Parse(value); Debounce(); } } }
    SearchQuery _timelineQuery = SearchQuery.Empty;
    bool _timelineWindows;
    public bool TimelineIncludeWindows { get => _timelineWindows; set { if (Set(ref _timelineWindows, value)) RefreshFilters(); } }
    int _routineRecords;
    /// <summary>Records of routine files on the timeline tab in view.</summary>
    public int RoutineRecords { get => _routineRecords; private set => Set(ref _routineRecords, value); }
    int _ownRecords;
    /// <summary>Records of this suite's own files on the timeline tab in view, that the routine switch does not already cover.</summary>
    public int OwnRecords { get => _ownRecords; private set => Set(ref _ownRecords, value); }
    public int HiddenRecords => (TimelineIncludeWindows ? 0 : RoutineRecords) + (ShowOwnTraces ? 0 : OwnRecords);
    string _timelineKind = "All";
    /// <summary>The kind of record the timeline is narrowed to: All, Ran, Loaded, Seen, Deleted or Changed.</summary>
    public string TimelineKind { get => _timelineKind; set { if (Set(ref _timelineKind, value)) RefreshFilters(); } }

    // The same records, by folder: a journal with thousands of rows reads as the few folders something happened in.
    string _timelineLayout = "Records";
    /// <summary>"Records" (one row per record) or "Folders" (one row per folder, its records beside it).</summary>
    public string TimelineLayout
    {
        get => _timelineLayout;
        set
        {
            if (!Set(ref _timelineLayout, value)) return;
            OnPropertyChanged(nameof(TimelineByFolder));
            BuildFolders();
        }
    }
    public bool TimelineByFolder => TimelineLayout == "Folders";
    public IReadOnlyList<FolderRow> FolderGroups { get; private set; } = [];
    FolderRow? _selectedFolder;
    public FolderRow? SelectedFolder { get => _selectedFolder; set => Set(ref _selectedFolder, value); }

    /// <summary>Groups exactly the records the list shows (same tab, same search, same hidden rows), so both layouts count the same.</summary>
    void BuildFolders()
    {
        string? keep = SelectedFolder?.Folder;
        FolderGroups = !TimelineByFolder ? [] : TimelineView.Cast<EvidenceRow>()
            .GroupBy(r => r.Folder, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FolderRow(g.Key, g.ToList()))
            .OrderByDescending(g => g.Latest ?? DateTime.MinValue).ThenBy(g => g.Folder, StringComparer.OrdinalIgnoreCase).ToList();
        OnPropertyChanged(nameof(FolderGroups));
        SelectedFolder = FolderGroups.FirstOrDefault(g => g.Folder.Equals(keep, StringComparison.OrdinalIgnoreCase)) ?? FolderGroups.FirstOrDefault();
    }

    static bool KindMatches(string tab, Core.Models.EvidenceKind kind) => tab switch
    {
        "Ran" => kind == Core.Models.EvidenceKind.Execution,
        "Loaded" => kind == Core.Models.EvidenceKind.LoadedModule,
        "Seen" => kind == Core.Models.EvidenceKind.Presence,
        "Deleted" => kind is Core.Models.EvidenceKind.Deleted or Core.Models.EvidenceKind.Recycled,
        "Changed" => kind is Core.Models.EvidenceKind.Created or Core.Models.EvidenceKind.Renamed or Core.Models.EvidenceKind.Modified
            or Core.Models.EvidenceKind.TimestampChanged or Core.Models.EvidenceKind.HardLinked,
        _ => true,
    };
    string _memorySearch = "";
    public string MemorySearch { get => _memorySearch; set { if (Set(ref _memorySearch, value)) { _memoryQuery = SearchQuery.Parse(value); Debounce(); } } }
    SearchQuery _memoryQuery = SearchQuery.Empty;

    bool MemoryFilter(MemoryHit h) =>
        _memoryQuery.Matches(h.Process + " " + h.Path);


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
            var full = await Core.Bypass.BypassScanner.RunAsync(options, argumentRules, progress, _cts.Token);
            // A period whose start this PC does not have (no game running) is shown as the next wider one, under that name.
            var window = TimeWindows.Effective(SelectedWindow, full.History.Machine);
            _full = full;
            _fullSince = TimeWindows.Since(window, full.History.StartedUtc, full.History.Machine);
            _gameStart = DefaultGame(full.History.Machine);
            LoadedFrom = null;
            Show(Core.Bypass.BypassScanner.Trim(full, window), null);
            MarkWhole();
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
        // Copies of one library become one row with a count; the copies stay a switch (and a search) away.
        var rowOf = new Dictionary<string, FileRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in _files) rowOf.TryAdd(row.Path, row);
        foreach (var group in Core.Analysis.Repeats.Find(result.Files))
            if (rowOf.TryGetValue(group.Lead, out var lead))
                lead.Fold(group.Copies.Select(p => rowOf.GetValueOrDefault(p)).OfType<FileRow>().ToList(), group.Why);
        FilesView = new ListCollectionView(_files) { Filter = o => FileFilter((FileRow)o) };


        // The timeline folds what the file pages fold: every record of a routine file, and Windows' own data files in its
        // folder (Prefetch files, logs) that were never run. Decided per file by the scan, never by the row's path alone.
        var folded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in _files.Where(f => f.Folded))
            foreach (var e in f.Record.Evidence) folded.Add(e.Path);
        // Windows writes its data files constantly, so those records fold - but not the ones that say such a file was
        // deleted, renamed or had its dates changed: a Prefetch file or a log that went away is what a check looks for.
        var dataFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in _files.Where(f => f.Type == Core.Models.FileType.Other && !f.Ran && Core.Analysis.RoutineFiles.InWindowsFolder(f.Path)))
            foreach (var e in f.Record.Evidence) dataFiles.Add(e.Path);
        bool Folds(Evidence e) => folded.Contains(e.Path) || (dataFiles.Contains(e.Path) &&
            e.Kind is not (EvidenceKind.Deleted or EvidenceKind.Recycled or EvidenceKind.Renamed or EvidenceKind.TimestampChanged));
        // And it keeps this suite's own records out of the way as the file pages do: the scan itself is the newest thing
        // that ran, so its traces would otherwise head the list. Ours only by the scan's verified match, as on those pages.
        var ownPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in _files.Where(f => f.IsThisTool))
            foreach (var e in f.Record.Evidence) ownPaths.Add(e.Path);
        TimelineView = new ListCollectionView(result.Timeline
                .Select(e => new EvidenceRow(e, Folds(e)) { IsThisTool = ownPaths.Contains(e.Path) }).ToList())
        { Filter = o => TimelineFilter((EvidenceRow)o) };
        FindingsView = new ListCollectionView(findings.ToList()) { Filter = o => FindingFilter((Finding)o, false) };
        InconsistencyView = new ListCollectionView(findings.ToList()) { Filter = o => FindingFilter((Finding)o, true) };
        MemoryView = new ListCollectionView(result.MemoryHits.ToList()) { Filter = o => MemoryFilter((MemoryHit)o) };
        // Every table opens newest first. Commands that carry a time come first in that order; the ones a history file
        // keeps without a time follow in the order that file has them. Flagged ones are marked, not moved: the Flagged
        // filter collects them.
        SelectedCommand = null;
        SelectedFinding = null;
        CommandsView = new ListCollectionView(result.Commands.OrderByDescending(c => c.TimeUtc.HasValue).ThenByDescending(c => c.TimeUtc)
                .Select(c => new CommandRow(c)).ToList())
        { Filter = o => CommandFilter((CommandRow)o) };

        HighCount = findings.Count(f => f.Severity == Severity.High);
        MediumCount = findings.Count(f => f.Severity == Severity.Medium);
        LowCount = findings.Count(f => f.Severity == Severity.Low);
        InconsistencyCount = findings.Count(f => InconsistencyCategories.Contains(f.Category) && !f.ByThisTool);
        var visible = _files.Where(f => !f.Folded && !f.IsThisTool && !f.IsCopy).ToList();
        OwnTraceCount = _files.Count(f => f.IsThisTool) + findings.Count(f => f.ByThisTool && f.Path == null);
        ProgramCount = visible.Count(f => PagePreset("Programs", f));
        ExeCount = visible.Count(f => PagePreset("Executables", f));
        DllCount = visible.Count(f => PagePreset("Dlls", f));
        JarCount = visible.Count(f => PagePreset("Jars", f));
        ScriptCount = visible.Count(f => PagePreset("Scripts", f));
        DriverCount = visible.Count(f => PagePreset("Drivers", f));
        DeletedCount = visible.Count(f => PagePreset("Deleted", f));
        CommandCount = result.Commands.Count;
        SuspiciousCommandCount = result.Commands.Count(c => c.Suspicion != null);
        TopFindings = findings.Where(f => !f.ByThisTool).Take(8).ToList();
        Areas = BuildAreas(result, findings);
        SessionMarks = BuildMarks(result);
        Activity =
        [
            new("Ran", ProgramCount, "programs, jars and scripts", "Programs"),
            new("Unsigned", visible.Count(f => PagePreset("Programs", f) && f.IsUnsigned), "of those that ran", "Programs:Unsigned"),
            new("Deleted", DeletedCount, "ran, now gone", "Deleted"),
            new("JARs", JarCount, "run, opened or seen", "Jars"),
            new("Scripts", ScriptCount, "run or seen", "Scripts"),
            new("Drivers", DriverCount, "loaded or installed", "Drivers"),
            new("Commands", SuspiciousCommandCount, $"flagged of {CommandCount:N0}", "Commands:Suspicious"),
            new("USB", Combined?.UsbDevices.Count ?? 0, "devices in the period", "Tamper:Usb"),
        ];
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
        "Dlls" => f.Type == Core.Models.FileType.Dll && !f.IsDriver,
        "Jars" => f.Type == Core.Models.FileType.Jar,
        "Scripts" => f.Type == Core.Models.FileType.Script,
        "Drivers" => f.IsDriver,
        "Deleted" => f.IsGone && f.Ran && f.Type != Core.Models.FileType.Other,
        _ => true,
    };

    /// <summary>The rows of the tab in view before any chip narrows them: the tab's kind, what is kept out of the way, the search.</summary>
    bool FileBase(FileRow f)
    {
        if (!PagePreset(Page, f)) return false;
        bool searching = _fileQuery.Seeks;
        // Routine files and copies are folded, never dropped: a search looks through them too.
        if (!IncludeWindows && f.Folded && !searching) return false;
        if (!ShowRepeats && f.IsCopy && !searching) return false;
        if (!ShowOwnTraces && f.IsThisTool) return false;
        return _fileQuery.MatchesLower(f.SearchText);
    }

    bool FileFilter(FileRow f) =>
        FileBase(f) && (!FlaggedOnly || f.Severity != null) && (!UnsignedOnly || f.IsUnsigned) &&
        (!GoneOnly || Page == "Deleted" || f.IsGone) && (!RanOnly || f.Ran);

    bool TimelineFilter(EvidenceRow e)
    {
        if (!KindMatches(TimelineKind, e.Item.Kind)) return false;
        if (!TimelineIncludeWindows && e.IsWindows && !_timelineQuery.Seeks) return false;
        if (!ShowOwnTraces && e.IsThisTool && !_timelineQuery.Seeks) return false;
        return _timelineQuery.MatchesLower(e.SearchText);
    }

    /// <summary>The findings of a tab before a severity chip narrows them. <paramref name="own"/>: count this suite's own even while they are hidden.</summary>
    bool FindingBase(Finding f, bool inconsistenciesOnly, bool own = false)
    {
        if (inconsistenciesOnly && !InconsistencyCategories.Contains(f.Category)) return false;
        if (!own && !ShowOwnTraces && f.ByThisTool) return false;
        return _findingQuery.Matches(FindingText(f));
    }

    bool FindingFilter(Finding f, bool inconsistenciesOnly)
    {
        if (!FindingBase(f, inconsistenciesOnly)) return false;
        // No chip on means not narrowed: everything.
        if (!ShowHigh && !ShowMedium && !ShowLow) return true;
        return f.Severity switch { Severity.High => ShowHigh, Severity.Medium => ShowMedium, _ => ShowLow };
    }

    bool CommandBase(CommandRow c) =>
        (CommandGroup == "All" || c.Group == CommandGroup) &&
        _commandQuery.MatchesLower(c.SearchText);

    bool CommandFilter(CommandRow c) => CommandBase(c) && (!SuspiciousOnly || c.IsSuspicious);

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

    /// <summary>Applies what is typed in a search box at once instead of a moment after the last key (the self-test drives searches through this).</summary>
    internal void ApplySearchNow()
    {
        _filterTimer.Stop();
        RefreshFilters();
    }

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
            // Every chip says how many rows it would leave, and the hidden button how many rows of each kind are out of view.
            if (key == "Files")
            {
                VisibleFiles = view.Count;
                int flagged = 0, unsigned = 0, gone = 0, ran = 0, routine = 0, own = 0, repeats = 0;
                foreach (var f in _files)
                {
                    if (!PagePreset(Page, f)) continue;
                    if (f.IsThisTool) own++;
                    else if (f.Folded) routine++;
                    else if (f.IsCopy) repeats++;
                    if (!FileBase(f)) continue;
                    if (f.Severity != null) flagged++;
                    if (f.IsUnsigned) unsigned++;
                    if (f.IsGone) gone++;
                    if (f.Ran) ran++;
                }
                (FlaggedFiles, UnsignedFiles, GoneFiles, RanFiles, RoutineCount, OwnFiles, RepeatFiles) = (flagged, unsigned, gone, ran, routine, own, repeats);
                OnPropertyChanged(nameof(HiddenFiles));
            }
            else if (key == "Timeline")
            {
                VisibleTimeline = view.Count;
                RoutineRecords = view.SourceCollection.Cast<EvidenceRow>().Count(e => e.IsWindows && KindMatches(TimelineKind, e.Item.Kind));
                // A record that is both routine and ours is counted once, as routine: one switch shows it.
                OwnRecords = view.SourceCollection.Cast<EvidenceRow>().Count(e => e.IsThisTool && (TimelineIncludeWindows || !e.IsWindows) && KindMatches(TimelineKind, e.Item.Kind));
                OnPropertyChanged(nameof(HiddenRecords));
                if (TimelineByFolder) BuildFolders();
            }
            else if (key == "Commands")
            {
                VisibleCommands = view.Count;
                FlaggedCommands = view.SourceCollection.Cast<CommandRow>().Count(c => c.IsSuspicious && CommandBase(c));
            }
            else if (key is "Findings" or "Inconsistencies")
            {
                bool dates = key == "Inconsistencies";
                int high = 0, medium = 0, low = 0, own = 0;
                foreach (Finding f in view.SourceCollection)
                {
                    if (f.ByThisTool && FindingBase(f, dates, own: true)) own++;
                    if (!FindingBase(f, dates)) continue;
                    if (f.Severity == Severity.High) high++; else if (f.Severity == Severity.Medium) medium++; else low++;
                }
                (HighOnTab, MediumOnTab, LowOnTab, OwnFindings) = (high, medium, low, own);
                OnPropertyChanged(nameof(HiddenFindings));
            }
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
        if (parts[0] is "Findings" or "Inconsistencies")
        {
            // "Findings:High" from an overview card; the findings page alone opens on High and Medium, the dates tab on everything.
            string severity = parts.Length == 2 ? parts[1] : parts[0] == "Findings" ? "Leads" : "All";
            // "Findings:Area:programs" from an overview row: that area's findings, by the same search anyone can type.
            // Any other way in drops an area search left from before, so the page never opens narrowed without having been asked.
            bool area = parts.Length == 3 && parts[1] == "Area";
            if (area || FindingSearch.StartsWith("area:", StringComparison.Ordinal))
            {
                _findingSearch = area ? "area:" + parts[2] : "";
                _findingQuery = SearchQuery.Parse(_findingSearch);
                OnPropertyChanged(nameof(FindingSearch));
            }
            if (area) severity = "Leads";
            ShowSeverities(severity is "High" or "Leads", severity is "Medium" or "Leads", severity == "Low");
        }
        if (parts.Length == 2 && parts[0] == "Programs" && parts[1] == "Unsigned")
        {
            _flaggedOnly = _goneOnly = _ranOnly = false;
            _unsignedOnly = true;
            foreach (var p in new[] { nameof(FlaggedOnly), nameof(GoneOnly), nameof(RanOnly), nameof(UnsignedOnly) }) OnPropertyChanged(p);
            RefreshFilters();
        }
        if (parts.Length == 2 && parts[0] == "Commands" && parts[1] == "Suspicious") SuspiciousOnly = true;
        Page = parts[0];
        // "Programs:Game" from the Overview: the list, at the row where the game started.
        if (parts.Length == 2 && parts[1] == "Game") JumpToGameRequested?.Invoke();
    }

    void ShowFile(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        var row = _files.FirstOrDefault(f => string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase));
        if (row == null) return;
        _fileSearch = "";
        _fileQuery = SearchQuery.Empty;
        _flaggedOnly = _goneOnly = _ranOnly = _unsignedOnly = false;
        _includeWindows |= row.Folded;
        _showOwnTraces |= row.IsThisTool;
        _showRepeats |= row.IsCopy;
        foreach (var p in new[] { nameof(FileSearch), nameof(FlaggedOnly), nameof(GoneOnly), nameof(RanOnly), nameof(UnsignedOnly), nameof(IncludeWindows), nameof(ShowOwnTraces), nameof(ShowRepeats) })
            OnPropertyChanged(p);
        string page = row.Type switch
        {
            _ when row.IsDriver => "Drivers",
            Core.Models.FileType.Dll => "Dlls",
            Core.Models.FileType.Jar => "Jars",
            Core.Models.FileType.Exe => "Executables",
            Core.Models.FileType.Script => "Scripts",
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

    string DefaultFileName(string suffix, string ext) =>
        ReportFiles.DefaultName(Result!, HidePrivate || ShowingRedactedReport, suffix, ext);

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
                ["Flag", "Name", "Type", "How", "Last run (local)", "Run count", "Status", "Status detail", "Sources", "Signature", "Signer", "SHA-256", "Path"],
                (IsFilePage ? FilesView.Cast<FileRow>() : _files).Select(f => new[]
                {
                    f.Severity?.ToString(), f.Name, f.TypeText, f.HowText, Local(f.LastRun), f.RunCount?.ToString(), Display.Status(f.Status),
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

        ExportDialog.SaveCsv(DefaultFileName("-" + table.Name, "csv"), () => ReportFiles.Csv(table.Header, table.Rows));

        static string? Local(DateTime? t) => t?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
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
