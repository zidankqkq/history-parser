using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using HistoryParser.App.ViewModels;
using HistoryParser.Core.Export;
using HistoryParser.Core.Native;

namespace HistoryParser.App;

/// <summary>
/// Startup flow for a screenshare: double-click → Windows asks for admin → choose default or custom rules → scan.
/// Command-line switches:
///   --no-elevate     do not ask for admin (scan will be incomplete)
///   --autoscan       scan immediately with the default rules
///   --rules file.txt load a rules file and scan immediately
///   --open file.json open a saved report
///   --snapshot dir [--report file.json]  developer aid: render every page to PNG and exit
/// </summary>
public partial class App : Application
{
    static string[] _args = [];

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Draw in software: some graphics drivers leave stale pixels behind when part of the window
        // changes, e.g. two scrollbar thumbs and one menu entry drawn over another in the sidebar during a scan.
        RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
        _args = e.Args;
        DispatcherUnhandledException += OnUnhandledException;

        bool snapshot = Has("--snapshot");
        if (!snapshot && !Has("--no-elevate") && !Has("--open") && !WinApi.IsElevated() && TryRelaunchElevated())
        {
            Shutdown();
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        var vm = (MainViewModel)window.DataContext;

        if (snapshot)
        {
            await RunSnapshots(window, vm);
            return;
        }

        window.Show();
        if (Value("--open") is { } report)
        {
            try { vm.OpenFile(report); }
            catch (Exception ex) { vm.Error = $"Could not open {Path.GetFileName(report)}: {ex.Message}"; }
        }
        else if (Value("--rules") is { } rulesFile)
        {
            // One-command custom screenshare: load the rules file and scan straight away.
            if (vm.LoadRulesFrom(rulesFile)) await vm.ScanAsync();
        }
        else if (Has("--autoscan"))
        {
            await vm.ScanAsync();
        }
        // Otherwise the start screen asks for default or custom rules before anything is read.
    }

    static bool Has(string flag) => _args.Contains(flag, StringComparer.OrdinalIgnoreCase);

    static string? Value(string flag)
    {
        int i = Array.FindIndex(_args, a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < _args.Length ? _args[i + 1] : null;
    }

    /// <summary>Restarts this exe through the UAC prompt. False if the user said no.</summary>
    public static bool TryRelaunchElevated()
    {
        try
        {
            // The elevated copy may start in another folder, so file arguments become absolute paths.
            var fixedArgs = _args.Select((a, i) => i > 0 && _args[i - 1] is "--rules" or "--open" ? Path.GetFullPath(a) : a);
            var args = string.Join(" ", fixedArgs.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!, args) { UseShellExecute = true, Verb = "runas" });
            return true;
        }
        catch (Win32Exception)
        {
            return false; // UAC declined: carry on unelevated, the app explains what is missing
        }
    }

    void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Rendering pages for a developer has nobody to press OK: write the error down and stop, with an exit code that says so.
        if (Has("--snapshot"))
        {
            e.Handled = true;
            try
            {
                string dir = Value("--snapshot") ?? "snapshots";
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, "crash.txt"), e.Exception.ToString());
            }
            catch (Exception io) when (io is IOException or UnauthorizedAccessException) { }
            Environment.Exit(3);
            return;
        }
        // Never lose a screenshare to a crash: report it and keep the window open.
        MessageBox.Show($"Something went wrong: {e.Exception.Message}\n\nThe scan results you already have are still available.",
            "History Parser", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    // ---- developer snapshots ---------------------------------------------------------------

    static readonly string[] Pages =
        ["Overview", "Programs", "Executables", "Dlls", "Jars", "Scripts", "Drivers", "Deleted", "Inconsistencies", "Findings", "Commands", "Timeline", "Memory", "Integrity", "Help"];
    static readonly string[] TamperPages =
        ["Overview", "Findings", "Antivirus", "Logs", "Evidence", "Services", "Clock", "Usb", "Arguments"];

    async Task RunSnapshots(MainWindow window, MainViewModel vm)
    {
        string dir = Value("--snapshot") ?? "snapshots";
        Directory.CreateDirectory(dir);
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = -20000;
        window.ShowActivated = false;
        window.Show();

        await vm.BuildRead; // the title bar shows this program's hash on every page, the first render included
        var total = Stopwatch.StartNew();
        Render(window, Path.Combine(dir, "00-start.png"));
        vm.Page = "Help";
        Render(window, Path.Combine(dir, "00-help-before-scan.png"));
        vm.Page = "Overview";
        vm.RulesMode = "Custom";
        Render(window, Path.Combine(dir, "00-start-custom.png"));
        vm.CommandsText += Environment.NewLine + "/([broken/ => oops";
        await vm.ScanAsync(); // must refuse: the rule is invalid
        File.WriteAllText(Path.Combine(dir, "rules-check.txt"), $"state={vm.State} error={vm.RulesError}");
        Render(window, Path.Combine(dir, "00-start-error.png"));
        vm.ResetRulesCommand.Execute(null);
        vm.RulesMode = "Default";
        vm.Page = "Overview";
        if (Value("--report") is { } report) vm.OpenFile(report);
        else await vm.ScanAsync();

        for (int i = 0; i < Pages.Length; i++)
        {
            vm.Page = Pages[i];
            if (vm.IsFilePage) vm.SelectedFile = vm.FilesView.Cast<FileRow>().FirstOrDefault();
            if (vm.IsFindingPage) vm.SelectedFinding = vm.ActiveFindings.Cast<HistoryParser.Core.Models.Finding>().FirstOrDefault();
            Render(window, Path.Combine(dir, $"{i + 1:00}-{Pages[i].ToLowerInvariant()}.png"));
        }
        // The tampering pages, picked from the same sidebar.
        foreach (var page in TamperPages)
        {
            vm.NavPage = "Tamper:" + page;
            Render(window, Path.Combine(dir, $"{Pages.Length + 1}-tamper-{page.ToLowerInvariant()}.png"));
        }
        vm.Page = "Timeline";
        vm.TimelineLayout = "Folders";
        Render(window, Path.Combine(dir, "12b-timeline-folders.png"));
        vm.TimelineLayout = "Records";
        vm.NavPage = "Overview";
        // The list of periods drops down from the title bar; it is its own surface, so it is rendered on its own.
        if (vm.Periods.Count > 0)
        {
            window.PeriodToggle.IsChecked = true;
            window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            if (window.PeriodPopup.Child is FrameworkElement list) RenderElement(list, Path.Combine(dir, "01c-period-list.png"));
            window.PeriodToggle.IsChecked = false;
            if (vm.Periods.FirstOrDefault(p => p.Instant && p.Enabled && !p.IsCurrent) is { } narrower)
            {
                string first = vm.Periods.First(p => p.IsCurrent).Key;
                vm.SetPeriodCommand.Execute(narrower.Key);
                Render(window, Path.Combine(dir, "01b-overview-narrower-period.png"));
                vm.SetPeriodCommand.Execute(first);
            }
        }
        // The build's card drops down from the other end of the title bar: its own surface too.
        window.BuildToggle.IsChecked = true;
        window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        if (window.BuildPopup.Child is FrameworkElement card) RenderElement(card, Path.Combine(dir, "01d-build.png"));
        window.BuildToggle.IsChecked = false;
        var timing = $"load+render: {total.ElapsedMilliseconds} ms{Environment.NewLine}";
        File.WriteAllText(Path.Combine(dir, "selftest.txt"), timing + SelfTest(window, vm));
        Shutdown();
    }

    /// <summary>Drives every filter, sort and navigation path through the real view model and layout.</summary>
    static string SelfTest(MainWindow window, MainViewModel vm)
    {
        var log = new System.Text.StringBuilder();
        void Step(string name, Action action)
        {
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                action();
                long actionMs = sw.ElapsedMilliseconds;
                window.UpdateLayout();
                log.Append($"[action {actionMs} ms] ");
                log.AppendLine($"ok   {sw.ElapsedMilliseconds,6} ms  {name}: files={vm.VisibleFiles} commands={vm.VisibleCommands} timeline={vm.VisibleTimeline} page={vm.Page}");
            }
            catch (Exception e) { log.AppendLine($"FAIL {name}: {e}"); }
        }

        for (int n = 0; n < 3; n++) Step("noop-start", () => { });
        foreach (var page in new[] { "Programs", "Executables", "Dlls", "Jars", "Scripts", "Drivers", "Deleted" })
        {
            Step($"page {page}", () => vm.Page = page);
            Step("  default order is Last run, newest first", () =>
            {
                var rows = vm.FilesView.Cast<FileRow>().ToList();
                for (int i = 1; i < rows.Count; i++)
                    if (rows[i].LastRun != null && !(rows[i - 1].LastRun >= rows[i].LastRun))
                        throw new InvalidOperationException($"order broken at row {i}: {rows[i - 1].Path} / {rows[i].Path}");
            });
            // Each chip must leave exactly as many rows as the count it carries, or the count is a lie.
            void Chip(string name, Action<bool> set, Func<int> count) => Step($"  {name} chip leaves the rows it counts", () =>
            {
                int promised = count();
                set(true);
                int left = vm.VisibleFiles;
                set(false);
                if (left != promised) throw new InvalidOperationException($"{name} on {page}: the chip says {promised}, the list has {left}");
            });
            Chip("flagged", on => vm.FlaggedOnly = on, () => vm.FlaggedFiles);
            Chip("unsigned", on => vm.UnsignedOnly = on, () => vm.UnsignedFiles);
            Chip("ran", on => vm.RanOnly = on, () => vm.RanFiles);
            if (page != "Deleted") Chip("deleted", on => vm.GoneOnly = on, () => vm.GoneFiles);
            Step("  showing everything hidden adds exactly the hidden count", () =>
            {
                int before = vm.VisibleFiles, hidden = vm.HiddenFiles;
                vm.IncludeWindows = vm.ShowRepeats = vm.ShowOwnTraces = true;
                int after = vm.VisibleFiles, stillHidden = vm.HiddenFiles;
                vm.IncludeWindows = vm.ShowRepeats = vm.ShowOwnTraces = false;
                if (after - before != hidden || stillHidden != 0)
                    throw new InvalidOperationException($"{page}: {hidden} hidden, but showing them took the list from {before} to {after} (and {stillHidden} still counted hidden)");
            });
        }

        foreach (var target in new[] { "Findings:High", "Findings:Medium", "Inconsistencies", "Deleted", "Programs", "Commands:Suspicious", "Integrity", "Overview" })
            Step($"navigate {target}", () => vm.NavigateCommand.Execute(target));
        Step("commands reset", () => vm.SuspiciousOnly = false);
        foreach (var group in new[] { "PowerShell", "CMD / Terminal", "Run box", "Explorer", "Bash", "Running", "Event log", "All" })
            Step($"commands {group}", () => { vm.Page = "Commands"; vm.CommandGroup = group; });
        foreach (var kind in new[] { "Ran", "Loaded", "Seen", "Deleted", "Changed", "All" })
            Step($"timeline {kind}", () =>
            {
                vm.Page = "Timeline";
                vm.TimelineKind = kind;
                string[]? allowed = kind switch
                {
                    "Ran" => ["Executed"], "Loaded" => ["Loaded"], "Seen" => ["Seen"], "Deleted" => ["Deleted", "Recycled"],
                    "Changed" => ["Created", "Renamed", "Modified", "Times changed", "Hard link"], _ => null,
                };
                if (allowed != null && vm.TimelineView.Cast<EvidenceRow>().FirstOrDefault(e => !allowed.Contains(e.KindText)) is { } wrong)
                    throw new InvalidOperationException($"a {wrong.KindText} row is on the {kind} tab");
            });
        Step("findings: each severity chip leaves the findings it counts", () =>
        {
            vm.NavigateCommand.Execute("Findings");
            foreach (var (high, medium, low, name) in new[] { (true, false, false, "High"), (false, true, false, "Medium"), (false, false, true, "Low") })
            {
                (vm.ShowHigh, vm.ShowMedium, vm.ShowLow) = (high, medium, low);
                int promised = high ? vm.HighOnTab : medium ? vm.MediumOnTab : vm.LowOnTab;
                if (vm.ActiveFindings.Count != promised) throw new InvalidOperationException($"{name}: the chip says {promised}, the list has {vm.ActiveFindings.Count}");
            }
            (vm.ShowHigh, vm.ShowMedium, vm.ShowLow) = (false, false, false);
            if (vm.ActiveFindings.Count != vm.HighOnTab + vm.MediumOnTab + vm.LowOnTab) throw new InvalidOperationException("no chip picked should list every finding");
        });
        Step("commands: the flagged chip leaves the commands it counts", () =>
        {
            vm.Page = "Commands";
            vm.CommandGroup = "All";
            int promised = vm.FlaggedCommands;
            vm.SuspiciousOnly = true;
            int left = vm.VisibleCommands;
            vm.SuspiciousOnly = false;
            if (left != promised) throw new InvalidOperationException($"the chip says {promised}, the list has {left}");
        });
        if (vm.Tamper.HasResults)
            foreach (var tamperPage in TamperPages.Where(p => p != "Overview"))
                Step($"tampering {tamperPage}: showing what is hidden adds exactly the hidden count", () =>
                {
                    vm.NavPage = "Tamper:" + tamperPage;
                    var t = vm.Tamper;
                    int Rows() => new[] { t.FindingsView, t.LogsView, t.GapsView, t.ServicesView, t.ServiceEventsView, t.UsbView, t.UsbEventsView, t.ArgumentsView,
                        t.EvidenceView, t.ClockView, t.ChecksView, t.AntivirusView, t.AvChangesView }.Sum(v => v.Count);
                    int before = Rows(), hidden = t.HiddenRows;
                    t.ShowUnflagged = t.ShowTemp = true;
                    int after = Rows(), stillHidden = t.HiddenRows;
                    t.ShowUnflagged = t.ShowTemp = false;
                    if (after - before != hidden || stillHidden != 0)
                        throw new InvalidOperationException($"{hidden} hidden, but showing them took the tables from {before} to {after} rows (and {stillHidden} still counted hidden)");
                });
        Step("findings tabs share one list", () =>
        {
            vm.NavigateCommand.Execute("Inconsistencies");
            if (!vm.IsFindingPage || vm.ActiveFindings != vm.InconsistencyView) throw new InvalidOperationException("date inconsistencies tab shows the wrong list");
            vm.NavigateCommand.Execute("Findings");
            if (vm.ActiveFindings != vm.FindingsView) throw new InvalidOperationException("findings tab shows the wrong list");
        });
        if (vm.Result?.Findings.FirstOrDefault(f => f.Path != null) is { } finding)
            Step($"show file {finding.Path}", () =>
            {
                vm.ShowFileCommand.Execute(finding.Path);
                if (!string.Equals(vm.SelectedFile?.Path, finding.Path, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("file not selected");
            });
        Step("overview: every kind of finding belongs to an area, and the areas count every flagged finding", () =>
        {
            foreach (var category in Enum.GetValues<HistoryParser.Core.Models.FindingCategory>())
                if (MainViewModel.AreaKey(category) == "other") throw new InvalidOperationException($"{category} findings belong to no area");
            int expected = vm.FindingsView.SourceCollection.Cast<HistoryParser.Core.Models.Finding>()
                .Count(f => !f.ByThisTool && f.Severity >= HistoryParser.Core.Models.Severity.Medium);
            int counted = vm.Areas.Skip(1).Sum(a => a.Count); // the first row is the scan itself
            if (counted != expected) throw new InvalidOperationException($"the areas count {counted} flagged findings, the scan has {expected}");
        });
        Step("overview: an area row opens exactly the findings it counts", () =>
        {
            foreach (var area in vm.Areas.Where(a => a.Target.StartsWith("Findings:Area:", StringComparison.Ordinal)))
            {
                vm.NavigateCommand.Execute(area.Target);
                if (vm.ActiveFindings.Count != area.Count) throw new InvalidOperationException($"{area.Name}: the row says {area.Count}, the page lists {vm.ActiveFindings.Count}");
            }
            vm.NavigateCommand.Execute("Findings");
            if (vm.FindingSearch.Length != 0) throw new InvalidOperationException("an area search stayed on after opening the findings another way");
        });
        Step("overview: each activity number opens the list it counts", () =>
        {
            foreach (var tile in vm.Activity.Where(a => !a.Target.StartsWith("Tamper:", StringComparison.Ordinal) && !a.Target.StartsWith("Commands", StringComparison.Ordinal)))
            {
                vm.NavigateCommand.Execute(tile.Target);
                if (vm.VisibleFiles != tile.Count) throw new InvalidOperationException($"{tile.Label}: the number is {tile.Count}, the list has {vm.VisibleFiles}");
                vm.UnsignedOnly = false;
            }
        });
        Step("timeline: the folders hold exactly the records the list shows", () =>
        {
            vm.Page = "Timeline";
            vm.TimelineKind = "All";
            vm.TimelineLayout = "Folders";
            int inFolders = vm.FolderGroups.Sum(f => f.Records);
            bool picked = vm.FolderGroups.Count == 0 || vm.SelectedFolder != null;
            vm.TimelineLayout = "Records";
            if (inFolders != vm.VisibleTimeline) throw new InvalidOperationException($"the folders hold {inFolders} records, the list {vm.VisibleTimeline}");
            if (!picked) throw new InvalidOperationException("no folder is picked");
        });
        Step("timeline: this suite's own records are out of the way, and their switch brings exactly those back", () =>
        {
            vm.Page = "Timeline";
            vm.TimelineKind = "All";
            int shown = vm.VisibleTimeline, own = vm.OwnRecords, hidden = vm.HiddenRecords;
            vm.ShowOwnTraces = true;
            int with = vm.VisibleTimeline, hiddenWith = vm.HiddenRecords;
            vm.ShowOwnTraces = false;
            if (with - shown != own || hidden - hiddenWith != own)
                throw new InvalidOperationException($"{own} own records counted; the switch showed {with - shown} more and the hidden count fell by {hidden - hiddenWith}");
            if (vm.TimelineView.Cast<EvidenceRow>().Any(r => r.IsThisTool)) throw new InvalidOperationException("one of this suite's own records is listed with its switch off");
        });
        Step("search: what a word leaves and what its opposite leaves add up to the list", () =>
        {
            vm.Page = "Timeline";
            vm.TimelineIncludeWindows = vm.ShowOwnTraces = true; // nothing kept out of the way, so the three counts are of the same rows
            int all = vm.VisibleTimeline;
            int Count(string search) { vm.TimelineSearch = search; vm.ApplySearchNow(); return vm.VisibleTimeline; }
            int with = Count(".exe"), without = Count("!.exe"), both = Count(".exe !.exe"), phrase = Count("\"\\windows\\\" .exe");
            Count("");
            vm.TimelineIncludeWindows = vm.ShowOwnTraces = false;
            if (with + without != all) throw new InvalidOperationException($"{with} with + {without} without is not the {all} in the list");
            if (both != 0) throw new InvalidOperationException("a word and its opposite together left rows");
            if (phrase > with) throw new InvalidOperationException("a second word widened the search");
        });
        Step("search: taking rows away does not bring hidden rows back", () =>
        {
            vm.Page = "Programs";
            int shown = vm.VisibleFiles;
            vm.FileSearch = "!zzzz-not-in-any-row";
            vm.ApplySearchNow();
            int after = vm.VisibleFiles;
            vm.FileSearch = "";
            vm.ApplySearchNow();
            if (after != shown) throw new InvalidOperationException($"a search that only takes rows away changed the list from {shown} to {after}");
        });
        if (vm.Periods.Count > 0)
            Step("period: a narrower one is cut from this scan, and the first one comes back whole", () =>
            {
                vm.Page = "Programs";
                string first = vm.Periods.First(p => p.IsCurrent).Key;
                var whole = vm.Combined!;
                int files = vm.VisibleFiles, findings = whole.Findings.Count, flagged = vm.FlaggedFindingCount, programs = vm.ProgramCount;
                // What describes the PC as it is now has no date, and no period may drop it.
                var standing = whole.Findings.Where(f => f.TimeUtc == null && f.Path == null).Select(f => f.Title).ToList();
                foreach (var period in vm.Periods.Where(p => p.Instant && p.Enabled && !p.IsCurrent).ToList())
                {
                    vm.SetPeriodCommand.Execute(period.Key);
                    var cut = vm.Combined!;
                    if (cut.History.Window.ToString() != period.Key) throw new InvalidOperationException($"{period.Label}: the period did not change");
                    if (vm.NavPage != "Programs") throw new InvalidOperationException($"{period.Label}: left the page for {vm.NavPage}");
                    if (cut.History.Files.Count > whole.History.Files.Count || cut.Findings.Count > findings)
                        throw new InvalidOperationException($"{period.Label}: a narrower period lists more than the scan holds");
                    if (cut.History.SinceUtc is { } since && cut.History.Timeline.Any(e => e.TimeUtc < since))
                        throw new InvalidOperationException($"{period.Label}: a record from before the period is listed");
                    if (standing.FirstOrDefault(title => !cut.Findings.Any(f => f.Title == title)) is { } lost)
                        throw new InvalidOperationException($"{period.Label}: dropped a finding about the PC as it is now: {lost}");
                    if (cut.Session.Count != whole.Session.Count) throw new InvalidOperationException($"{period.Label}: the session's times changed");
                    if (vm.FlaggedEarlier + vm.FlaggedFindingCount != flagged)
                        throw new InvalidOperationException($"{period.Label}: {vm.FlaggedFindingCount} flagged shown and {vm.FlaggedEarlier} said to be earlier, of {flagged}");
                    if (vm.ProgramsEarlier + vm.ProgramCount != programs)
                        throw new InvalidOperationException($"{period.Label}: {vm.ProgramCount} programs shown and {vm.ProgramsEarlier} said to be earlier, of {programs}");
                    if (vm.ProgramsEarlier + vm.FlaggedEarlier > 0 == (vm.EarlierText.Length == 0))
                        throw new InvalidOperationException($"{period.Label}: the title bar says \"{vm.EarlierText}\" with {vm.ProgramsEarlier} programs and {vm.FlaggedEarlier} flagged left out");
                }
                vm.SetPeriodCommand.Execute(first);
                if (vm.VisibleFiles != files || vm.Combined!.Findings.Count != findings)
                    throw new InvalidOperationException($"the first period came back with {vm.VisibleFiles} files and {vm.Combined!.Findings.Count} findings, not {files} and {findings}");
            });
        if (vm.Games.Count > 0)
            Step("games: every game is listed, and picking one starts the period at its start", () =>
            {
                vm.Page = "Programs";
                string first = vm.Periods.First(p => p.IsCurrent).Key;
                int listed = vm.Games.Count;
                // A Java program that is not recognisably the game is listed, and is the game only when the reader picks it.
                if (vm.GameStartUtc is { } assumed && vm.Result!.Machine.Games.Any(g => g.StartUtc == assumed && g.Unrecognised) &&
                    !vm.Result.Machine.Games.Any(g => g.StartUtc == assumed && !g.Unrecognised))
                    throw new InvalidOperationException("a Java program that is not recognisably the game was taken for the game");
                foreach (var game in vm.Games.Where(g => g.Enabled).ToList())
                {
                    vm.PickGameCommand.Execute(game.Key);
                    var start = new DateTime(long.Parse(game.Key), DateTimeKind.Utc);
                    if (vm.Result!.Window != HistoryParser.Core.Models.TimeWindow.Game || vm.Result.SinceUtc != start)
                        throw new InvalidOperationException($"{game.Title}: the period starts {vm.Result.SinceUtc:u}, not at the game's {start:u}");
                    if (vm.Games.Count != listed || vm.Games.Count(g => g.IsPicked) != 1 || !vm.Games.First(g => g.Key == game.Key).IsPicked)
                        throw new InvalidOperationException($"{game.Title}: {vm.Games.Count} games listed, {vm.Games.Count(g => g.IsPicked)} marked as picked");
                    if (vm.Result.Timeline.Any(e => e.TimeUtc < start)) throw new InvalidOperationException($"{game.Title}: a record from before its start is listed");
                    if (vm.NavPage != "Programs") throw new InvalidOperationException($"{game.Title}: left the page for {vm.NavPage}");
                }
                vm.SetPeriodCommand.Execute(first);
            });
        Step("partial: a scan without administrator rights says so, and names what was not read", () =>
        {
            bool partial = !vm.Result!.Machine.IsElevated;
            if (vm.ScanPartial != partial) throw new InvalidOperationException($"elevated {!partial}, said to be partial {vm.ScanPartial}");
            if (partial && vm.Result.Sources.FirstOrDefault(s => !s.Success) is { } unread && !vm.PartialText.Contains(unread.Name))
                throw new InvalidOperationException($"\"{vm.PartialText}\" does not name {unread.Name}");
        });
        Step("build: the title bar gives the hash of the file this program was started from, short and whole", () =>
        {
            if (!vm.BuildRead.IsCompleted) throw new InvalidOperationException("the program's file has not been hashed");
            string path = Environment.ProcessPath!;
            string expected;
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(file)).ToLowerInvariant();
            if (vm.OwnHash != expected) throw new InvalidOperationException($"shows {vm.OwnHash}, the file is {expected}");
            if (vm.OwnHashShort != expected[..8]) throw new InvalidOperationException($"the title bar shows \"{vm.OwnHashShort}\"");
            string whole = vm.OwnHashLines.Replace(" ", "").Replace(Environment.NewLine, "");
            if (whole != expected || vm.OwnHashLines.Split(Environment.NewLine).Length != 2)
                throw new InvalidOperationException($"the card shows \"{vm.OwnHashLines}\"");
            // A build whose code is not in the hashed file says so; a build that is one file has nothing to add.
            bool oneFile = HistoryParser.Core.Analysis.SelfTraces.OneFile;
            if ((vm.OwnHashNote.Length == 0) != oneFile) throw new InvalidOperationException($"one file {oneFile}, note \"{vm.OwnHashNote}\"");
            // A saved report names the build that made it only when it recorded one, and a scan made now never does.
            bool says = vm.LoadedFrom != null && vm.Result!.Machine.ToolSha256.Length > 0;
            if ((vm.ReportBuildText.Length > 0) != says) throw new InvalidOperationException($"report build \"{vm.ReportBuildText}\"");
            if (vm.LoadedFrom == null && vm.Result!.Machine.ToolSha256 != (oneFile ? expected : ""))
                throw new InvalidOperationException($"the scan recorded \"{vm.Result.Machine.ToolSha256}\"");
        });
        Step("new scan returns to rules screen", () =>
        {
            vm.PrimaryActionCommand.Execute(null);
            if (vm.State != AppState.Ready || !vm.HasPreviousResults) throw new InvalidOperationException($"state {vm.State}");
        });
        Step("back to last results", () =>
        {
            vm.BackToResultsCommand.Execute(null);
            if (vm.State != AppState.Results || vm.Page != "Overview") throw new InvalidOperationException($"state {vm.State}");
        });
        for (int n = 0; n < 3; n++) Step("noop-end", () => { });
        Step("noop-end-files", () => vm.Page = "Programs");
        for (int n = 0; n < 2; n++) { Step("only files", () => vm.FilesView.Refresh()); Step("only timeline", () => vm.TimelineView.Refresh()); Step("only findings", () => vm.FindingsView.Refresh()); Step("only incons", () => vm.InconsistencyView.Refresh()); Step("only memory", () => vm.MemoryView.Refresh()); Step("only commands", () => vm.CommandsView.Refresh()); }
        for (int n = 0; n < 3; n++) Step("noop-end2", () => { });
        return log.ToString();
    }

    static void Render(Window window, string path)
    {
        window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        window.UpdateLayout();
        window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        RenderElement((FrameworkElement)window.Content, path);
    }

    static void RenderElement(FrameworkElement root, string path)
    {
        root.UpdateLayout();
        var dpi = VisualTreeHelper.GetDpi(root);
        var bmp = new RenderTargetBitmap((int)(root.ActualWidth * dpi.DpiScaleX), (int)(root.ActualHeight * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        bmp.Render(root);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path);
        encoder.Save(fs);
    }
}
