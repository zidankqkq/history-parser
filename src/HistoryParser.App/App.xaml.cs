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
        // Never lose a screenshare to a crash: report it and keep the window open.
        MessageBox.Show($"Something went wrong: {e.Exception.Message}\n\nThe scan results you already have are still available.",
            "History Parser", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    // ---- developer snapshots ---------------------------------------------------------------

    static readonly string[] Pages =
        ["Overview", "Programs", "Executables", "Dlls", "Jars", "Deleted", "Inconsistencies", "Findings", "Commands", "Timeline", "Memory", "Integrity", "Help"];
    static readonly string[] TamperPages =
        ["Overview", "Findings", "Logs", "Evidence", "Services", "Clock", "Usb", "Arguments"];

    async Task RunSnapshots(MainWindow window, MainViewModel vm)
    {
        string dir = Value("--snapshot") ?? "snapshots";
        Directory.CreateDirectory(dir);
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.Left = -20000;
        window.ShowActivated = false;
        window.Show();

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
            Render(window, Path.Combine(dir, $"{i + 1:00}-{Pages[i].ToLowerInvariant()}.png"));
        }
        // The tampering pages, picked from the same sidebar.
        foreach (var page in TamperPages)
        {
            vm.NavPage = "Tamper:" + page;
            Render(window, Path.Combine(dir, $"{Pages.Length + 1}-tamper-{page.ToLowerInvariant()}.png"));
        }
        vm.NavPage = "Overview";
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
        foreach (var page in new[] { "Programs", "Executables", "Dlls", "Jars", "Deleted" })
        {
            Step($"page {page}", () => vm.Page = page);
            Step("  default order is Last run, newest first", () =>
            {
                var rows = vm.FilesView.Cast<FileRow>().ToList();
                for (int i = 1; i < rows.Count; i++)
                    if (rows[i].LastRun != null && !(rows[i - 1].LastRun >= rows[i].LastRun))
                        throw new InvalidOperationException($"order broken at row {i}: {rows[i - 1].Path} / {rows[i].Path}");
            });
            Step("  flagged", () => { vm.FlaggedOnly = true; vm.FlaggedOnly = false; });
            Step("  ran", () => { vm.RanOnly = true; vm.RanOnly = false; });
            Step("  gone", () => { vm.GoneOnly = true; vm.GoneOnly = false; });
            Step("  windows", () => { vm.IncludeWindows = true; vm.IncludeWindows = false; });
        }

        foreach (var target in new[] { "Findings:High", "Findings:Medium", "Inconsistencies", "Deleted", "Programs", "Commands:Suspicious", "Integrity", "Overview" })
            Step($"navigate {target}", () => vm.NavigateCommand.Execute(target));
        Step("commands reset", () => vm.SuspiciousOnly = false);
        foreach (var group in new[] { "PowerShell", "CMD / Terminal", "Run box", "Explorer", "Bash", "Running", "Event log", "All" })
            Step($"commands {group}", () => { vm.Page = "Commands"; vm.CommandGroup = group; });
        if (vm.Result?.Findings.FirstOrDefault(f => f.Path != null) is { } finding)
            Step($"show file {finding.Path}", () =>
            {
                vm.ShowFileCommand.Execute(finding.Path);
                if (vm.SelectedFile?.Path != finding.Path) throw new InvalidOperationException("file not selected");
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
        var root = (FrameworkElement)window.Content;
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
