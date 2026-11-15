using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using HistoryParser.App.ViewModels;

namespace HistoryParser.App;

public partial class MainWindow : Window
{
    MainViewModel Vm => (MainViewModel)DataContext;

    public MainWindow()
    {
        InitializeComponent();
        // Open as large as the screen comfortably allows: the tables are wide, and a window sized for a small screen is
        // most of what makes them feel cramped on a big one.
        var screen = SystemParameters.WorkArea;
        Width = Math.Clamp(screen.Width * 0.94, MinWidth, 1720);
        Height = Math.Clamp(screen.Height * 0.94, MinHeight, 1040);
        StateChanged += (_, _) => ApplyWindowState();
        // "Show in the list" on the Overview: once the list is on screen, go to the game's row.
        void Hook(object? context)
        {
            if (context is MainViewModel vm)
                vm.JumpToGameRequested += () => Dispatcher.BeginInvoke(JumpToGame, System.Windows.Threading.DispatcherPriority.ContextIdle);
        }
        Hook(DataContext);
        DataContextChanged += (_, e) => Hook(e.NewValue);
        // The build's card hangs from the right end of the title bar: lined up by its right edge, it stays inside the window.
        BuildPopup.CustomPopupPlacementCallback = (card, button, _) =>
            [new System.Windows.Controls.Primitives.CustomPopupPlacement(new Point(button.Width - card.Width, button.Height), System.Windows.Controls.Primitives.PopupPrimaryAxis.Horizontal)];
        // The sidebar is taller than the window: keep the selected page in view, however it was picked.
        AddHandler(System.Windows.Controls.Primitives.ToggleButton.CheckedEvent, new RoutedEventHandler((_, e) =>
        {
            if (e.OriginalSource is RadioButton { GroupName: "nav" } nav) nav.BringIntoView();
        }));
        // A new file list opens sorted by Last run, newest first, with the arrow on that header like any other sort.
        // Applied after the table takes the list: a DataGrid clears the sort when its ItemsSource changes.
        System.ComponentModel.DependencyPropertyDescriptor.FromProperty(ItemsControl.ItemsSourceProperty, typeof(DataGrid))
            .AddValueChanged(FilesGrid, (_, _) =>
            {
                Vm.SortFilesByLastRun();
                foreach (var column in FilesGrid.Columns)
                    column.SortDirection = column.SortMemberPath == nameof(FileRow.LastRunKey) ? System.ComponentModel.ListSortDirection.Descending : null;
            });
    }

    // A maximized WindowChrome window overhangs the screen by the resize border; pad it back in.
    void ApplyWindowState()
    {
        bool max = WindowState == WindowState.Maximized;
        Root.BorderThickness = max ? new Thickness(0) : new Thickness(1);
        Root.Padding = max ? new Thickness(7) : new Thickness(0);
        MaxButton.Content = max ? "" : "";
    }

    void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    void Close_Click(object sender, RoutedEventArgs e) => Close();

    void JumpToGame_Click(object sender, RoutedEventArgs e) => JumpToGame();

    /// <summary>
    /// Brings the row where the game started into view and selects it: the game's own row when the list has it, otherwise
    /// the first thing that happened after its start. Works whatever the list is sorted by.
    /// </summary>
    void JumpToGame()
    {
        if (Vm.GameStartUtc is not { } start) return;
        var grid = Vm.Page == "Timeline" ? (Vm.TimelineByFolder ? null : TimelineGrid) : Vm.IsFilePage ? FilesGrid : null;
        if (grid == null) return;
        object? target = null;
        var closest = DateTime.MaxValue;
        string game = Vm.GamePath;
        foreach (var item in grid.Items)
        {
            var (time, path) = item switch { FileRow f => (f.LastRun, f.Path), EvidenceRow r => (r.Time, r.Path), _ => ((DateTime?)null, "") };
            if (time is not { } t) continue;
            if (game.Length > 0 && path.Equals(game, StringComparison.OrdinalIgnoreCase) && (t - start).Duration() < TimeSpan.FromMinutes(2))
            {
                target = item;
                break;
            }
            if (t >= start && t < closest) (closest, target) = (t, item);
        }
        if (target == null) return;
        grid.SelectedItem = target;
        grid.ScrollIntoView(target);
        grid.Focus();
    }

    /// <summary>A period was picked from the list in the title bar: the list closes.</summary>
    void Period_Click(object sender, RoutedEventArgs e) => PeriodToggle.IsChecked = false;

    /// <summary>The hash or the check command was copied from the build's card: the card closes, which is the sign that it was.</summary>
    void Build_Click(object sender, RoutedEventArgs e) => BuildToggle.IsChecked = false;

    void FilesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FilesGrid.SelectedItem is { } item) FilesGrid.ScrollIntoView(item);
    }

    TextBox? SearchBoxForPage() => Vm.IsFilePage ? FileSearchBox : Vm.Page switch
    {
        "Findings" => FindingSearchBox,
        "Inconsistencies" => FindingSearchBox,
        "Commands" => CommandSearchBox,
        "Timeline" => TimelineSearchBox,
        "Memory" => MemorySearchBox,
        _ => null,
    };

    /// <summary>The sidebar's pages in the order they are listed: Ctrl+1…9 opens one, Ctrl+Page Up / Page Down steps through them.</summary>
    static readonly string[] NavOrder =
        ["Overview", "Findings", "Programs", "Commands", "Tamper:Arguments", "Tamper:Usb", "Timeline", "Memory", "Integrity", "Tamper:Antivirus", "Tamper:Logs", "Tamper:Evidence"];

    bool GoTo(int index)
    {
        if (index < 0 || index >= NavOrder.Length) return false;
        string target = NavOrder[index];
        if (target.StartsWith("Tamper:", StringComparison.Ordinal) && !Vm.Tamper.HasResults) return false; // an older report without those pages
        Vm.NavPage = target;
        return true;
    }

    void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (!Vm.HasResults) return;
        bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
        if (ctrl && e.Key == Key.G)
        {
            JumpToGame();
            e.Handled = true;
            return;
        }

        if (ctrl && e.Key is >= Key.D1 and <= Key.D9)
        {
            if (GoTo(e.Key - Key.D1)) e.Handled = true;
            return;
        }
        if (ctrl && e.Key is Key.PageDown or Key.PageUp)
        {
            int now = Array.IndexOf(NavOrder, Vm.IsFilePage ? "Programs" : Vm.IsFindingPage ? "Findings" : Vm.NavPage), step = e.Key == Key.PageDown ? 1 : -1;
            for (int i = now + step; i >= 0 && i < NavOrder.Length; i += step)
                if (GoTo(i)) break;
            e.Handled = true;
            return;
        }

        if (ctrl && e.Key == Key.F && SearchBoxForPage() is { } box)
        {
            box.Focus();
            box.SelectAll();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && Keyboard.FocusedElement is TextBox { Text.Length: > 0 } focused && focused == SearchBoxForPage())
        {
            focused.Clear();
            e.Handled = true;
        }
        else if (ctrl && e.Key == Key.C && Keyboard.FocusedElement is not TextBox)
        {
            // Copy the most useful field of the selected row instead of WPF's empty cell copy.
            string? text = Vm.Page switch
            {
                "Commands" => (CommandsGrid.SelectedItem as CommandRow)?.Command,
                "Timeline" => (TimelineGrid.SelectedItem as EvidenceRow)?.Path,
                "Memory" => (MemoryGrid.SelectedItem as HistoryParser.Core.Models.MemoryHit)?.Path,
                _ when Vm.IsFilePage => Vm.SelectedFile?.Path,
                _ when Vm.IsFindingPage && Vm.SelectedFinding is { } finding => finding.Title + Environment.NewLine + finding.Detail,
                _ => null,
            };
            if (text != null && Vm.CopyCommand.CanExecute(text))
            {
                Vm.CopyCommand.Execute(text);
                e.Handled = true;
            }
        }
    }
}
