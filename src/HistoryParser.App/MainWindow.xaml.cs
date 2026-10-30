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
        StateChanged += (_, _) => ApplyWindowState();
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

    void FilesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FilesGrid.SelectedItem is { } item) FilesGrid.ScrollIntoView(item);
    }

    TextBox? SearchBoxForPage() => Vm.IsFilePage ? FileSearchBox : Vm.Page switch
    {
        "Findings" => FindingSearchBox,
        "Inconsistencies" => InconsistencySearchBox,
        "Commands" => CommandSearchBox,
        "Timeline" => TimelineSearchBox,
        "Memory" => MemorySearchBox,
        _ => null,
    };

    void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (!Vm.HasResults) return;
        bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;

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
