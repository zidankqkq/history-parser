using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;


namespace HistoryParser.App.Tampering;

/// <summary>The tampering and bypass pages, bound to a <see cref="TamperViewModel"/>; shown inside History Parser's main window.</summary>
public partial class TamperView : UserControl
{
    TamperViewModel? Vm => DataContext as TamperViewModel;

    public TamperView()
    {
        InitializeComponent();
        // Clicking a row on a page with a details panel shows everything about it (rows without details are ignored).
        AddHandler(System.Windows.Controls.Primitives.Selector.SelectionChangedEvent, new SelectionChangedEventHandler((_, e) =>
        {
            if (Vm is { } vm && e.OriginalSource is DataGrid { SelectedItem: { } row } && vm.HasDetailsPanel && vm.Report != null &&
                DetailView.For(row, vm.Report) != null)
                vm.SelectedRow = row;
        }));
    }

    void View_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Vm is not { HasResults: true } vm) return;
        bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
        if (ctrl && e.Key == Key.F && vm.IsTablePage)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && Keyboard.FocusedElement == SearchBox && SearchBox.Text.Length > 0)
        {
            SearchBox.Clear();
            e.Handled = true;
        }
        else if (ctrl && e.Key == Key.C && Keyboard.FocusedElement is DataGridCell or DataGrid or DataGridRow)
        {
            // Copy the whole selected row as text (every column), which suits these mixed tables.
            if (FindParentGrid(Keyboard.FocusedElement as DependencyObject)?.SelectedItem is { } row)
            {
                vm.CopyCommand.Execute(row.ToString());
                e.Handled = true;
            }
        }
    }

    static DataGrid? FindParentGrid(DependencyObject? d)
    {
        while (d != null && d is not DataGrid) d = System.Windows.Media.VisualTreeHelper.GetParent(d);
        return d as DataGrid;
    }
}
