using System.IO;
using System.Text;
using System.Windows;
using Microsoft.Win32;

namespace HistoryParser.App.ViewModels;

/// <summary>The save step every CSV export shares: ask where, then write it.</summary>
static class ExportDialog
{
    /// <summary>
    /// Asks where to save, then writes the text from <paramref name="content"/> (only built once a file was
    /// chosen) with a UTF-8 BOM so Excel reads it correctly.
    /// </summary>
    public static void SaveCsv(string fileName, Func<string> content)
    {
        var dialog = new SaveFileDialog { FileName = fileName, Filter = "CSV (*.csv)|*.csv" };
        if (dialog.ShowDialog() != true) return;
        try { File.WriteAllText(dialog.FileName, content(), new UTF8Encoding(true)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show($"Could not save the CSV: {e.Message}", "History Parser", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
