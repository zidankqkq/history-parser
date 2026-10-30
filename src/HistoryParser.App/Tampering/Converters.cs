using System.Globalization;
using System.Windows.Data;

namespace HistoryParser.App.Tampering;

/// <summary>Bytes → "12.3 MB".</summary>
public sealed class SizeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        long b when b >= 1024L * 1024 * 1024 => $"{b / (1024.0 * 1024 * 1024):0.#} GB",
        long b when b >= 1024 * 1024 => $"{b / (1024.0 * 1024):0.#} MB",
        long b => $"{b / 1024.0:0} KB",
        _ => "—",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>true → "Yes", false → "No", null → "—".</summary>
public sealed class YesNoConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is bool b ? (b ? "Yes" : "No") : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>A selected row as copyable text (records print every column).</summary>
public sealed class RowText : IValueConverter
{
    public static readonly RowText Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value?.ToString();

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}
