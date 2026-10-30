using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using HistoryParser.Core.Models;

namespace HistoryParser.App.Converters;

/// <summary>UTC → the scanned machine's local time. Null shows as an em dash.</summary>
public sealed class LocalTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is DateTime t ? t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Severity / CheckState / FileStatus → brush. Parameter "soft" gives the tinted background variant.</summary>
public sealed class ToneBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string tone = value switch
        {
            Severity.High or CheckState.Bad => "High",
            Severity.Medium or CheckState.Warning => "Medium",
            Severity.Low => "Low",
            CheckState.Ok or FileStatus.Exists => "Ok",
            FileStatus.Deleted or FileStatus.InRecycleBin or FileStatus.Renamed => "High",
            FileStatus.Missing or FileStatus.DriveNotConnected => "Medium",
            bool b => b ? "Ok" : "High",
            _ => "Neutral",
        };
        string key = parameter as string == "soft" ? tone + "Soft" : tone;
        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Visible when the bound string equals the parameter (page switching).</summary>
public sealed class EqualsToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Equals(value?.ToString(), parameter?.ToString()) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Two-way bool for RadioButtons bound to a string property.</summary>
public sealed class EqualsToBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Equals(value?.ToString(), parameter?.ToString());

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? parameter! : Binding.DoNothing;
}

/// <summary>Collapsed for null, false, 0 and empty strings. Parameter "invert" flips it.</summary>
public sealed class VisibleWhenConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool visible = value switch
        {
            null => false,
            bool b => b,
            int i => i != 0,
            string s => s.Length > 0,
            System.Collections.ICollection c => c.Count > 0,
            _ => true,
        };
        if (parameter as string == "invert") visible = !visible;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class StatusTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        FileStatus s => Display.Status(s),
        SignatureStatus s => Display.Signature(s),
        _ => value?.ToString() ?? "",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Sidebar scan button label.</summary>
public sealed class ScanLabel : IValueConverter
{
    public static readonly ScanLabel Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? "New scan" : "Start scan";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class CategoryTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is FindingCategory c ? Display.Category(c) : value?.ToString() ?? "";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}
