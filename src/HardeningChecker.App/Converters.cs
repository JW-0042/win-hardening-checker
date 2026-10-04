using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using HardeningChecker.Core;

namespace HardeningChecker.App;

/// <summary>Status to accent brush. Colors are chosen to read well in both light and dark themes.</summary>
public sealed class StatusBrushConverter : IValueConverter
{
    private static readonly Dictionary<CheckStatus, SolidColorBrush> Brushes = new()
    {
        [CheckStatus.Pass] = Make(0x1F, 0x9D, 0x55),
        [CheckStatus.Warning] = Make(0xD9, 0xA4, 0x00),
        [CheckStatus.Fail] = Make(0xD9, 0x30, 0x25),
        [CheckStatus.NeedsAdmin] = Make(0x7C, 0x6B, 0xE0),
        [CheckStatus.NotApplicable] = Make(0x8A, 0x93, 0x9E),
        [CheckStatus.Error] = Make(0x8A, 0x93, 0x9E),
    };

    private static SolidColorBrush Make(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is CheckStatus s ? Brushes[s] : Brushes[CheckStatus.NotApplicable];

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        (value is true) ^ Invert ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
