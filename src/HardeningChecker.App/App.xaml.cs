using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace HardeningChecker.App;

public partial class App : Application
{
    // HardeningChecker.exe --screenshot <file.png> [--theme light|dark]
    // Runs a scan, renders the main window to a PNG and exits. Used for the README screenshots.
    protected override async void OnStartup(StartupEventArgs e)
    {
        var args = e.Args;
        var i = Array.IndexOf(args, "--screenshot");
        base.OnStartup(e);
        if (i < 0 || i + 1 >= args.Length)
        {
            MainWindow = new MainWindow();
            MainWindow.Show();
            return;
        }

        var path = Path.GetFullPath(args[i + 1]);
        try
        {
            await RenderScreenshotAsync(args, path);
            Shutdown(0);
        }
        catch (Exception ex)
        {
            File.WriteAllText(path + ".error.txt", ex.ToString());
            Shutdown(1);
        }
    }

    private async Task RenderScreenshotAsync(string[] args, string path)
    {
        var t = Array.IndexOf(args, "--theme");
        if (t >= 0 && t + 1 < args.Length)
        {
            ThemeMode = args[t + 1] == "dark" ? ThemeMode.Dark : ThemeMode.Light;
        }

        MainViewModel.MachineNameOverride = "DEMO-PC";
        var window = new MainWindow { Left = -20000, Top = -20000, ShowActivated = false, WindowStartupLocation = WindowStartupLocation.Manual };
        window.Show();
        var vm = (MainViewModel)window.DataContext;
        await vm.ScanAsync();
        vm.Selected = vm.Items.FirstOrDefault(x => x.HasCommand) ?? vm.Items.FirstOrDefault();
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);

        var content = (FrameworkElement)window.Content;
        var dpi = VisualTreeHelper.GetDpi(window);
        var bmp = new RenderTargetBitmap(
            (int)(content.ActualWidth * dpi.DpiScaleX), (int)(content.ActualHeight * dpi.DpiScaleY),
            dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        var bg = new DrawingVisual();
        using (var dc = bg.RenderOpen())
        {
            dc.DrawRectangle(BackgroundFor(window), null, new Rect(0, 0, content.ActualWidth, content.ActualHeight));
        }
        bmp.Render(bg);
        bmp.Render(content);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        await using (var fs = File.Create(path))
        {
            encoder.Save(fs);
        }
    }

    // Offscreen rendering skips the window chrome, so paint the theme background ourselves.
    private Brush BackgroundFor(Window window)
    {
        if (window.Background is SolidColorBrush { Color.A: 255 } solid) return solid;
        if (window.TryFindResource("ApplicationBackgroundBrush") is SolidColorBrush { Color.A: 255 } themed) return themed;
        return ThemeMode == ThemeMode.Dark
            ? new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20))
            : new SolidColorBrush(Color.FromRgb(0xF3, 0xF3, 0xF3));
    }
}
