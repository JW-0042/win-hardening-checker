using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Navigation;
using HardeningChecker.Core;
using Microsoft.Win32;

namespace HardeningChecker.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private MainViewModel Vm => (MainViewModel)DataContext;

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await Vm.ScanAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Scan failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Elevate_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
            Application.Current.Shutdown();
        }
        catch (Win32Exception)
        {
            // The user cancelled the UAC prompt. Keep running without elevation.
        }
    }

    private void ExportHtml_Click(object sender, RoutedEventArgs e) =>
        Export("HTML report|*.html", "html", Reports.ToHtml);

    private void ExportJson_Click(object sender, RoutedEventArgs e) =>
        Export("JSON report|*.json", "json", Reports.ToJson);

    private void Export(string filter, string extension, Func<ScanReport, string> render)
    {
        if (Vm.Report is null) return;
        var dialog = new SaveFileDialog
        {
            Filter = filter,
            FileName = $"hardening-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmm}.{extension}",
        };
        if (dialog.ShowDialog(this) != true) return;
        File.WriteAllText(dialog.FileName, render(Vm.Report));
        if (extension == "html") Process.Start(new ProcessStartInfo(dialog.FileName) { UseShellExecute = true });
    }

    private void CopyCommand_Click(object sender, RoutedEventArgs e)
    {
        if (Vm.Selected?.RemediationCommand is { } cmd) Clipboard.SetText(cmd);
    }

    private void Link_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
