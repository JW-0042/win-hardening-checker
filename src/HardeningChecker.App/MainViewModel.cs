using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using HardeningChecker.Core;

namespace HardeningChecker.App;

public sealed class OutcomeItem(CheckOutcome outcome)
{
    public CheckOutcome Outcome { get; } = outcome;
    public string Id => Outcome.Check.Id;
    public string Title => Outcome.Check.Title;
    public string Category => Outcome.Check.Category.ToString();
    public string Severity => Outcome.Check.Severity.ToString();
    public CheckStatus Status => Outcome.Result.Status;
    public string StatusLabel => Reports.StatusLabel(Status);
    public string Evidence => Outcome.Result.Evidence;
    public string Description => Outcome.Check.Description;
    public string Rationale => Outcome.Check.Rationale;
    public string Remediation => Outcome.Check.Remediation;
    public string? RemediationCommand => Outcome.Check.RemediationCommand;
    public bool HasCommand => !string.IsNullOrEmpty(RemediationCommand);
    public IReadOnlyList<Reference> References => Outcome.Check.References;
    public int SortKey => Reports.Rank(Status) * 10 - (int)Outcome.Check.Severity;
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ISystemProbe _probe = new WindowsSystemProbe();
    private List<OutcomeItem> _all = [];
    private ScanReport? _report;
    private bool _isScanning;
    private string _filter = "All";
    private string _search = "";
    private OutcomeItem? _selected;
    private int _progress;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<OutcomeItem> Items { get; } = [];

    public IReadOnlyList<string> Filters { get; } = ["All", "Fail", "Warning", "Pass", "Needs admin", "Not applicable"];

    public bool IsElevated => _probe.IsElevated;
    // Screenshot mode sets a neutral name so the real machine name never ends up in public images.
    public static string? MachineNameOverride { get; set; }

    public string MachineLine => $"{MachineNameOverride ?? Environment.MachineName} · {_probe.Os.Caption}";
    public string ElevationLine => IsElevated ? "Running as administrator" : "Not running as administrator. Some checks need admin rights.";
    public int CheckCount => CheckCatalog.All.Count;

    public ScanReport? Report { get => _report; private set { _report = value; OnChanged(); OnChanged(nameof(HasReport)); OnChanged(nameof(ScoreText)); OnChanged(nameof(SummaryText)); } }
    public bool HasReport => _report is not null;
    public string ScoreText => _report is null ? "–" : _report.Score.ToString();
    public string SummaryText => _report is null
        ? "Press Scan to check this computer. The scan only reads settings and changes nothing."
        : $"{_report.Count(CheckStatus.Fail)} failed · {_report.Count(CheckStatus.Warning)} warnings · {_report.Count(CheckStatus.Pass)} passed · {_report.Count(CheckStatus.NeedsAdmin)} need admin";

    public bool IsScanning { get => _isScanning; private set { _isScanning = value; OnChanged(); OnChanged(nameof(CanScan)); } }
    public bool CanScan => !_isScanning;
    public int Progress { get => _progress; private set { _progress = value; OnChanged(); } }

    public string Filter { get => _filter; set { _filter = value; OnChanged(); ApplyFilter(); } }
    public string Search { get => _search; set { _search = value; OnChanged(); ApplyFilter(); } }

    public OutcomeItem? Selected { get => _selected; set { _selected = value; OnChanged(); OnChanged(nameof(HasSelection)); } }
    public bool HasSelection => _selected is not null;

    public async Task ScanAsync()
    {
        IsScanning = true;
        Progress = 0;
        Items.Clear();
        Selected = null;
        var progress = new Progress<CheckOutcome>(_ => Progress++);
        try
        {
            Report = await Task.Run(() => Scanner.Run(_probe, progress: progress));
            _all = Report.Outcomes.Select(o => new OutcomeItem(o)).OrderBy(i => i.SortKey).ToList();
            ApplyFilter();
            Selected = Items.FirstOrDefault();
        }
        finally
        {
            IsScanning = false;
        }
    }

    private void ApplyFilter()
    {
        var keepSelected = Selected;
        Items.Clear();
        foreach (var item in _all)
        {
            if (_filter != "All" && item.StatusLabel != _filter) continue;
            if (_search.Length > 0
                && !item.Title.Contains(_search, StringComparison.OrdinalIgnoreCase)
                && !item.Id.Contains(_search, StringComparison.OrdinalIgnoreCase)
                && !item.Category.Contains(_search, StringComparison.OrdinalIgnoreCase)) continue;
            Items.Add(item);
        }
        Selected = keepSelected is not null && Items.Contains(keepSelected) ? keepSelected : Items.FirstOrDefault();
    }

    private void OnChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
