using System.Diagnostics;

namespace HardeningChecker.Core;

public static class Scanner
{
    /// <summary>Runs checks one by one. A failing check never stops the scan.</summary>
    public static ScanReport Run(ISystemProbe probe, IEnumerable<CheckDefinition>? checks = null, IProgress<CheckOutcome>? progress = null)
    {
        var started = DateTimeOffset.Now;
        var sw = Stopwatch.StartNew();
        var outcomes = new List<CheckOutcome>();
        foreach (var check in checks ?? CheckCatalog.All)
        {
            var outcome = new CheckOutcome(check, Evaluate(check, probe));
            outcomes.Add(outcome);
            progress?.Report(outcome);
        }
        return new ScanReport(Environment.MachineName, probe.Os, probe.IsElevated, started, sw.Elapsed, outcomes);
    }

    public static CheckResult Evaluate(CheckDefinition check, ISystemProbe probe)
    {
        try
        {
            return check.Evaluate(probe);
        }
        catch (UnauthorizedAccessException) when (!probe.IsElevated)
        {
            return new CheckResult(CheckStatus.NeedsAdmin, "This check needs administrator rights. Run the tool as administrator.");
        }
        catch (ProbeUnavailableException ex)
        {
            return CheckResult.NotApplicable(ex.Message);
        }
        catch (Exception ex)
        {
            return new CheckResult(CheckStatus.Error, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}
