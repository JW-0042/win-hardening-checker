namespace HardeningChecker.Core;

public enum Severity { Low = 1, Medium = 2, High = 3 }

public enum CheckStatus { Pass, Warning, Fail, NotApplicable, NeedsAdmin, Error }

public enum CheckCategory { Network, Credentials, Accounts, Defense, Logging, System }

public sealed record Reference(string Label, string Url);

public sealed record CheckResult(CheckStatus Status, string Evidence)
{
    public static CheckResult Pass(string evidence) => new(CheckStatus.Pass, evidence);
    public static CheckResult Warning(string evidence) => new(CheckStatus.Warning, evidence);
    public static CheckResult Fail(string evidence) => new(CheckStatus.Fail, evidence);
    public static CheckResult NotApplicable(string evidence) => new(CheckStatus.NotApplicable, evidence);
}

/// <summary>One read-only hardening check. Evaluate must never change system state.</summary>
public sealed record CheckDefinition(
    string Id,
    string Title,
    CheckCategory Category,
    Severity Severity,
    string Description,
    string Rationale,
    string Remediation,
    string? RemediationCommand,
    IReadOnlyList<Reference> References,
    Func<ISystemProbe, CheckResult> Evaluate);

public sealed record CheckOutcome(CheckDefinition Check, CheckResult Result);

public sealed record OsInfo(string Caption, string Build, bool IsServer);

public sealed record ScanReport(
    string MachineName,
    OsInfo Os,
    bool IsElevated,
    DateTimeOffset StartedAt,
    TimeSpan Duration,
    IReadOnlyList<CheckOutcome> Outcomes)
{
    /// <summary>Weighted score 0 to 100 from checks that produced a verdict (pass, warning, fail).</summary>
    public int Score
    {
        get
        {
            double possible = 0, earned = 0;
            foreach (var o in Outcomes)
            {
                var weight = (int)o.Check.Severity;
                switch (o.Result.Status)
                {
                    case CheckStatus.Pass: possible += weight; earned += weight; break;
                    case CheckStatus.Warning: possible += weight; earned += weight / 2.0; break;
                    case CheckStatus.Fail: possible += weight; break;
                }
            }
            return possible == 0 ? 0 : (int)Math.Round(earned / possible * 100);
        }
    }

    public int Count(CheckStatus status) => Outcomes.Count(o => o.Result.Status == status);
}
