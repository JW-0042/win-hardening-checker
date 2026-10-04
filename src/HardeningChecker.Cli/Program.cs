using HardeningChecker.Core;

// hardening-check [--json <file>] [--html <file>] [--quiet]
// Exit codes: 0 = no failed checks, 1 = at least one failed check, 2 = invalid arguments.

string? jsonPath = null, htmlPath = null;
var quiet = false;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--json" when i + 1 < args.Length: jsonPath = args[++i]; break;
        case "--html" when i + 1 < args.Length: htmlPath = args[++i]; break;
        case "--quiet": quiet = true; break;
        case "-h" or "--help" or "/?":
            Console.WriteLine("Hardening Checker: read-only Windows security baseline scan.");
            Console.WriteLine("Usage: hardening-check [--json <file>] [--html <file>] [--quiet]");
            Console.WriteLine("Exit code 0 = no failed checks, 1 = failed checks found.");
            return 0;
        default:
            Console.Error.WriteLine($"Unknown argument: {args[i]}. Use --help.");
            return 2;
    }
}

var probe = new WindowsSystemProbe();
var report = Scanner.Run(probe);

if (!quiet)
{
    Console.WriteLine($"Hardening Checker · {report.MachineName} · {report.Os.Caption} (build {report.Os.Build})");
    if (!report.IsElevated) Console.WriteLine("Not running as administrator: some checks will report 'Needs admin'.");
    Console.WriteLine();
    foreach (var o in report.Outcomes.OrderBy(o => Reports.Rank(o.Result.Status)).ThenByDescending(o => o.Check.Severity))
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = o.Result.Status switch
        {
            CheckStatus.Pass => ConsoleColor.Green,
            CheckStatus.Warning => ConsoleColor.Yellow,
            CheckStatus.Fail => ConsoleColor.Red,
            CheckStatus.NeedsAdmin => ConsoleColor.Magenta,
            _ => ConsoleColor.Gray,
        };
        Console.Write($"{Reports.StatusLabel(o.Result.Status),-15}");
        Console.ForegroundColor = prev;
        Console.WriteLine($"{o.Check.Id,-9} {o.Check.Title}");
        Console.WriteLine($"{"",-24}{o.Result.Evidence}");
    }
    Console.WriteLine();
    Console.WriteLine($"Score: {report.Score}/100 · pass {report.Count(CheckStatus.Pass)} · warning {report.Count(CheckStatus.Warning)} · fail {report.Count(CheckStatus.Fail)} · needs admin {report.Count(CheckStatus.NeedsAdmin)} · {report.Duration.TotalSeconds:0.0} s");
}

if (jsonPath is not null) File.WriteAllText(jsonPath, Reports.ToJson(report));
if (htmlPath is not null) File.WriteAllText(htmlPath, Reports.ToHtml(report));

return report.Count(CheckStatus.Fail) > 0 ? 1 : 0;
