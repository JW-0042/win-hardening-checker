using System.Text.Json;
using HardeningChecker.Core;

namespace HardeningChecker.Tests;

public class CatalogAndReportTests
{
    [Fact]
    public void Check_ids_are_unique()
    {
        var ids = CheckCatalog.All.Select(c => c.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    [Fact]
    public void Every_check_is_documented()
    {
        foreach (var c in CheckCatalog.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Title), c.Id);
            Assert.False(string.IsNullOrWhiteSpace(c.Description), c.Id);
            Assert.False(string.IsNullOrWhiteSpace(c.Rationale), c.Id);
            Assert.False(string.IsNullOrWhiteSpace(c.Remediation), c.Id);
            Assert.NotEmpty(c.References);
            Assert.All(c.References, r => Assert.StartsWith("https://", r.Url));
        }
    }

    [Fact]
    public void Texts_use_plain_punctuation()
    {
        // House style: no em dashes or semicolons between sentences in user-facing text.
        foreach (var c in CheckCatalog.All)
        {
            foreach (var t in new[] { c.Title, c.Description, c.Rationale, c.Remediation })
            {
                Assert.DoesNotContain("—", t);
                Assert.DoesNotContain("; ", t);
            }
        }
    }

    private static ScanReport SampleReport() => Scanner.Run(new FakeProbe()
        .Reg(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 1)
        .Wmi("Win32_UserAccount", FakeProbe.Row(("Name", "<script>"), ("SID", "S-1-5-21-1-500"), ("Disabled", false))));

    [Fact]
    public void Score_is_within_range_and_failures_lower_it()
    {
        var report = SampleReport();
        Assert.InRange(report.Score, 0, 100);
        Assert.True(report.Count(CheckStatus.Fail) > 0);
        Assert.True(report.Score < 100);
    }

    [Fact]
    public void Html_report_encodes_untrusted_values()
    {
        var html = Reports.ToHtml(SampleReport());
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void Json_report_is_valid_and_complete()
    {
        var report = SampleReport();
        using var doc = JsonDocument.Parse(Reports.ToJson(report));
        Assert.Equal(CheckCatalog.All.Count, doc.RootElement.GetProperty("results").GetArrayLength());
        Assert.Equal(report.Score, doc.RootElement.GetProperty("score").GetInt32());
    }
}
