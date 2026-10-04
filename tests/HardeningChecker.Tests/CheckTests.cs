using HardeningChecker.Core;
using static HardeningChecker.Tests.FakeProbe;

namespace HardeningChecker.Tests;

public class CheckTests
{
    private static CheckStatus Run(string id, FakeProbe probe) =>
        Scanner.Evaluate(CheckCatalog.All.Single(c => c.Id == id), probe).Status;

    private const string Lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";

    [Fact]
    public void Smb1_enabled_fails_disabled_passes_absent_passes()
    {
        Assert.Equal(CheckStatus.Fail, Run("NET-001", new FakeProbe().Wmi("SMB1Protocol", Row(("InstallState", 1u)))));
        Assert.Equal(CheckStatus.Pass, Run("NET-001", new FakeProbe().Wmi("SMB1Protocol", Row(("InstallState", 2u)))));
        Assert.Equal(CheckStatus.Pass, Run("NET-001", new FakeProbe()));
    }

    [Theory]
    [InlineData(0, CheckStatus.Pass)]
    [InlineData(1, CheckStatus.Fail)]
    [InlineData(null, CheckStatus.Fail)]
    public void Llmnr(int? value, CheckStatus expected) =>
        Assert.Equal(expected, Run("NET-004", new FakeProbe().Reg(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", value)));

    [Fact]
    public void Netbios_warns_when_any_interface_is_not_disabled()
    {
        const string root = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
        var probe = new FakeProbe().SubKeys(root, "Tcpip_a", "Tcpip_b")
            .Reg($@"{root}\Tcpip_a", "NetbiosOptions", 2)
            .Reg($@"{root}\Tcpip_b", "NetbiosOptions", 0);
        Assert.Equal(CheckStatus.Warning, Run("NET-005", probe));
        probe.Reg($@"{root}\Tcpip_b", "NetbiosOptions", 2);
        Assert.Equal(CheckStatus.Pass, Run("NET-005", probe));
    }

    [Fact]
    public void Rdp_is_not_applicable_when_disabled_and_fails_without_nla()
    {
        const string ts = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
        Assert.Equal(CheckStatus.NotApplicable, Run("NET-006", new FakeProbe().Reg(ts, "fDenyTSConnections", 1)));
        var on = new FakeProbe().Reg(ts, "fDenyTSConnections", 0).Reg($@"{ts}\WinStations\RDP-Tcp", "UserAuthentication", 0);
        Assert.Equal(CheckStatus.Fail, Run("NET-006", on));
        on.Reg($@"{ts}\WinStations\RDP-Tcp", "UserAuthentication", 1);
        Assert.Equal(CheckStatus.Pass, Run("NET-006", on));
    }

    [Fact]
    public void Firewall_fails_if_one_profile_is_off()
    {
        var probe = new FakeProbe().Wmi("MSFT_NetFirewallProfile",
            Row(("Name", "Domain"), ("Enabled", (ushort)1)),
            Row(("Name", "Public"), ("Enabled", (ushort)0)));
        Assert.Equal(CheckStatus.Fail, Run("NET-007", probe));
    }

    [Theory]
    [InlineData(1, CheckStatus.Fail)]
    [InlineData(0, CheckStatus.Pass)]
    [InlineData(null, CheckStatus.Pass)]
    public void Wdigest(int? value, CheckStatus expected) =>
        Assert.Equal(expected, Run("CRED-001", new FakeProbe().Reg(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", value)));

    [Theory]
    [InlineData(null, CheckStatus.Warning)]
    [InlineData(1, CheckStatus.Fail)]
    [InlineData(3, CheckStatus.Warning)]
    [InlineData(5, CheckStatus.Pass)]
    public void Lm_compatibility_level(int? value, CheckStatus expected) =>
        Assert.Equal(expected, Run("CRED-004", new FakeProbe().Reg(Lsa, "LmCompatibilityLevel", value)));

    [Fact]
    public void Credential_guard_reads_running_services()
    {
        var running = new FakeProbe().Wmi("Win32_DeviceGuard", Row(("SecurityServicesRunning", new uint[] { 1, 2 })));
        Assert.Equal(CheckStatus.Pass, Run("CRED-003", running));
        var off = new FakeProbe().Wmi("Win32_DeviceGuard", Row(("SecurityServicesRunning", new uint[] { 2 })));
        Assert.Equal(CheckStatus.Warning, Run("CRED-003", off));
    }

    [Fact]
    public void Uac_fails_when_admins_are_elevated_without_prompt()
    {
        const string sys = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Assert.Equal(CheckStatus.Fail, Run("ACC-001", new FakeProbe().Reg(sys, "EnableLUA", 1).Reg(sys, "ConsentPromptBehaviorAdmin", 0)));
        Assert.Equal(CheckStatus.Fail, Run("ACC-001", new FakeProbe().Reg(sys, "EnableLUA", 0)));
        Assert.Equal(CheckStatus.Pass, Run("ACC-001", new FakeProbe().Reg(sys, "EnableLUA", 1).Reg(sys, "ConsentPromptBehaviorAdmin", 5)));
    }

    [Fact]
    public void Guest_account_is_found_by_rid_not_by_name()
    {
        var probe = new FakeProbe().Wmi("Win32_UserAccount",
            Row(("Name", "Gast"), ("SID", "S-1-5-21-1-2-3-501"), ("Disabled", false)),
            Row(("Name", "Administrator"), ("SID", "S-1-5-21-1-2-3-500"), ("Disabled", true)));
        Assert.Equal(CheckStatus.Fail, Run("ACC-002", probe));
        Assert.Equal(CheckStatus.Pass, Run("ACC-003", probe));
    }

    [Fact]
    public void Antivirus_accepts_third_party_product_on_client()
    {
        var probe = new FakeProbe()
            .Wmi("MSFT_MpComputerStatus", Row(("RealTimeProtectionEnabled", false), ("AntivirusEnabled", false), ("AMRunningMode", "Passive Mode")))
            .Wmi("AntiVirusProduct", Row(("displayName", "Example AV"), ("productState", 397568L)));
        Assert.Equal(CheckStatus.Pass, Run("DEF-001", probe));
        Assert.Equal(CheckStatus.NotApplicable, Run("DEF-002", probe));
    }

    [Fact]
    public void Antivirus_fails_when_nothing_is_active()
    {
        var probe = new FakeProbe()
            .Wmi("MSFT_MpComputerStatus", Row(("RealTimeProtectionEnabled", false), ("AntivirusEnabled", true), ("AMRunningMode", "Normal")))
            .Wmi("AntiVirusProduct", Row(("displayName", "Windows Defender"), ("productState", 393472L)));
        Assert.Equal(CheckStatus.Fail, Run("DEF-001", probe));
    }

    [Fact]
    public void Bitlocker_needs_admin_when_access_is_denied_and_not_elevated()
    {
        var probe = new FakeProbe { IsElevated = false }.WmiThrows("Win32_EncryptableVolume", new UnauthorizedAccessException());
        Assert.Equal(CheckStatus.NeedsAdmin, Run("SYS-002", probe));
    }

    [Fact]
    public void Bitlocker_unavailable_edition_is_a_warning()
    {
        var probe = new FakeProbe().WmiThrows("Win32_EncryptableVolume", new ProbeUnavailableException("no namespace"));
        Assert.Equal(CheckStatus.Warning, Run("SYS-002", probe));
    }

    [Fact]
    public void Updates_use_most_recent_install_date()
    {
        var recent = DateTime.Today.AddDays(-5).ToString("M/d/yyyy", System.Globalization.CultureInfo.InvariantCulture);
        var probe = new FakeProbe().Wmi("Win32_QuickFixEngineering",
            Row(("HotFixID", "KB1"), ("InstalledOn", "1/1/2020")),
            Row(("HotFixID", "KB2"), ("InstalledOn", recent)));
        Assert.Equal(CheckStatus.Pass, Run("SYS-004", probe));
        var old = new FakeProbe().Wmi("Win32_QuickFixEngineering", Row(("HotFixID", "KB1"), ("InstalledOn", "1/1/2020")));
        Assert.Equal(CheckStatus.Fail, Run("SYS-004", old));
    }

    [Theory]
    [InlineData("3/7/2026", 2026, 3, 7)]
    [InlineData("07.03.2026", 2026, 3, 7)]
    [InlineData("2026-03-07", 2026, 3, 7)]
    public void Date_parsing_handles_common_formats(string input, int y, int m, int d) =>
        Assert.Equal(new DateTime(y, m, d), CheckCatalog.ParseDate(input));

    [Fact]
    public void Unexpected_exception_becomes_error_not_crash()
    {
        var probe = new FakeProbe().WmiThrows("MSFT_NetFirewallProfile", new InvalidOperationException("boom"));
        var result = Scanner.Evaluate(CheckCatalog.All.Single(c => c.Id == "NET-007"), probe);
        Assert.Equal(CheckStatus.Error, result.Status);
        Assert.Contains("boom", result.Evidence);
    }
}
