using System.Globalization;

namespace HardeningChecker.Core;

/// <summary>All built-in checks. Every check only reads state: registry, WMI. Nothing is changed.</summary>
public static class CheckCatalog
{
    private const string Lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string LanmanServer = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string LanmanWorkstation = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    private const string PolicySystem = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string Defender = @"root\Microsoft\Windows\Defender";

    private static readonly Reference Cis = new("CIS Microsoft Windows Benchmarks", "https://www.cisecurity.org/benchmark/microsoft_windows_desktop");

    private static Reference Attack(string id, string name) =>
        new($"MITRE ATT&CK {id}: {name}", $"https://attack.mitre.org/techniques/{id.Replace('.', '/')}/");

    private static Reference Ms(string label, string url) => new($"Microsoft: {label}", url);

    public static IReadOnlyList<CheckDefinition> All { get; } =
    [
        // ---------------- Network ----------------
        new("NET-001", "SMBv1 protocol is disabled", CheckCategory.Network, Severity.High,
            "Checks whether the legacy SMB 1.0 protocol is installed.",
            "SMBv1 has no modern security features and was the entry point for WannaCry and NotPetya. Nothing current needs it.",
            "Remove the SMB 1.0/CIFS File Sharing Support Windows feature.",
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            [Attack("T1210", "Exploitation of Remote Services"), Ms("Detect, enable and disable SMBv1", "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"), Cis],
            p => OptionalFeature(p, "SMB1Protocol") switch
            {
                FeatureState.Enabled => CheckResult.Fail("SMB1Protocol feature is installed and enabled."),
                FeatureState.Disabled => CheckResult.Pass("SMB1Protocol feature is disabled."),
                _ => CheckResult.Pass("SMB1Protocol feature is not present on this system."),
            }),

        new("NET-002", "SMB server requires signing", CheckCategory.Network, Severity.Medium,
            "Checks whether this machine requires signed SMB sessions when it shares files.",
            "Without required signing an attacker in the network path can relay or tamper with SMB traffic (NTLM relay).",
            "Set the policy \"Microsoft network server: Digitally sign communications (always)\" to Enabled.",
            "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
            [Attack("T1557", "Adversary-in-the-Middle"), Cis],
            p => p.Dword(LanmanServer, "RequireSecuritySignature") switch
            {
                1 => CheckResult.Pass("RequireSecuritySignature = 1"),
                0 => CheckResult.Fail("RequireSecuritySignature = 0"),
                _ => CheckResult.Warning("RequireSecuritySignature is not set explicitly. The default depends on the Windows version."),
            }),

        new("NET-003", "SMB client requires signing", CheckCategory.Network, Severity.Medium,
            "Checks whether this machine requires signed SMB sessions when it connects to file shares.",
            "Unsigned SMB client traffic can be intercepted and modified by an attacker on the network.",
            "Set the policy \"Microsoft network client: Digitally sign communications (always)\" to Enabled.",
            "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force",
            [Attack("T1557", "Adversary-in-the-Middle"), Cis],
            p => p.Dword(LanmanWorkstation, "RequireSecuritySignature") switch
            {
                1 => CheckResult.Pass("RequireSecuritySignature = 1"),
                0 => CheckResult.Fail("RequireSecuritySignature = 0"),
                _ => CheckResult.Warning("RequireSecuritySignature is not set explicitly. The default depends on the Windows version."),
            }),

        new("NET-004", "LLMNR is disabled", CheckCategory.Network, Severity.Medium,
            "Checks whether Link-Local Multicast Name Resolution is turned off by policy.",
            "LLMNR lets any machine on the local network answer name lookups. Tools like Responder use it to capture password hashes.",
            "Enable the policy \"Turn off multicast name resolution\" (Computer Configuration > Administrative Templates > Network > DNS Client).",
            @"New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord",
            [Attack("T1557.001", "Name Resolution Poisoning and SMB Relay"), Cis],
            p => p.Dword(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast") == 0
                ? CheckResult.Pass("EnableMulticast = 0 (LLMNR off)")
                : CheckResult.Fail("LLMNR is not disabled by policy (EnableMulticast is not 0).")),

        new("NET-005", "NetBIOS over TCP/IP is disabled", CheckCategory.Network, Severity.Low,
            "Checks the NetBIOS setting of every network interface.",
            "NetBIOS name resolution can be poisoned in the same way as LLMNR. Most modern networks do not need it.",
            "Disable NetBIOS over TCP/IP on each adapter (IPv4 properties > Advanced > WINS) or through DHCP option 001.",
            @"Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty $_.PSPath -Name NetbiosOptions -Value 2 }",
            [Attack("T1557.001", "Name Resolution Poisoning and SMB Relay")],
            p =>
            {
                const string root = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
                var interfaces = p.GetRegistrySubKeyNames(root);
                if (interfaces.Count == 0) return CheckResult.NotApplicable("No NetBT interfaces found.");
                var enabled = interfaces.Where(i => p.Dword($@"{root}\{i}", "NetbiosOptions") != 2).ToList();
                return enabled.Count == 0
                    ? CheckResult.Pass($"NetBIOS disabled on all {interfaces.Count} interfaces.")
                    : CheckResult.Warning($"NetBIOS not disabled on {enabled.Count} of {interfaces.Count} interfaces (value 0 = set by DHCP, 1 = enabled).");
            }),

        new("NET-006", "Remote Desktop requires Network Level Authentication", CheckCategory.Network, Severity.High,
            "If Remote Desktop is enabled, checks that users must authenticate before a session is created.",
            "Without NLA anyone who reaches the RDP port gets a login screen and the server spends resources before authentication, which widens the attack surface.",
            "Enable \"Require user authentication for remote connections by using Network Level Authentication\".",
            @"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1",
            [Attack("T1021.001", "Remote Services: Remote Desktop Protocol"), Cis],
            p =>
            {
                if (p.Dword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") != 0)
                    return CheckResult.NotApplicable("Remote Desktop is disabled.");
                return p.Dword(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication") == 1
                    ? CheckResult.Pass("Remote Desktop is enabled and requires NLA.")
                    : CheckResult.Fail("Remote Desktop is enabled without Network Level Authentication.");
            }),

        new("NET-007", "Windows Firewall is enabled for all profiles", CheckCategory.Network, Severity.High,
            "Checks the Domain, Private and Public firewall profiles.",
            "A disabled firewall profile exposes every listening service to the network the machine is connected to.",
            "Turn on Windows Defender Firewall for all three profiles.",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
            [Attack("T1686", "Disable or Modify System Firewall"), Cis],
            p =>
            {
                var rows = p.QueryWmi(@"root\StandardCimv2", "SELECT Name, Enabled FROM MSFT_NetFirewallProfile");
                if (rows.Count == 0) return CheckResult.Warning("No firewall profiles were returned.");
                var off = rows.Where(r => Convert.ToInt32(r["Enabled"] ?? 1) == 0).Select(r => r["Name"]?.ToString()).ToList();
                return off.Count == 0
                    ? CheckResult.Pass($"All {rows.Count} profiles are enabled.")
                    : CheckResult.Fail($"Disabled profiles: {string.Join(", ", off)}");
            }),

        // ---------------- Credentials ----------------
        new("CRED-001", "WDigest does not store plaintext passwords", CheckCategory.Credentials, Severity.High,
            "Checks that WDigest authentication is not configured to keep passwords in memory.",
            "With UseLogonCredential = 1 the LSASS process holds plaintext passwords that tools like Mimikatz can read.",
            "Set UseLogonCredential to 0 or remove the value.",
            @"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0",
            [Attack("T1003.001", "OS Credential Dumping: LSASS Memory"), Cis],
            p => p.Dword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential") == 1
                ? CheckResult.Fail("UseLogonCredential = 1 (plaintext passwords cached in LSASS).")
                : CheckResult.Pass("WDigest plaintext caching is off.")),

        new("CRED-002", "LSA protection (RunAsPPL) is enabled", CheckCategory.Credentials, Severity.Medium,
            "Checks whether LSASS runs as a protected process.",
            "A protected LSASS blocks most credential dumping tools from reading its memory, even with administrator rights.",
            "Enable \"Configure LSASS to run as a protected process\" or set RunAsPPL to 1 and restart.",
            @"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord",
            [Attack("T1003.001", "OS Credential Dumping: LSASS Memory"), Ms("Configure added LSA protection", "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection")],
            p => p.Dword(Lsa, "RunAsPPL") is 1 or 2
                ? CheckResult.Pass($"RunAsPPL = {p.Dword(Lsa, "RunAsPPL")}")
                : CheckResult.Fail("LSA protection is not enabled.")),

        new("CRED-003", "Credential Guard is running", CheckCategory.Credentials, Severity.Medium,
            "Checks whether Windows Defender Credential Guard is active.",
            "Credential Guard isolates secrets with virtualization so that pass-the-hash and pass-the-ticket attacks get much harder.",
            "Enable Virtualization Based Security and Credential Guard (requires a supported edition and hardware).",
            null,
            [Attack("T1550.002", "Use Alternate Authentication Material: Pass the Hash"), Ms("Credential Guard overview", "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/")],
            p =>
            {
                var row = p.QueryWmi(@"root\Microsoft\Windows\DeviceGuard", "SELECT SecurityServicesRunning FROM Win32_DeviceGuard").FirstOrDefault();
                var running = row?["SecurityServicesRunning"] as Array;
                var ids = running?.Cast<object>().Select(Convert.ToInt32).ToList() ?? [];
                return ids.Contains(1)
                    ? CheckResult.Pass("Credential Guard is running.")
                    : CheckResult.Warning("Credential Guard is not running. It needs Enterprise or Education edition, or Windows 11 22H2+ with supported hardware.");
            }),

        new("CRED-004", "NTLMv1 and LM are refused", CheckCategory.Credentials, Severity.Medium,
            "Checks the LAN Manager authentication level.",
            "LM and NTLMv1 responses can be cracked quickly. Level 5 sends only NTLMv2 and refuses LM and NTLM.",
            "Set \"Network security: LAN Manager authentication level\" to \"Send NTLMv2 response only. Refuse LM & NTLM\".",
            @"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord",
            [Attack("T1557", "Adversary-in-the-Middle"), Cis],
            p =>
            {
                var level = p.Dword(Lsa, "LmCompatibilityLevel");
                return level switch
                {
                    null => CheckResult.Warning("LmCompatibilityLevel is not set. Windows defaults to 3, CIS recommends 5."),
                    >= 5 => CheckResult.Pass($"LmCompatibilityLevel = {level}"),
                    >= 3 => CheckResult.Warning($"LmCompatibilityLevel = {level}. Recommended value is 5."),
                    _ => CheckResult.Fail($"LmCompatibilityLevel = {level}. LM or NTLMv1 responses are still sent."),
                };
            }),

        new("CRED-005", "Anonymous enumeration is restricted", CheckCategory.Credentials, Severity.Low,
            "Checks that anonymous users cannot list accounts and shares.",
            "Anonymous enumeration gives an attacker a free list of user names to target with password spraying.",
            "Enable \"Do not allow anonymous enumeration of SAM accounts and shares\".",
            @"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1 -Type DWord",
            [Attack("T1087", "Account Discovery"), Cis],
            p =>
            {
                if (p.Dword(Lsa, "RestrictAnonymousSAM") == 0)
                    return CheckResult.Fail("RestrictAnonymousSAM = 0 (anonymous SAM enumeration allowed).");
                return p.Dword(Lsa, "RestrictAnonymous") == 1
                    ? CheckResult.Pass("Anonymous enumeration of SAM accounts and shares is blocked.")
                    : CheckResult.Warning("SAM accounts are protected, but anonymous share enumeration is allowed (RestrictAnonymous is not 1).");
            }),

        // ---------------- Accounts ----------------
        new("ACC-001", "User Account Control is enabled", CheckCategory.Accounts, Severity.High,
            "Checks that UAC is on and administrators are asked before elevation.",
            "Without UAC every program an administrator starts runs with full rights, so one malicious download can take over the machine.",
            "Keep UAC enabled and do not set \"Elevate without prompting\" for administrators.",
            @"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1",
            [Attack("T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control"), Cis],
            p =>
            {
                if (p.Dword(PolicySystem, "EnableLUA") == 0) return CheckResult.Fail("UAC is disabled (EnableLUA = 0).");
                return p.Dword(PolicySystem, "ConsentPromptBehaviorAdmin") == 0
                    ? CheckResult.Fail("Administrators are elevated without any prompt (ConsentPromptBehaviorAdmin = 0).")
                    : CheckResult.Pass("UAC is enabled and administrators are prompted.");
            }),

        new("ACC-002", "Guest account is disabled", CheckCategory.Accounts, Severity.Medium,
            "Checks the built-in Guest account.",
            "An enabled Guest account allows access without a known password.",
            "Disable the built-in Guest account.",
            "Get-LocalUser | Where-Object SID -like '*-501' | Disable-LocalUser",
            [Attack("T1078.001", "Valid Accounts: Default Accounts"), Cis],
            p => BuiltInAccount(p, "-501") is { } a
                ? (a.Disabled ? CheckResult.Pass($"Guest account '{a.Name}' is disabled.") : CheckResult.Fail($"Guest account '{a.Name}' is enabled."))
                : CheckResult.NotApplicable("Built-in Guest account was not found.")),

        new("ACC-003", "Built-in Administrator account is disabled", CheckCategory.Accounts, Severity.Medium,
            "Checks the built-in Administrator account (RID 500).",
            "The RID 500 account is a well known target and is not subject to account lockout. Named personal admin accounts are safer and auditable.",
            "Disable the built-in Administrator and use named administrator accounts instead.",
            "Get-LocalUser | Where-Object SID -like '*-500' | Disable-LocalUser",
            [Attack("T1078.001", "Valid Accounts: Default Accounts"), Cis],
            p => BuiltInAccount(p, "-500") is { } a
                ? (a.Disabled ? CheckResult.Pass($"Built-in Administrator '{a.Name}' is disabled.") : CheckResult.Warning($"Built-in Administrator '{a.Name}' is enabled."))
                : CheckResult.NotApplicable("Built-in Administrator account was not found.")),

        new("ACC-004", "Local Administrators group is small", CheckCategory.Accounts, Severity.Low,
            "Lists members of the local Administrators group.",
            "Every additional administrator is another account whose compromise means full control of the machine.",
            "Remove members that do not need permanent administrator rights. Consider just-in-time elevation or LAPS.",
            "Get-LocalGroupMember -SID S-1-5-32-544",
            [Attack("T1078", "Valid Accounts"), Cis],
            p =>
            {
                var group = p.QueryWmi(@"root\cimv2", "SELECT Name, Domain FROM Win32_Group WHERE LocalAccount=True AND SID='S-1-5-32-544'").FirstOrDefault();
                if (group is null) return CheckResult.NotApplicable("Local Administrators group not found.");
                var q = $"ASSOCIATORS OF {{Win32_Group.Domain='{group["Domain"]}',Name='{group["Name"]}'}} WHERE AssocClass=Win32_GroupUser Role=GroupComponent";
                var members = p.QueryWmi(@"root\cimv2", q).Select(m => $"{m["Domain"]}\\{m["Name"]}").ToList();
                var list = string.Join(", ", members);
                return members.Count <= 2
                    ? CheckResult.Pass($"{members.Count} member(s): {list}")
                    : CheckResult.Warning($"{members.Count} members: {list}");
            }),

        // ---------------- Defense ----------------
        new("DEF-001", "Antivirus real-time protection is on", CheckCategory.Defense, Severity.High,
            "Checks Microsoft Defender real-time protection, or another registered antivirus product.",
            "Without real-time protection malware runs without any check at the moment it is opened.",
            "Turn on real-time protection in Windows Security, or make sure your third-party antivirus is active.",
            "Set-MpPreference -DisableRealtimeMonitoring $false",
            [Attack("T1685", "Disable or Modify Tools"), Cis],
            p =>
            {
                try
                {
                    var mp = p.QueryWmi(Defender, "SELECT RealTimeProtectionEnabled, AntivirusEnabled, AMRunningMode FROM MSFT_MpComputerStatus").FirstOrDefault();
                    if (mp is not null && AsBool(mp["RealTimeProtectionEnabled"]) && AsBool(mp["AntivirusEnabled"]))
                        return CheckResult.Pass("Microsoft Defender real-time protection is on.");
                }
                catch (ProbeUnavailableException) { }

                if (p.Os.IsServer) return CheckResult.Fail("Microsoft Defender real-time protection is off.");
                var av = p.QueryWmi(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct")
                    .Where(r => ((Convert.ToInt64(r["productState"] ?? 0) >> 12) & 0xF) == 1)
                    .Select(r => r["displayName"]?.ToString())
                    .ToList();
                return av.Count > 0
                    ? CheckResult.Pass($"Active antivirus: {string.Join(", ", av)}")
                    : CheckResult.Fail("No antivirus with active real-time protection was found.");
            }),

        new("DEF-002", "Defender signatures are current", CheckCategory.Defense, Severity.Medium,
            "Checks the age of Microsoft Defender antivirus signatures.",
            "Old signatures miss recent malware families.",
            "Run Windows Update or update signatures manually.",
            "Update-MpSignature",
            [Attack("T1685", "Disable or Modify Tools")],
            p =>
            {
                var mp = p.QueryWmi(Defender, "SELECT AntivirusSignatureAge, AMRunningMode FROM MSFT_MpComputerStatus").FirstOrDefault();
                if (mp is null || IsPassive(mp)) return CheckResult.NotApplicable("Microsoft Defender is not the active antivirus.");
                var age = Convert.ToInt32(mp["AntivirusSignatureAge"] ?? 999);
                return age switch
                {
                    <= 3 => CheckResult.Pass($"Signatures are {age} day(s) old."),
                    <= 7 => CheckResult.Warning($"Signatures are {age} days old."),
                    _ => CheckResult.Fail($"Signatures are {age} days old."),
                };
            }),

        new("DEF-003", "Defender tamper protection is on", CheckCategory.Defense, Severity.Medium,
            "Checks Microsoft Defender tamper protection.",
            "Tamper protection stops malware and scripts from switching Defender off through the registry or PowerShell.",
            "Turn on Tamper Protection in Windows Security > Virus & threat protection settings, or through Intune.",
            null,
            [Attack("T1685", "Disable or Modify Tools"), Ms("Tamper protection", "https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview")],
            p =>
            {
                var mp = p.QueryWmi(Defender, "SELECT IsTamperProtected, AMRunningMode FROM MSFT_MpComputerStatus").FirstOrDefault();
                if (mp is null || IsPassive(mp)) return CheckResult.NotApplicable("Microsoft Defender is not the active antivirus.");
                return AsBool(mp["IsTamperProtected"])
                    ? CheckResult.Pass("Tamper protection is on.")
                    : CheckResult.Warning("Tamper protection is off.");
            }),

        // ---------------- Logging ----------------
        new("LOG-001", "PowerShell script block logging is enabled", CheckCategory.Logging, Severity.Medium,
            "Checks whether PowerShell records the content of executed script blocks.",
            "Most attacks use PowerShell at some point. Script block logging records even obfuscated code after it is decoded.",
            "Enable \"Turn on PowerShell Script Block Logging\" (Administrative Templates > Windows Components > Windows PowerShell).",
            @"New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord",
            [Attack("T1059.001", "Command and Scripting Interpreter: PowerShell"), Cis],
            p => p.Dword(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging") == 1
                ? CheckResult.Pass("Script block logging is enabled.")
                : CheckResult.Fail("Script block logging is not enabled.")),

        new("LOG-002", "PowerShell 2.0 engine is removed", CheckCategory.Logging, Severity.Medium,
            "Checks whether the legacy PowerShell 2.0 engine is installed.",
            "PowerShell 2.0 has no script block logging or AMSI, so attackers downgrade to it to hide their activity.",
            "Remove the Windows PowerShell 2.0 feature.",
            "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
            [Attack("T1059.001", "Command and Scripting Interpreter: PowerShell"), Cis],
            p => OptionalFeature(p, "MicrosoftWindowsPowerShellV2Root") == FeatureState.Enabled
                ? CheckResult.Fail("The PowerShell 2.0 engine is installed.")
                : CheckResult.Pass("The PowerShell 2.0 engine is not installed.")),

        // ---------------- System ----------------
        new("SYS-001", "Secure Boot is enabled", CheckCategory.System, Severity.Medium,
            "Checks whether UEFI Secure Boot is active.",
            "Secure Boot blocks bootkits and unsigned boot loaders that load before Windows and its defenses.",
            "Enable Secure Boot in the UEFI firmware settings.",
            "Confirm-SecureBootUEFI",
            [Attack("T1542", "Pre-OS Boot")],
            p => p.Dword(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") switch
            {
                1 => CheckResult.Pass("Secure Boot is enabled."),
                0 => CheckResult.Fail("Secure Boot is supported but disabled."),
                _ => CheckResult.Warning("Secure Boot state is unknown. The system may boot in legacy BIOS mode."),
            }),

        new("SYS-002", "System drive is encrypted with BitLocker", CheckCategory.System, Severity.High,
            "Checks BitLocker protection of the Windows system drive.",
            "Without encryption anyone with physical access to the disk can read all data, including cached credentials.",
            "Turn on BitLocker (or Device Encryption on Home edition) for the system drive.",
            "Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -TpmProtector",
            [Ms("BitLocker overview", "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/"), Cis],
            p =>
            {
                IReadOnlyList<IReadOnlyDictionary<string, object?>> volumes;
                try
                {
                    volumes = p.QueryWmi(@"root\CIMV2\Security\MicrosoftVolumeEncryption", "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume");
                }
                catch (ProbeUnavailableException)
                {
                    return CheckResult.Warning("BitLocker is not available on this edition. Check Device Encryption in Settings > Privacy & security.");
                }
                var sys = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
                var vol = volumes.FirstOrDefault(v => string.Equals(v["DriveLetter"]?.ToString(), sys, StringComparison.OrdinalIgnoreCase));
                if (vol is null) return CheckResult.Warning($"No BitLocker information for {sys}.");
                return Convert.ToInt32(vol["ProtectionStatus"] ?? 0) == 1
                    ? CheckResult.Pass($"{sys} is protected by BitLocker.")
                    : CheckResult.Fail($"{sys} is not protected by BitLocker.");
            }),

        new("SYS-003", "AutoRun is disabled for all drives", CheckCategory.System, Severity.Low,
            "Checks that Windows does not run programs automatically from inserted media.",
            "AutoRun lets malware on USB drives or discs start without the user doing anything.",
            "Set \"Turn off Autoplay\" to All drives.",
            @"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord",
            [Attack("T1091", "Replication Through Removable Media"), Cis],
            p => p.Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun") == 0xFF
                ? CheckResult.Pass("AutoRun is disabled for all drive types.")
                : CheckResult.Fail("AutoRun is not disabled for all drive types.")),

        new("SYS-004", "Updates were installed recently", CheckCategory.System, Severity.High,
            "Checks the date of the most recent installed update.",
            "Most successful attacks use vulnerabilities that already have a patch. Monthly updates close them.",
            "Install pending updates through Windows Update or your update management tool.",
            "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5",
            [Attack("T1068", "Exploitation for Privilege Escalation")],
            p =>
            {
                var dates = p.QueryWmi(@"root\cimv2", "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering")
                    .Select(r => ParseDate(r["InstalledOn"]?.ToString()))
                    .Where(d => d is not null)
                    .Select(d => d!.Value)
                    .ToList();
                if (dates.Count == 0) return CheckResult.Warning("No installed updates with a date were found.");
                var last = dates.Max();
                var days = (int)(DateTime.Today - last).TotalDays;
                return days switch
                {
                    <= 40 => CheckResult.Pass($"Last update installed {last:yyyy-MM-dd} ({days} days ago)."),
                    <= 90 => CheckResult.Warning($"Last update installed {last:yyyy-MM-dd} ({days} days ago)."),
                    _ => CheckResult.Fail($"Last update installed {last:yyyy-MM-dd} ({days} days ago)."),
                };
            }),

        new("SYS-005", "Remote Registry service is disabled", CheckCategory.System, Severity.Low,
            "Checks the startup type of the Remote Registry service.",
            "Remote Registry lets other machines read and change the registry over the network.",
            "Set the Remote Registry service to Disabled unless a management tool needs it.",
            "Set-Service RemoteRegistry -StartupType Disabled",
            [Cis],
            p => p.Dword(@"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start") switch
            {
                null => CheckResult.NotApplicable("Remote Registry service is not installed."),
                4 => CheckResult.Pass("Remote Registry is disabled."),
                3 => CheckResult.Warning("Remote Registry is set to Manual start."),
                var v => CheckResult.Fail($"Remote Registry starts automatically (Start = {v})."),
            }),
    ];

    // ---------------- helpers ----------------

    internal enum FeatureState { Enabled, Disabled, Absent }

    internal static FeatureState OptionalFeature(ISystemProbe p, string name)
    {
        var row = p.QueryWmi(@"root\cimv2", $"SELECT Name, InstallState FROM Win32_OptionalFeature WHERE Name='{name}'").FirstOrDefault();
        return row is null ? FeatureState.Absent : Convert.ToInt32(row["InstallState"] ?? 3) switch
        {
            1 => FeatureState.Enabled,
            2 => FeatureState.Disabled,
            _ => FeatureState.Absent,
        };
    }

    internal sealed record LocalAccount(string Name, bool Disabled);

    internal static LocalAccount? BuiltInAccount(ISystemProbe p, string ridSuffix)
    {
        var row = p.QueryWmi(@"root\cimv2", "SELECT Name, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount=True")
            .FirstOrDefault(r => r["SID"]?.ToString()?.EndsWith(ridSuffix, StringComparison.Ordinal) == true);
        return row is null ? null : new LocalAccount(row["Name"]?.ToString() ?? "?", AsBool(row["Disabled"]));
    }

    internal static bool AsBool(object? v) => v switch
    {
        bool b => b,
        null => false,
        _ => Convert.ToInt32(v) != 0,
    };

    private static bool IsPassive(IReadOnlyDictionary<string, object?> mp) =>
        mp.TryGetValue("AMRunningMode", out var m) && m?.ToString()?.Contains("Passive", StringComparison.OrdinalIgnoreCase) == true;

    internal static DateTime? ParseDate(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        string[] formats = ["M/d/yyyy", "MM/dd/yyyy", "d.M.yyyy", "dd.MM.yyyy", "yyyy-MM-dd", "yyyyMMdd"];
        if (DateTime.TryParseExact(s.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) return d;
        // WMI hex FILETIME variant (seen on some systems)
        if (long.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var ft) && ft > 0)
        {
            try { return DateTime.FromFileTimeUtc(ft).Date; } catch (ArgumentOutOfRangeException) { }
        }
        return null;
    }
}

internal static class ProbeExtensions
{
    public static int? Dword(this ISystemProbe p, string keyPath, string valueName) => p.GetRegistryValue(keyPath, valueName) switch
    {
        int i => i,
        long l => (int)l,
        uint u => unchecked((int)u),
        string s when int.TryParse(s, out var x) => x,
        _ => null,
    };
}
