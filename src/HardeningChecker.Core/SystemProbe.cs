using System.Management;
using System.Security.Principal;
using Microsoft.Win32;

namespace HardeningChecker.Core;

/// <summary>Thrown when a data source (WMI namespace or class) does not exist on this system.</summary>
public sealed class ProbeUnavailableException(string message) : Exception(message);

/// <summary>Read-only access to the system state that checks need. Faked in tests.</summary>
public interface ISystemProbe
{
    bool IsElevated { get; }

    OsInfo Os { get; }

    /// <summary>Reads a value under HKEY_LOCAL_MACHINE (64-bit view). Returns null if the key or value is missing.</summary>
    object? GetRegistryValue(string keyPath, string valueName);

    /// <summary>Lists subkeys under HKEY_LOCAL_MACHINE. Returns an empty list if the key is missing.</summary>
    IReadOnlyList<string> GetRegistrySubKeyNames(string keyPath);

    /// <summary>Runs a WQL query. Throws ProbeUnavailableException for a missing namespace or class and
    /// UnauthorizedAccessException when access is denied.</summary>
    IReadOnlyList<IReadOnlyDictionary<string, object?>> QueryWmi(string wmiNamespace, string query);
}

public sealed class WindowsSystemProbe : ISystemProbe
{
    private readonly Lazy<OsInfo> _os;

    public WindowsSystemProbe()
    {
        using var identity = WindowsIdentity.GetCurrent();
        IsElevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        _os = new Lazy<OsInfo>(ReadOs);
    }

    public bool IsElevated { get; }

    public OsInfo Os => _os.Value;

    public object? GetRegistryValue(string keyPath, string valueName)
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(keyPath, writable: false);
        return key?.GetValue(valueName);
    }

    public IReadOnlyList<string> GetRegistrySubKeyNames(string keyPath)
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(keyPath, writable: false);
        return key?.GetSubKeyNames() ?? [];
    }

    public IReadOnlyList<IReadOnlyDictionary<string, object?>> QueryWmi(string wmiNamespace, string query)
    {
        try
        {
            var scope = new ManagementScope(wmiNamespace);
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
            var rows = new List<IReadOnlyDictionary<string, object?>>();
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    foreach (var p in obj.Properties)
                    {
                        row[p.Name] = p.Value;
                    }
                    rows.Add(row);
                }
            }
            return rows;
        }
        catch (ManagementException ex) when (ex.ErrorCode is ManagementStatus.InvalidNamespace or ManagementStatus.InvalidClass or ManagementStatus.NotFound)
        {
            throw new ProbeUnavailableException($"WMI source not available: {wmiNamespace}");
        }
        catch (ManagementException ex) when (ex.ErrorCode == ManagementStatus.AccessDenied)
        {
            throw new UnauthorizedAccessException($"Access denied to {wmiNamespace}", ex);
        }
        catch (System.Runtime.InteropServices.COMException ex) when ((uint)ex.HResult == 0x80070005)
        {
            throw new UnauthorizedAccessException($"Access denied to {wmiNamespace}", ex);
        }
    }

    private OsInfo ReadOs()
    {
        try
        {
            var row = QueryWmi(@"root\cimv2", "SELECT Caption, BuildNumber, ProductType FROM Win32_OperatingSystem").FirstOrDefault();
            if (row is null) return new OsInfo("Windows", Environment.OSVersion.Version.Build.ToString(), false);
            var productType = Convert.ToInt32(row["ProductType"] ?? 1);
            return new OsInfo(
                row["Caption"]?.ToString()?.Trim() ?? "Windows",
                row["BuildNumber"]?.ToString() ?? "",
                IsServer: productType != 1);
        }
        catch (Exception)
        {
            return new OsInfo("Windows", Environment.OSVersion.Version.Build.ToString(), false);
        }
    }
}
