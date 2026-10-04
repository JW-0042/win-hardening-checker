using HardeningChecker.Core;

namespace HardeningChecker.Tests;

/// <summary>In-memory system state for tests. WMI answers are matched by a substring of the query.</summary>
internal sealed class FakeProbe : ISystemProbe
{
    private readonly Dictionary<string, object?> _registry = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _subKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string QueryPart, Func<IReadOnlyList<IReadOnlyDictionary<string, object?>>> Answer)> _wmi = [];

    public bool IsElevated { get; set; } = true;

    public OsInfo Os { get; set; } = new("Windows 11 Pro", "26100", IsServer: false);

    public FakeProbe Reg(string path, string name, object? value)
    {
        _registry[$@"{path}\\{name}"] = value;
        return this;
    }

    public FakeProbe SubKeys(string path, params string[] names)
    {
        _subKeys[path] = [.. names];
        return this;
    }

    public FakeProbe Wmi(string queryPart, params Dictionary<string, object?>[] rows)
    {
        _wmi.Add((queryPart, () => rows));
        return this;
    }

    public FakeProbe WmiThrows(string queryPart, Exception ex)
    {
        _wmi.Add((queryPart, () => throw ex));
        return this;
    }

    public object? GetRegistryValue(string keyPath, string valueName) =>
        _registry.TryGetValue($@"{keyPath}\\{valueName}", out var v) ? v : null;

    public IReadOnlyList<string> GetRegistrySubKeyNames(string keyPath) =>
        _subKeys.TryGetValue(keyPath, out var v) ? v : [];

    public IReadOnlyList<IReadOnlyDictionary<string, object?>> QueryWmi(string wmiNamespace, string query)
    {
        foreach (var (part, answer) in _wmi)
        {
            if (query.Contains(part, StringComparison.OrdinalIgnoreCase)) return answer();
        }
        return [];
    }

    public static Dictionary<string, object?> Row(params (string Key, object? Value)[] values) =>
        values.ToDictionary(v => v.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
}
