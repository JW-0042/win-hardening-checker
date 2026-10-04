# Notes for AI coding agents

## Build and test

- Target: .NET 10 and WPF, Windows only.
- Build: `dotnet build HardeningChecker.slnx`
- Test: `dotnet test HardeningChecker.slnx`
- Warnings are treated as errors.

## Rules for the code

- **The tool is read-only.** Never add code that writes to the registry, changes services or applies fixes.
- **All system access goes through `ISystemProbe`** (src/HardeningChecker.Core/SystemProbe.cs). Checks must not call the registry or WMI directly.
- **Every new check in `CheckCatalog.cs` needs:**
  - a unique ID with the category prefix,
  - a description, a rationale and a remediation,
  - at least one reference, with the URL verified to open,
  - tests in `CheckTests.cs` that use `FakeProbe`.
- **Map failures correctly:**
  - Access denied while not elevated becomes NeedsAdmin.
  - A missing WMI class or namespace becomes NotApplicable.
  - Never turn an unknown result into Fail.

## Text style

Plain English. No em dashes and no semicolons joining sentences. The catalog test enforces this.

## README screenshots

Regenerate them with:

`HardeningChecker.exe --screenshot docs/screenshot-light.png --theme light`

Run it again with `--theme dark` for the dark version.
