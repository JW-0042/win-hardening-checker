# How this was built

Hardening Checker is part of a small series of Windows administration and security tools that I build with an AI coding agent (Claude Code). The goal is to show how quickly a consultant with a security background can ship working tools when AI does the typing and a human owns the decisions.

## Who did what

**My part:**
- the idea and the scope,
- the choice of checks and what counts as a pass or a fail,
- the read-only rule,
- reviewing every check against how real environments are set up,
- testing on real machines,
- deciding what goes into a release.

**The AI agent's part:**
- the project structure,
- the code for the checks,
- the WPF interface,
- the tests and the CI pipeline,
- the first drafts of the texts,
- checking that every reference link in the catalog opens the right page.

## Decisions that mattered

- **Read-only, always.** A tool that changes security settings on its own is a risk in itself. Fixes are shown as commands that you review and run yourself.
- **One door to the system.** Every registry and WMI read goes through `ISystemProbe`. That kept the checks small and made it possible to test them with a fake system. As a result, the tests run anywhere, CI included.
- **No guessing.** Missing admin rights, an unsupported Windows edition and a missing WMI class each get their own status. People learn to ignore a baseline tool that quietly marks unknowns as failures.
- **Evidence on screen.** Every result shows the raw value it is based on. An admin who disagrees with the verdict can see exactly why it was given.
- **Few dependencies.** The app uses plain .NET 10 and WPF, MVVM without a framework and a single NuGet package (System.Management).

## Where a human was needed

- **Setting thresholds.** For example, how old the last update may be before it counts as a warning (40 days) or a failure (90 days).
- **Handling Windows Home.** BitLocker is not available on Windows Home. That case should be a warning with an explanation, not a failure.
- **Keeping references correct.** MITRE ATT&CK had renumbered two Defense Evasion techniques. The agent found this while checking the links, but someone has to care that references stay correct.
- **Running it on real hardware.** The first real scan found Secure Boot turned off on my own PC.

## Quality gates

- The build treats warnings as errors.
- xUnit tests cover every check with a fake system probe. They also cover the catalog rules (unique IDs, complete documentation) and report encoding.
- On every push, GitHub Actions builds the app, runs the tests and runs the CLI on a clean Windows runner.
- Releases are self-contained single-file builds with signed build provenance.
