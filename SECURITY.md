# Security policy

Hardening Checker is a read-only tool. It reads registry values and WMI classes and never changes system settings.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). You will get an answer within a few days.

Useful things to include: the Windows version and build, the check ID, what you expected and what happened.

## Verifying a release

Every release binary is built by GitHub Actions and has a signed build provenance attestation. You can verify a download with the GitHub CLI:

```
gh attestation verify HardeningChecker-win-x64.zip --repo JW-0042/win-hardening-checker
```
