# Windows Health Audit

A privacy-conscious PowerShell audit that turns local Windows health signals into a structured review plan without changing the system.

The project demonstrates evidence collection, failure isolation, privacy-by-default output, and bounded decision support. It does **not** install software, apply updates, change security policy, edit the registry, modify firewall or network settings, terminate processes, or perform remediation.

## What it produces

`Get-WindowsHealthSnapshot.ps1` returns one PowerShell object containing:

- Windows version, build, uptime, and architecture;
- memory capacity and availability;
- de-identified fixed-volume capacity and free-space percentages;
- network-interface counts and default-gateway availability, without addresses;
- Microsoft Defender and registered antivirus status when available;
- an aggregate installed-update summary;
- bounded System error counts and top provider names, without raw messages;
- Windows Reliability Index metrics when available; and
- review-oriented findings based on transparent thresholds.

Each collector is failure-isolated. An unavailable Windows feature is reported in `CollectorStatus` while the remaining audit continues.

## Quick start

Requirements: Windows PowerShell 5.1 or PowerShell 7 on Windows. Administrator rights are not required.

```powershell
$snapshot = & .\src\Get-WindowsHealthSnapshot.ps1
$snapshot | ConvertTo-Json -Depth 8
```

To reduce or expand the bounded Event Log review:

```powershell
& .\src\Get-WindowsHealthSnapshot.ps1 -EventLookbackDays 3 -MaxSystemErrors 50
```

The script writes nothing. If a persistent report is needed, the caller chooses the destination and retention policy.

## Safety boundary

The implementation has four enforced constraints:

1. **Read-only collection.** Only query commands and .NET inspection APIs are used.
2. **No elevation.** There is no administrator requirement or self-elevation path.
3. **No network activity.** The script does not contact update services, APIs, package managers, or download endpoints.
4. **No remediation.** Findings describe what a person may want to review; they never execute the suggested action.

The CI policy parses every PowerShell file and rejects command families associated with installation, updates, execution-policy changes, firewall or network changes, service control, file mutation, remote execution, and download-and-execute behavior.

See [the safety model](docs/safety-model.md) for the complete boundary.

## Privacy model

The returned object excludes computer name, user name, volume labels, drive letters, IP addresses, MAC addresses, DNS servers, gateway addresses, event messages, serial numbers, UUIDs, account identifiers, and secrets. Fixed volumes receive run-local labels such as `fixed-1`. Collector errors expose only the exception type, not paths or full error text.

The example report is synthetic. It does not describe a real computer or user.

## Architecture

```text
Windows read-only data sources
          |
          v
  failure-isolated collectors
          |
          v
 privacy-preserving normalization
          |
          v
 transparent review thresholds
          |
          v
 one pipeline object (no file writes)
```

More detail is available in [architecture.md](docs/architecture.md).

## Validation

Run the same parse and policy checks used in CI:

```powershell
.\tests\Invoke-StaticChecks.ps1
```

The check validates PowerShell syntax, the no-remediation command policy, the no-elevation/no-download source policy, and the synthetic JSON sample. CI runs on `windows-latest` with `actions/checkout@v6`.

## Limitations

- This is a review aid, not a diagnostic authority, benchmark, security scanner, or monitoring service.
- Some collectors depend on Windows editions, services, or management providers that may be unavailable.
- Event and reliability data are intentionally aggregated; root-cause work still requires a scoped expert review.
- Threshold findings are prompts for human review, not proof that a system is unhealthy.

## Project status and license

This repository is maintained as a portfolio showcase. It is source-available for review but is not open source. See [LICENSE.md](LICENSE.md).

Copyright (c) 2026 Gateway Information Group LLC. All rights reserved.
