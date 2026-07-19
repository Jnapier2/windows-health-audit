# Architecture

Windows Health Audit is organized as a one-way evidence pipeline. It deliberately has no execution path from a finding back into the operating system.

## Components

### 1. Bounded collectors

Nine collectors query local Windows or .NET data sources:

| Collector | Source | Returned output |
|---|---|---|
| Operating system | `Win32_OperatingSystem` | Version, build, architecture, boot time, uptime |
| Memory | `Win32_OperatingSystem`, `Win32_ComputerSystem` | Total and available capacity |
| Fixed volumes | `Win32_LogicalDisk` | De-identified capacity and free-space percentage |
| Network summary | .NET network interfaces | Counts, up-state count, gateway-presence boolean |
| Microsoft Defender | `Get-MpComputerStatus` | Enabled states and signature age |
| Security products | Windows Security Center | Product count and display names |
| Installed updates | `Get-HotFix` | Aggregate count and most recent date |
| System errors | `Get-WinEvent` | Bounded count and top provider names |
| Reliability | `Win32_ReliabilityStabilityMetrics` | Count, latest index, 30-day average |

Every collector has a finite scope. Event collection has explicit lookback and record caps. CIM calls have operation timeouts where the Windows provider supports them.

### 2. Failure isolation

`Invoke-HealthCollector` catches failures per source and records a minimal status. The snapshot remains useful when a provider, cmdlet, namespace, or Windows feature is unavailable. Error messages are excluded because they can contain local paths or device details.

### 3. Privacy-preserving normalization

Normalization removes the need to expose raw identifiers. Volumes are numbered only after sorting, network addresses never leave the collector, and event records are reduced to counts. The report contains enough context to guide a review while avoiding a machine inventory.

### 4. Transparent review rules

Small, explicit rules create findings for extended uptime, memory pressure, low free space, Defender state or signature age, and a saturated Event Log inspection cap. Each finding provides evidence and a suggested human review. No finding contains an executable remediation command.

### 5. Pipeline-only output

The script returns one object and does not create directories, logs, state, scheduled tasks, services, archives, or reports. Persistence is an external caller decision.

## Design trade-offs

- Aggregation improves privacy but removes detail needed for root-cause analysis.
- Graceful degradation improves portability but requires consumers to inspect `CollectorStatus`.
- Read-only operation makes the project safe to evaluate but intentionally leaves remediation to established organizational processes.
