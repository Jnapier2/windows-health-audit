# Safety model

## Boundary

The project is an observer. It may read local health signals and return an in-memory object. It may not change Windows or initiate a corrective action.

### Permitted capability families

- CIM/WMI queries for operating-system, memory, logical-disk, Security Center, and reliability metadata;
- read-only PowerShell queries for Defender status, installed hotfix history, and bounded Event Log records;
- .NET network-interface inspection reduced to counts and booleans;
- in-memory calculation, grouping, sorting, threshold comparison, and object construction; and
- pipeline output controlled by the caller.

### Explicitly excluded capability families

- package installation, removal, upgrade, or package-manager orchestration;
- Windows Update, WinGet, Store, driver, firmware, or application changes;
- execution-policy changes, file unblocking, self-elevation, or administrator relaunch;
- registry writes, service control, scheduled-task changes, or process termination;
- Defender exclusions, antivirus configuration, quarantine changes, or firewall changes;
- IP, DNS, route, adapter, VPN, proxy, or other network configuration changes;
- disk repair, cleanup, formatting, partitioning, file deletion, or file relocation;
- remote commands, browser automation, API calls, downloads, or downloaded-code execution;
- persistence, background monitoring, telemetry upload, or secret collection; and
- automatic remediation of any finding.

## Enforcement

The repository contains two layers of enforcement:

1. Human-reviewable source with no dynamic command construction or hidden control path.
2. CI that parses the PowerShell AST and rejects a conservative list of mutating, administrative, remote, and download commands. CI also rejects elevation directives, execution-policy bypass flags, encoded commands, download APIs, and embedded web URLs in tracked source.

Static checks reduce risk but do not replace review. Any future feature that crosses the observer boundary must be built in a different repository and may not be added here.

## Output privacy

The report does not include user or host names, local paths, drive letters, volume labels, serial numbers, account identifiers, network addresses, raw event messages, or secrets. Security-product display names and event provider names are retained because they are categorical evidence, not unique identifiers; consumers with stricter requirements can remove those fields before persistence.
