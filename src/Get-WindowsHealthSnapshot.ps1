#requires -Version 5.1
<#
.SYNOPSIS
Collects a privacy-conscious, read-only Windows health snapshot.

.DESCRIPTION
Queries local Windows telemetry and returns one structured object to the pipeline.
The script does not remediate findings, require elevation, call the network, or
write files. Collector failures are isolated so one unavailable data source does
not prevent the remaining snapshot from being produced.

.PARAMETER EventLookbackDays
Number of recent days considered when counting System log errors.

.PARAMETER MaxSystemErrors
Maximum number of System log error records inspected. Event messages and machine
identifiers are never included in the returned object.

.OUTPUTS
PSCustomObject
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 30)]
    [int]$EventLookbackDays = 7,

    [ValidateRange(10, 500)]
    [int]$MaxSystemErrors = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Percentage {
    param(
        [double]$Part,
        [double]$Whole
    )

    if ($Whole -le 0) {
        return $null
    }

    return [math]::Round(($Part / $Whole) * 100, 1)
}

function Invoke-HealthCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $true)]
        [System.Collections.IList]$Status
    )

    try {
        $result = & $Operation
        [void]$Status.Add([pscustomobject][ordered]@{
            Name = $Name
            State = 'collected'
            ErrorType = $null
        })
        return $result
    }
    catch {
        [void]$Status.Add([pscustomobject][ordered]@{
            Name = $Name
            State = 'unavailable'
            ErrorType = $_.Exception.GetType().Name
        })
        return [pscustomobject][ordered]@{
            Available = $false
            Reason = 'Collector unavailable on this system.'
        }
    }
}

function New-ReviewFinding {
    param(
        [ValidateSet('review', 'attention')]
        [string]$Level,
        [string]$Category,
        [string]$Title,
        [string]$Evidence,
        [string]$SuggestedReview
    )

    return [pscustomobject][ordered]@{
        Level = $Level
        Category = $Category
        Title = $Title
        Evidence = $Evidence
        SuggestedReview = $SuggestedReview
    }
}

$collectorStatus = [System.Collections.ArrayList]::new()
$findings = [System.Collections.ArrayList]::new()

$operatingSystem = Invoke-HealthCollector -Name 'operating-system' -Status $collectorStatus -Operation {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 8 -ErrorAction Stop
    $bootTime = [datetime]$os.LastBootUpTime
    $uptimeDays = [math]::Round(((Get-Date) - $bootTime).TotalDays, 1)

    [pscustomobject][ordered]@{
        Available = $true
        Caption = [string]$os.Caption
        Version = [string]$os.Version
        BuildNumber = [string]$os.BuildNumber
        Architecture = [string]$os.OSArchitecture
        LastBootUtc = $bootTime.ToUniversalTime().ToString('o')
        UptimeDays = $uptimeDays
    }
}

$memory = Invoke-HealthCollector -Name 'memory' -Status $collectorStatus -Operation {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 8 -ErrorAction Stop
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 8 -ErrorAction Stop
    $totalBytes = [int64]$system.TotalPhysicalMemory
    $availableBytes = [int64]$os.FreePhysicalMemory * 1KB

    [pscustomobject][ordered]@{
        Available = $true
        TotalBytes = $totalBytes
        AvailableBytes = $availableBytes
        AvailablePercent = Get-Percentage -Part $availableBytes -Whole $totalBytes
    }
}

$fixedVolumes = Invoke-HealthCollector -Name 'fixed-volumes' -Status $collectorStatus -Operation {
    $items = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 8 -ErrorAction Stop | Sort-Object DeviceID)
    $volumeRows = [System.Collections.ArrayList]::new()
    $index = 0

    foreach ($item in $items) {
        $index++
        $sizeBytes = [int64]$item.Size
        $freeBytes = [int64]$item.FreeSpace
        [void]$volumeRows.Add([pscustomobject][ordered]@{
            Volume = "fixed-$index"
            SizeBytes = $sizeBytes
            FreeBytes = $freeBytes
            FreePercent = Get-Percentage -Part $freeBytes -Whole $sizeBytes
        })
    }

    [pscustomobject][ordered]@{
        Available = $true
        Count = $volumeRows.Count
        Volumes = @($volumeRows)
    }
}

$network = Invoke-HealthCollector -Name 'network-summary' -Status $collectorStatus -Operation {
    $interfaces = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        $_.NetworkInterfaceType -notin @(
            [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback,
            [System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel
        )
    })
    $upInterfaces = @($interfaces | Where-Object {
        $_.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up
    })
    $hasDefaultGateway = $false

    foreach ($interface in $upInterfaces) {
        try {
            if (@($interface.GetIPProperties().GatewayAddresses).Count -gt 0) {
                $hasDefaultGateway = $true
                break
            }
        }
        catch {
            continue
        }
    }

    [pscustomobject][ordered]@{
        Available = $true
        InterfaceCount = $interfaces.Count
        UpInterfaceCount = $upInterfaces.Count
        HasDefaultGateway = $hasDefaultGateway
    }
}

$defender = Invoke-HealthCollector -Name 'microsoft-defender' -Status $collectorStatus -Operation {
    $command = Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $command) {
        return [pscustomobject][ordered]@{
            Available = $false
            Reason = 'Microsoft Defender status cmdlet is unavailable.'
        }
    }

    $status = Get-MpComputerStatus -ErrorAction Stop
    [pscustomobject][ordered]@{
        Available = $true
        AntivirusEnabled = [bool]$status.AntivirusEnabled
        AntispywareEnabled = [bool]$status.AntispywareEnabled
        RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
        AntivirusSignatureAgeDays = [int]$status.AntivirusSignatureAge
    }
}

$securityProducts = Invoke-HealthCollector -Name 'security-products' -Status $collectorStatus -Operation {
    $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -OperationTimeoutSec 8 -ErrorAction Stop)
    $names = @($products | ForEach-Object { [string]$_.displayName } | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } | Sort-Object -Unique)

    [pscustomobject][ordered]@{
        Available = $true
        ProductCount = $names.Count
        ProductNames = @($names)
    }
}

$updateHistory = Invoke-HealthCollector -Name 'installed-update-summary' -Status $collectorStatus -Operation {
    $hotFixes = @(Get-HotFix -ErrorAction Stop)
    $installedDates = [System.Collections.ArrayList]::new()

    foreach ($hotFix in $hotFixes) {
        if ($null -eq $hotFix.InstalledOn) {
            continue
        }

        try {
            [void]$installedDates.Add([datetime]$hotFix.InstalledOn)
        }
        catch {
            continue
        }
    }

    $latestDate = $null
    if ($installedDates.Count -gt 0) {
        $latestDate = [datetime](($installedDates | Sort-Object -Descending | Select-Object -First 1))
    }

    [pscustomobject][ordered]@{
        Available = $true
        RecordedUpdateCount = $hotFixes.Count
        LatestInstalledOn = if ($latestDate) { $latestDate.ToString('yyyy-MM-dd') } else { $null }
    }
}

$systemErrors = Invoke-HealthCollector -Name 'system-error-summary' -Status $collectorStatus -Operation {
    $startTime = (Get-Date).AddDays(-$EventLookbackDays)
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Level = 2
        StartTime = $startTime
    } -MaxEvents $MaxSystemErrors -ErrorAction Stop)
    $topProviders = @($events | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        [pscustomobject][ordered]@{
            Provider = [string]$_.Name
            Count = [int]$_.Count
        }
    })

    [pscustomobject][ordered]@{
        Available = $true
        LookbackDays = $EventLookbackDays
        ErrorCountObserved = $events.Count
        ReachedInspectionCap = ($events.Count -ge $MaxSystemErrors)
        TopProviders = $topProviders
    }
}

$reliability = Invoke-HealthCollector -Name 'reliability-index' -Status $collectorStatus -Operation {
    $since = (Get-Date).AddDays(-30)
    $metrics = @(Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -OperationTimeoutSec 8 -ErrorAction Stop | ForEach-Object {
        $recordedAt = [datetime]$_.TimeGenerated
        if ($recordedAt -ge $since) {
            [pscustomobject]@{
                RecordedAt = $recordedAt
                Index = [double]$_.SystemStabilityIndex
            }
        }
    } | Sort-Object RecordedAt)

    $latestIndex = $null
    $averageIndex = $null
    if ($metrics.Count -gt 0) {
        $latestIndex = [math]::Round([double]$metrics[-1].Index, 2)
        $averageIndex = [math]::Round([double](($metrics | Measure-Object Index -Average).Average), 2)
    }

    [pscustomobject][ordered]@{
        Available = ($metrics.Count -gt 0)
        MetricCount = $metrics.Count
        LatestIndex = $latestIndex
        Average30DayIndex = $averageIndex
    }
}

if ($operatingSystem.Available -and $operatingSystem.UptimeDays -ge 30) {
    [void]$findings.Add((New-ReviewFinding -Level 'review' -Category 'operating-system' -Title 'Extended uptime' -Evidence (
        'Current uptime is {0} days.' -f $operatingSystem.UptimeDays
    ) -SuggestedReview 'Review maintenance timing and confirm pending updates before deciding whether a restart is appropriate.'))
}

if ($memory.Available -and $memory.AvailablePercent -lt 15) {
    [void]$findings.Add((New-ReviewFinding -Level 'attention' -Category 'memory' -Title 'Low available memory' -Evidence (
        'Available physical memory is {0}%.' -f $memory.AvailablePercent
    ) -SuggestedReview 'Review workload and memory-pressure history; this audit does not terminate processes.'))
}

if ($fixedVolumes.Available) {
    foreach ($volume in @($fixedVolumes.Volumes)) {
        if ($volume.FreePercent -lt 10) {
            [void]$findings.Add((New-ReviewFinding -Level 'attention' -Category 'storage' -Title 'Very low free space' -Evidence (
                '{0} has {1}% free space.' -f $volume.Volume, $volume.FreePercent
            ) -SuggestedReview 'Review storage usage and retention policy; this audit does not delete or move files.'))
        }
        elseif ($volume.FreePercent -lt 20) {
            [void]$findings.Add((New-ReviewFinding -Level 'review' -Category 'storage' -Title 'Free space should be reviewed' -Evidence (
                '{0} has {1}% free space.' -f $volume.Volume, $volume.FreePercent
            ) -SuggestedReview 'Review capacity trends and decide whether additional space is needed.'))
        }
    }
}

if ($defender.Available) {
    if (-not $defender.AntivirusEnabled -or -not $defender.RealTimeProtectionEnabled) {
        [void]$findings.Add((New-ReviewFinding -Level 'attention' -Category 'security' -Title 'Microsoft Defender protection state requires review' -Evidence (
            'Antivirus enabled: {0}; real-time protection enabled: {1}.' -f $defender.AntivirusEnabled, $defender.RealTimeProtectionEnabled
        ) -SuggestedReview 'Confirm the intended endpoint-protection configuration in Windows Security or with the system administrator.'))
    }
    elseif ($defender.AntivirusSignatureAgeDays -gt 3) {
        [void]$findings.Add((New-ReviewFinding -Level 'review' -Category 'security' -Title 'Security intelligence age should be reviewed' -Evidence (
            'Reported signature age is {0} days.' -f $defender.AntivirusSignatureAgeDays
        ) -SuggestedReview 'Confirm update health through the organization-approved endpoint-management process.'))
    }
}

if ($systemErrors.Available -and $systemErrors.ReachedInspectionCap) {
    [void]$findings.Add((New-ReviewFinding -Level 'review' -Category 'reliability' -Title 'System error inspection cap reached' -Evidence (
        'At least {0} System log errors were observed within {1} days.' -f $MaxSystemErrors, $EventLookbackDays
    ) -SuggestedReview 'Perform a scoped Event Viewer review; raw event messages were intentionally excluded from this snapshot.'))
}

$collectedCount = @($collectorStatus | Where-Object { $_.State -eq 'collected' }).Count
$unavailableCount = @($collectorStatus | Where-Object { $_.State -eq 'unavailable' }).Count
$attentionCount = @($findings | Where-Object { $_.Level -eq 'attention' }).Count
$reviewCount = @($findings | Where-Object { $_.Level -eq 'review' }).Count

[pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    GeneratedAtUtc = [datetime]::UtcNow.ToString('o')
    Safety = [pscustomobject][ordered]@{
        ReadOnly = $true
        RequiresElevation = $false
        PerformsNetworkCalls = $false
        PerformsRemediation = $false
        IncludesHostOrUserName = $false
        IncludesNetworkAddresses = $false
        IncludesRawEventMessages = $false
    }
    Summary = [pscustomobject][ordered]@{
        CollectorsSucceeded = $collectedCount
        CollectorsUnavailable = $unavailableCount
        AttentionFindings = $attentionCount
        ReviewFindings = $reviewCount
    }
    OperatingSystem = $operatingSystem
    Memory = $memory
    FixedVolumes = $fixedVolumes
    Network = $network
    MicrosoftDefender = $defender
    SecurityProducts = $securityProducts
    InstalledUpdates = $updateHistory
    SystemErrors = $systemErrors
    Reliability = $reliability
    Findings = @($findings)
    CollectorStatus = @($collectorStatus)
}
