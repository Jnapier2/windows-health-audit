#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$powerShellExtensions = @('.ps1', '.psm1', '.psd1')
$powerShellFiles = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File | Where-Object {
    $powerShellExtensions -contains $_.Extension.ToLowerInvariant()
} | Sort-Object FullName)
$failures = [System.Collections.ArrayList]::new()

$forbiddenCommands = @(
    'Add-AppxPackage',
    'Add-MpPreference',
    'Add-Content',
    'Clear-Disk',
    'Copy-Item',
    'Disable-NetAdapter',
    'Disable-NetFirewallRule',
    'Enable-NetAdapter',
    'Enable-NetFirewallRule',
    'Export-Clixml',
    'Format-Volume',
    'Initialize-Disk',
    'Install-Module',
    'Install-Package',
    'Invoke-Command',
    'Invoke-Expression',
    'Invoke-RestMethod',
    'Invoke-WebRequest',
    'Move-Item',
    'New-Item',
    'New-ItemProperty',
    'New-NetFirewallRule',
    'New-NetIPAddress',
    'Out-File',
    'Remove-AppxPackage',
    'Remove-Item',
    'Remove-ItemProperty',
    'Remove-MpPreference',
    'Remove-NetFirewallRule',
    'Repair-Volume',
    'Restart-NetAdapter',
    'Restart-Service',
    'Set-Content',
    'Set-DnsClientServerAddress',
    'Set-ExecutionPolicy',
    'Set-ItemProperty',
    'Set-MpPreference',
    'Set-NetFirewallProfile',
    'Set-NetFirewallRule',
    'Set-NetIPInterface',
    'Set-Service',
    'Start-Process',
    'Start-Service',
    'Stop-Service',
    'Unblock-File',
    'Uninstall-Package',
    'Update-Module'
)

foreach ($file in $powerShellFiles) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref]$tokens,
        [ref]$parseErrors
    )

    foreach ($parseError in @($parseErrors)) {
        [void]$failures.Add(('{0}: parse error: {1}' -f $file.FullName, $parseError.Message))
    }

    $commandAsts = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true))

    foreach ($commandAst in $commandAsts) {
        $commandName = $commandAst.GetCommandName()
        if ($commandName -and $forbiddenCommands -contains $commandName) {
            [void]$failures.Add(('{0}: forbidden command: {1}' -f $file.FullName, $commandName))
        }
    }
}

$sourceRoot = Join-Path $repositoryRoot 'src'
$sourceFiles = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File | Where-Object {
    $powerShellExtensions -contains $_.Extension.ToLowerInvariant()
})
$sourceText = @($sourceFiles | ForEach-Object {
    Get-Content -LiteralPath $_.FullName -Raw
}) -join "`n"
$forbiddenSourcePatterns = [ordered]@{
    'elevation requirement' = '(?im)^\s*#requires\s+-RunAsAdministrator'
    'execution-policy bypass' = '(?i)-ExecutionPolicy\s+Bypass'
    'encoded command' = '(?i)-EncodedCommand\b'
    'download-and-execute API' = '(?i)DownloadString|DownloadFile|Net\.WebClient|HttpClient'
    'embedded web URL' = '(?i)https?://'
}

foreach ($entry in $forbiddenSourcePatterns.GetEnumerator()) {
    if ($sourceText -match $entry.Value) {
        [void]$failures.Add(('src: forbidden pattern: {0}' -f $entry.Key))
    }
}

$samplePath = Join-Path $repositoryRoot 'examples\synthetic-snapshot.json'
try {
    $sample = Get-Content -LiteralPath $samplePath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ([string]$sample.SchemaVersion -ne '1.0') {
        [void]$failures.Add('Synthetic sample has an unexpected SchemaVersion.')
    }
}
catch {
    [void]$failures.Add(('Synthetic sample is not valid JSON: {0}' -f $_.Exception.Message))
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Write-Error $failure -ErrorAction Continue
    }
    exit 1
}

Write-Host ('Static checks passed for {0} PowerShell file(s).' -f $powerShellFiles.Count)
