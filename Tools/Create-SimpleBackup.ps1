# =============================================================================
# Simple Pre-Hardening Backup Script
# =============================================================================
# This script creates basic backups before applying CIS IIS hardening
# Author: Security Team
# Version: 1.0
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = ".\Backups\Pre-Hardening-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"
$LogFile = ".\Logs\Simple-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore logging errors
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Backup-IISConfiguration {
    Write-Log "Backing up IIS configuration files" "INFO"
    
    if (-not $WhatIf) {
        try {
            $IISBackupPath = "$BackupPath\IIS"
            New-Item -ItemType Directory -Path $IISBackupPath -Force | Out-Null
            
            # Check if IIS is installed
            $IISFeature = Get-WindowsFeature -Name IIS-WebServerRole -ErrorAction SilentlyContinue
            if (-not $IISFeature -or $IISFeature.InstallState -ne "Installed") {
                Write-Log "IIS is not installed on this system" "WARN"
                return
            }
            
            # Backup main IIS configuration files
            $ConfigFiles = @(
                "$env:SystemRoot\System32\inetsrv\config\applicationHost.config",
                "$env:SystemRoot\System32\inetsrv\config\administration.config",
                "$env:SystemRoot\System32\inetsrv\config\redirection.config"
            )
            
            foreach ($ConfigFile in $ConfigFiles) {
                if (Test-Path $ConfigFile) {
                    try {
                        Copy-Item $ConfigFile "$IISBackupPath\$(Split-Path $ConfigFile -Leaf).backup" -Force
                        Write-Log "Backed up: $ConfigFile" "INFO"
                    }
                    catch {
                        Write-Log "Failed to backup $ConfigFile : $($_.Exception.Message)" "WARN"
                    }
                }
            }
            
            # Try to export IIS configuration using appcmd
            try {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list config /config /xml > "$IISBackupPath\iis-config-export.xml" 2>$null
                Write-Log "Exported IIS configuration" "INFO"
            }
            catch {
                Write-Log "Could not export IIS configuration: $($_.Exception.Message)" "WARN"
            }
            
            Write-Log "IIS configuration backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup IIS configuration: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would backup IIS configuration files" "INFO"
    }
}

function Backup-RegistrySettings {
    Write-Log "Backing up registry settings" "INFO"
    
    if (-not $WhatIf) {
        try {
            $RegistryBackupPath = "$BackupPath\Registry"
            New-Item -ItemType Directory -Path $RegistryBackupPath -Force | Out-Null
            
            # Backup SSL/TLS registry keys
            $RegistryKeys = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols",
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
            )
            
            foreach ($Key in $RegistryKeys) {
                if (Test-Path $Key) {
                    try {
                        $KeyName = $Key.Replace("HKLM:\", "").Replace("\", "_")
                        $ExportFile = "$RegistryBackupPath\$KeyName.reg"
                        & reg export $Key $ExportFile /y 2>$null
                        Write-Log "Backed up registry key: $Key" "INFO"
                    }
                    catch {
                        Write-Log "Failed to backup registry key $Key : $($_.Exception.Message)" "WARN"
                    }
                }
            }
            
            Write-Log "Registry backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup registry settings: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would backup registry settings" "INFO"
    }
}

function Backup-SystemState {
    Write-Log "Backing up system state information" "INFO"
    
    if (-not $WhatIf) {
        try {
            $SystemBackupPath = "$BackupPath\System"
            New-Item -ItemType Directory -Path $SystemBackupPath -Force | Out-Null
            
            # System information
            try {
                Get-ComputerInfo | Export-Clixml "$SystemBackupPath\ComputerInfo.xml" -ErrorAction SilentlyContinue
            }
            catch {
                # Fallback to basic system info
                $SystemInfo = @{
                    ComputerName = $env:COMPUTERNAME
                    OSVersion = [System.Environment]::OSVersion.Version.ToString()
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                    BackupDate = Get-Date
                }
                $SystemInfo | Export-Clixml "$SystemBackupPath\ComputerInfo.xml" -ErrorAction SilentlyContinue
            }
            
            # Windows features
            try {
                Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | Export-Csv "$SystemBackupPath\InstalledFeatures.csv" -NoTypeInformation -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Could not export Windows features" "WARN"
            }
            
            # Current date/time for reference
            Get-Date | Out-File "$SystemBackupPath\BackupTimestamp.txt" -ErrorAction SilentlyContinue
            
            Write-Log "System state backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup system state: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would backup system state information" "INFO"
    }
}

function Create-RestoreScript {
    Write-Log "Creating restore script" "INFO"
    
    if (-not $WhatIf) {
        try {
            $RestoreScript = @"
# =============================================================================
# IIS Hardening Restore Script
# =============================================================================
# This script restores the system to pre-hardening state
# Generated: $(Get-Date)
# Backup Path: $BackupPath
# =============================================================================

param(
    [Parameter(Mandatory=`$false)]
    [switch]`$WhatIf
)

`$ErrorActionPreference = "Continue"
`$BackupPath = "$BackupPath"

function Write-Log {
    param([string]`$Message, [string]`$Level = "INFO")
    `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$LogEntry = "[`$Timestamp] [`$Level] `$Message"
    Write-Host `$LogEntry
}

function Test-Administrator {
    `$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    `$principal = New-Object Security.Principal.WindowsPrincipal(`$currentUser)
    return `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restore-IISConfiguration {
    Write-Log "Restoring IIS configuration" "INFO"
    
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required to restore IIS configuration" "ERROR"
        return
    }
    
    if (-not `$WhatIf) {
        try {
            # Stop IIS
            iisreset /stop
            
            # Restore main configuration files
            `$ConfigFiles = @(
                "applicationHost.config",
                "administration.config", 
                "redirection.config"
            )
            
            foreach (`$ConfigFile in `$ConfigFiles) {
                `$BackupFile = "`$BackupPath\IIS\`$ConfigFile.backup"
                `$TargetFile = "`$env:SystemRoot\System32\inetsrv\config\`$ConfigFile"
                
                if (Test-Path `$BackupFile) {
                    Copy-Item `$BackupFile `$TargetFile -Force
                    Write-Log "Restored: `$ConfigFile" "INFO"
                }
            }
            
            # Start IIS
            iisreset /start
            
            Write-Log "IIS configuration restored successfully" "INFO"
        }
        catch {
            Write-Log "Failed to restore IIS configuration: `$(`$_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would restore IIS configuration" "INFO"
    }
}

function Restore-RegistrySettings {
    Write-Log "Restoring registry settings" "INFO"
    
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required to restore registry settings" "ERROR"
        return
    }
    
    if (-not `$WhatIf) {
        try {
            `$RegistryFiles = Get-ChildItem "`$BackupPath\Registry\*.reg" -ErrorAction SilentlyContinue
            foreach (`$RegFile in `$RegistryFiles) {
                & reg import `$RegFile.FullName
                Write-Log "Restored registry from: `$(`$RegFile.Name)" "INFO"
            }
            
            Write-Log "Registry settings restored successfully" "INFO"
        }
        catch {
            Write-Log "Failed to restore registry settings: `$(`$_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would restore registry settings" "INFO"
    }
}

# Main execution
try {
    Write-Log "Starting restore process" "INFO"
    
    if (-not (Test-Administrator)) {
        Write-Log "This script must be run as Administrator to restore system settings" "ERROR"
        Write-Log "Please run: Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File `$PSCommandPath' -Verb RunAs" "INFO"
        exit 1
    }
    
    Restore-IISConfiguration
    Restore-RegistrySettings
    
    Write-Log "Restore completed successfully" "INFO"
    Write-Log "Please restart the server to ensure all changes take effect" "WARN"
}
catch {
    Write-Log "Restore failed: `$(`$_.Exception.Message)" "ERROR"
    exit 1
}
"@
            
            $RestoreScript | Out-File "$BackupPath\Restore-PreHardeningState.ps1" -Encoding UTF8
            Write-Log "Restore script created: $BackupPath\Restore-PreHardeningState.ps1" "INFO"
        }
        catch {
            Write-Log "Failed to create restore script: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would create restore script" "INFO"
    }
}

# =============================================================================
# Main Execution
# =============================================================================

try {
    Write-Log "Starting pre-hardening backup process" "INFO"
    Write-Log "Backup path: $BackupPath" "INFO"
    Write-Log "WhatIf mode: $WhatIf" "INFO"
    Write-Log "Administrator privileges: $(Test-Administrator)" "INFO"
    
    if (-not $WhatIf) {
        # Create backup directory
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        Write-Log "Created backup directory: $BackupPath" "INFO"
    }
    
    # Perform all backups
    Backup-IISConfiguration
    Backup-RegistrySettings
    Backup-SystemState
    Create-RestoreScript
    
    Write-Log "Pre-hardening backup completed successfully" "INFO"
    Write-Log "Backup location: $BackupPath" "INFO"
    Write-Log "Log file: $LogFile" "INFO"
    
    if ($WhatIf) {
        Write-Log "WhatIf mode completed - no backups were created" "INFO"
    }
    else {
        Write-Log "To restore, run: .\Restore-PreHardeningState.ps1" "INFO"
        Write-Log "Note: Restore script requires Administrator privileges" "WARN"
    }
}
catch {
    Write-Log "Backup failed: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
