# =============================================================================
# Pre-Hardening Backup Script
# =============================================================================
# This script creates comprehensive backups before applying CIS IIS hardening
# Author: Security Team
# Version: 1.0
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = "C:\Backups\Pre-Hardening-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$LogFile = ".\Logs\Pre-Hardening-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
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
            
            # Backup main IIS configuration files
            $ConfigFiles = @(
                "$env:SystemRoot\System32\inetsrv\config\applicationHost.config",
                "$env:SystemRoot\System32\inetsrv\config\administration.config",
                "$env:SystemRoot\System32\inetsrv\config\redirection.config"
            )
            
            foreach ($ConfigFile in $ConfigFiles) {
                if (Test-Path $ConfigFile) {
                    Copy-Item $ConfigFile "$IISBackupPath\$(Split-Path $ConfigFile -Leaf).backup"
                    Write-Log "Backed up: $ConfigFile" "INFO"
                }
            }
            
            # Export complete IIS configuration
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list config /config /xml > "$IISBackupPath\iis-config-export.xml"
            
            # Backup web.config files for all sites
            $Sites = Get-WebSite -ErrorAction SilentlyContinue
            foreach ($Site in $Sites) {
                $SitePath = $Site.PhysicalPath
                if (Test-Path "$SitePath\web.config") {
                    $SiteBackupPath = "$IISBackupPath\Sites\$($Site.Name)"
                    New-Item -ItemType Directory -Path $SiteBackupPath -Force | Out-Null
                    Copy-Item "$SitePath\web.config" "$SiteBackupPath\web.config.backup"
                    Write-Log "Backed up web.config for site: $($Site.Name)" "INFO"
                }
            }
            
            # Export IIS sites and applications
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list sites /config /xml > "$IISBackupPath\sites-export.xml"
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list app /config /xml > "$IISBackupPath\applications-export.xml"
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list apppool /config /xml > "$IISBackupPath\apppools-export.xml"
            
            Write-Log "IIS configuration backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup IIS configuration: $($_.Exception.Message)" "ERROR"
            throw
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
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            )
            
            foreach ($Key in $RegistryKeys) {
                if (Test-Path $Key) {
                    $KeyName = $Key.Replace("HKLM:\", "").Replace("\", "_")
                    $ExportFile = "$RegistryBackupPath\$KeyName.reg"
                    & reg export $Key $ExportFile /y
                    Write-Log "Backed up registry key: $Key" "INFO"
                }
            }
            
            Write-Log "Registry backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup registry settings: $($_.Exception.Message)" "ERROR"
            throw
        }
    }
    else {
        Write-Log "Would backup registry settings" "INFO"
    }
}

function Backup-FirewallRules {
    Write-Log "Backing up firewall rules" "INFO"
    
    if (-not $WhatIf) {
        try {
            $FirewallBackupPath = "$BackupPath\Firewall"
            New-Item -ItemType Directory -Path $FirewallBackupPath -Force | Out-Null
            
            # Export firewall rules
            $FirewallProfiles = @("Domain", "Private", "Public")
            foreach ($Profile in $FirewallProfiles) {
                $ExportFile = "$FirewallBackupPath\FirewallRules_$Profile.txt"
                Get-NetFirewallRule -Profile $Profile | Export-Csv $ExportFile -NoTypeInformation
                Write-Log "Backed up firewall rules for profile: $Profile" "INFO"
            }
            
            # Export firewall profiles
            Get-NetFirewallProfile | Export-Csv "$FirewallBackupPath\FirewallProfiles.csv" -NoTypeInformation
            
            Write-Log "Firewall backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup firewall rules: $($_.Exception.Message)" "ERROR"
            throw
        }
    }
    else {
        Write-Log "Would backup firewall rules" "INFO"
    }
}

function Backup-SystemState {
    Write-Log "Backing up system state information" "INFO"
    
    if (-not $WhatIf) {
        try {
            $SystemBackupPath = "$BackupPath\System"
            New-Item -ItemType Directory -Path $SystemBackupPath -Force | Out-Null
            
            # System information
            Get-ComputerInfo | Export-Clixml "$SystemBackupPath\ComputerInfo.xml"
            
            # Windows features
            Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | Export-Csv "$SystemBackupPath\InstalledFeatures.csv" -NoTypeInformation
            
            # IIS modules
            Get-WebGlobalModule | Export-Csv "$SystemBackupPath\IISModules.csv" -NoTypeInformation
            
            # Current date/time for reference
            Get-Date | Out-File "$SystemBackupPath\BackupTimestamp.txt"
            
            Write-Log "System state backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup system state: $($_.Exception.Message)" "ERROR"
            throw
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

`$ErrorActionPreference = "Stop"
`$BackupPath = "$BackupPath"

function Write-Log {
    param([string]`$Message, [string]`$Level = "INFO")
    `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$LogEntry = "[`$Timestamp] [`$Level] `$Message"
    Write-Host `$LogEntry
}

function Restore-IISConfiguration {
    Write-Log "Restoring IIS configuration" "INFO"
    
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
            
            # Restore web.config files
            `$SiteBackups = Get-ChildItem "`$BackupPath\IIS\Sites" -Directory
            foreach (`$SiteBackup in `$SiteBackups) {
                `$WebConfigBackup = "`$SiteBackup.FullName\web.config.backup"
                if (Test-Path `$WebConfigBackup) {
                    # Find the site and restore its web.config
                    `$Site = Get-WebSite -Name `$SiteBackup.Name -ErrorAction SilentlyContinue
                    if (`$Site) {
                        `$TargetWebConfig = "`$(`$Site.PhysicalPath)\web.config"
                        Copy-Item `$WebConfigBackup `$TargetWebConfig -Force
                        Write-Log "Restored web.config for site: `$(`$SiteBackup.Name)" "INFO"
                    }
                }
            }
            
            # Start IIS
            iisreset /start
            
            Write-Log "IIS configuration restored successfully" "INFO"
        }
        catch {
            Write-Log "Failed to restore IIS configuration: `$(`$_.Exception.Message)" "ERROR"
            throw
        }
    }
    else {
        Write-Log "Would restore IIS configuration" "INFO"
    }
}

function Restore-RegistrySettings {
    Write-Log "Restoring registry settings" "INFO"
    
    if (-not `$WhatIf) {
        try {
            `$RegistryFiles = Get-ChildItem "`$BackupPath\Registry\*.reg"
            foreach (`$RegFile in `$RegistryFiles) {
                & reg import `$RegFile.FullName
                Write-Log "Restored registry from: `$(`$RegFile.Name)" "INFO"
            }
            
            Write-Log "Registry settings restored successfully" "INFO"
        }
        catch {
            Write-Log "Failed to restore registry settings: `$(`$_.Exception.Message)" "ERROR"
            throw
        }
    }
    else {
        Write-Log "Would restore registry settings" "INFO"
    }
}

function Restore-FirewallRules {
    Write-Log "Restoring firewall rules" "INFO"
    
    if (-not `$WhatIf) {
        try {
            # Remove any IIS-specific firewall rules that might have been added
            Remove-NetFirewallRule -DisplayName "IIS HTTP" -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName "IIS HTTPS" -ErrorAction SilentlyContinue
            
            Write-Log "Firewall rules restored (IIS-specific rules removed)" "INFO"
        }
        catch {
            Write-Log "Failed to restore firewall rules: `$(`$_.Exception.Message)" "ERROR"
            throw
        }
    }
    else {
        Write-Log "Would restore firewall rules" "INFO"
    }
}

# Main execution
try {
    Write-Log "Starting restore process" "INFO"
    
    Restore-IISConfiguration
    Restore-RegistrySettings  
    Restore-FirewallRules
    
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
            throw
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
    
    if (-not (Test-Administrator)) {
        Write-Log "This script must be run as Administrator" "ERROR"
        exit 1
    }
    
    if (-not $WhatIf) {
        # Create backup directory and logs directory
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        New-Item -ItemType Directory -Path ".\Logs" -Force | Out-Null
        Write-Log "Created backup directory: $BackupPath" "INFO"
    }
    
    # Perform all backups
    Backup-IISConfiguration
    Backup-RegistrySettings
    Backup-FirewallRules
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
    }
}
catch {
    Write-Log "Backup failed: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
