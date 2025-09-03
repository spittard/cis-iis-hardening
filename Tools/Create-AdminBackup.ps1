# =============================================================================
# Administrator Backup Script
# =============================================================================
# This script creates comprehensive backups with administrator privileges
# Run this script as Administrator for complete backup
# Author: Security Team
# Version: 1.0
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = ".\Backups\Admin-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"
$LogFile = ".\Logs\Admin-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
            try {
                $IISFeature = Get-WindowsFeature -Name IIS-WebServerRole -ErrorAction Stop
                if ($IISFeature.InstallState -ne "Installed") {
                    Write-Log "IIS is not installed on this system" "WARN"
                    return
                }
            }
            catch {
                Write-Log "Could not check IIS installation status" "WARN"
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
            
            # Export IIS configuration using appcmd
            try {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list config /config /xml > "$IISBackupPath\iis-config-export.xml" 2>$null
                Write-Log "Exported IIS configuration" "INFO"
            }
            catch {
                Write-Log "Could not export IIS configuration: $($_.Exception.Message)" "WARN"
            }
            
            # Export IIS sites and applications
            try {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list sites /config /xml > "$IISBackupPath\sites-export.xml" 2>$null
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list app /config /xml > "$IISBackupPath\applications-export.xml" 2>$null
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list apppool /config /xml > "$IISBackupPath\apppools-export.xml" 2>$null
                Write-Log "Exported IIS sites, applications, and app pools" "INFO"
            }
            catch {
                Write-Log "Could not export IIS sites/applications: $($_.Exception.Message)" "WARN"
            }
            
            # Backup web.config files for all sites
            try {
                $Sites = Get-WebSite -ErrorAction SilentlyContinue
                foreach ($Site in $Sites) {
                    $SitePath = $Site.PhysicalPath
                    if (Test-Path "$SitePath\web.config") {
                        $SiteBackupPath = "$IISBackupPath\Sites\$($Site.Name)"
                        New-Item -ItemType Directory -Path $SiteBackupPath -Force | Out-Null
                        Copy-Item "$SitePath\web.config" "$SiteBackupPath\web.config.backup" -Force
                        Write-Log "Backed up web.config for site: $($Site.Name)" "INFO"
                    }
                }
            }
            catch {
                Write-Log "Could not backup web.config files: $($_.Exception.Message)" "WARN"
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
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            )
            
            foreach ($Key in $RegistryKeys) {
                if (Test-Path $Key) {
                    try {
                        $KeyName = $Key.Replace("HKLM:\", "").Replace("\", "_")
                        $ExportFile = "$RegistryBackupPath\$KeyName.reg"
                        & reg export $Key $ExportFile /y 2>$null
                        if (Test-Path $ExportFile) {
                            Write-Log "Backed up registry key: $Key" "INFO"
                        }
                        else {
                            Write-Log "Failed to backup registry key: $Key" "WARN"
                        }
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

function Backup-FirewallRules {
    Write-Log "Backing up firewall rules" "INFO"
    
    if (-not $WhatIf) {
        try {
            $FirewallBackupPath = "$BackupPath\Firewall"
            New-Item -ItemType Directory -Path $FirewallBackupPath -Force | Out-Null
            
            # Export firewall rules
            $FirewallProfiles = @("Domain", "Private", "Public")
            foreach ($Profile in $FirewallProfiles) {
                try {
                    $ExportFile = "$FirewallBackupPath\FirewallRules_$Profile.csv"
                    Get-NetFirewallRule -Profile $Profile | Export-Csv $ExportFile -NoTypeInformation -ErrorAction SilentlyContinue
                    Write-Log "Backed up firewall rules for profile: $Profile" "INFO"
                }
                catch {
                    Write-Log "Failed to backup firewall rules for profile $Profile : $($_.Exception.Message)" "WARN"
                }
            }
            
            # Export firewall profiles
            try {
                Get-NetFirewallProfile | Export-Csv "$FirewallBackupPath\FirewallProfiles.csv" -NoTypeInformation -ErrorAction SilentlyContinue
                Write-Log "Backed up firewall profiles" "INFO"
            }
            catch {
                Write-Log "Failed to backup firewall profiles: $($_.Exception.Message)" "WARN"
            }
            
            Write-Log "Firewall backup completed" "INFO"
        }
        catch {
            Write-Log "Failed to backup firewall rules: $($_.Exception.Message)" "ERROR"
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
                Write-Log "Backed up Windows features" "INFO"
            }
            catch {
                Write-Log "Could not export Windows features: $($_.Exception.Message)" "WARN"
            }
            
            # IIS modules
            try {
                Get-WebGlobalModule | Export-Csv "$SystemBackupPath\IISModules.csv" -NoTypeInformation -ErrorAction SilentlyContinue
                Write-Log "Backed up IIS modules" "INFO"
            }
            catch {
                Write-Log "Could not export IIS modules: $($_.Exception.Message)" "WARN"
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
            `$SiteBackups = Get-ChildItem "`$BackupPath\IIS\Sites" -Directory -ErrorAction SilentlyContinue
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
        }
    }
    else {
        Write-Log "Would restore firewall rules" "INFO"
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
    Write-Log "Starting administrator backup process" "INFO"
    Write-Log "Backup path: $BackupPath" "INFO"
    Write-Log "WhatIf mode: $WhatIf" "INFO"
    Write-Log "Administrator privileges: $(Test-Administrator)" "INFO"
    
    if (-not (Test-Administrator)) {
        Write-Log "This script requires Administrator privileges for complete backup" "WARN"
        Write-Log "Some backup operations may fail without administrator access" "WARN"
    }
    
    if (-not $WhatIf) {
        # Create backup directory
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        Write-Log "Created backup directory: $BackupPath" "INFO"
    }
    
    # Perform all backups
    Backup-IISConfiguration
    Backup-RegistrySettings
    Backup-FirewallRules
    Backup-SystemState
    Create-RestoreScript
    
    Write-Log "Administrator backup completed successfully" "INFO"
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
