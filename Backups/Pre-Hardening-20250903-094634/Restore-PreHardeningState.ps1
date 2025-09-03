# =============================================================================
# IIS Hardening Restore Script
# =============================================================================
# This script restores the system to pre-hardening state
# Generated: 09/03/2025 09:46:47
# Backup Path: .\Backups\Pre-Hardening-20250903-094634
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"
$BackupPath = ".\Backups\Pre-Hardening-20250903-094634"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restore-IISConfiguration {
    Write-Log "Restoring IIS configuration" "INFO"
    
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required to restore IIS configuration" "ERROR"
        return
    }
    
    if (-not $WhatIf) {
        try {
            # Stop IIS
            iisreset /stop
            
            # Restore main configuration files
            $ConfigFiles = @(
                "applicationHost.config",
                "administration.config", 
                "redirection.config"
            )
            
            foreach ($ConfigFile in $ConfigFiles) {
                $BackupFile = "$BackupPath\IIS\$ConfigFile.backup"
                $TargetFile = "$env:SystemRoot\System32\inetsrv\config\$ConfigFile"
                
                if (Test-Path $BackupFile) {
                    Copy-Item $BackupFile $TargetFile -Force
                    Write-Log "Restored: $ConfigFile" "INFO"
                }
            }
            
            # Start IIS
            iisreset /start
            
            Write-Log "IIS configuration restored successfully" "INFO"
        }
        catch {
            Write-Log "Failed to restore IIS configuration: $($_.Exception.Message)" "ERROR"
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
    
    if (-not $WhatIf) {
        try {
            $RegistryFiles = Get-ChildItem "$BackupPath\Registry\*.reg" -ErrorAction SilentlyContinue
            foreach ($RegFile in $RegistryFiles) {
                & reg import $RegFile.FullName
                Write-Log "Restored registry from: $($RegFile.Name)" "INFO"
            }
            
            Write-Log "Registry settings restored successfully" "INFO"
        }
        catch {
            Write-Log "Failed to restore registry settings: $($_.Exception.Message)" "ERROR"
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
        Write-Log "Please run: Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File $PSCommandPath' -Verb RunAs" "INFO"
        exit 1
    }
    
    Restore-IISConfiguration
    Restore-RegistrySettings
    
    Write-Log "Restore completed successfully" "INFO"
    Write-Log "Please restart the server to ensure all changes take effect" "WARN"
}
catch {
    Write-Log "Restore failed: $($_.Exception.Message)" "ERROR"
    exit 1
}
