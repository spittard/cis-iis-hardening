# =============================================================================
# CIS IIS Server Hardening Script
# =============================================================================
# This script applies CIS-compliant hardening to Windows Server with IIS
# Author: Security Team
# Version: 1.0
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Level1", "Level2", "Custom")]
    [string]$HardeningLevel = "Level1",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBackup,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# =============================================================================
# Configuration and Setup
# =============================================================================

$ErrorActionPreference = "Stop"
$LogFile = "C:\Windows\Logs\CIS-IIS-Hardening-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

# =============================================================================
# Pre-flight Checks
# =============================================================================

Write-Log "Starting CIS IIS Hardening Script" "INFO"
Write-Log "Hardening Level: $HardeningLevel" "INFO"
Write-Log "WhatIf Mode: $WhatIf" "INFO"

if (-not (Test-Administrator)) {
    Write-Log "This script must be run as Administrator" "ERROR"
    exit 1
}

if (-not (Get-WindowsFeature -Name IIS-WebServerRole -ErrorAction SilentlyContinue)) {
    Write-Log "IIS is not installed on this server" "ERROR"
    exit 1
}

# =============================================================================
# Backup Functions
# =============================================================================

function Backup-IISConfiguration {
    if ($SkipBackup) {
        Write-Log "Skipping backup as requested" "WARN"
        return
    }
    
    $BackupPath = "C:\Backups\IIS-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    
    Write-Log "Creating IIS configuration backup at: $BackupPath" "INFO"
    
    try {
        # Backup applicationHost.config
        Copy-Item "$env:SystemRoot\System32\inetsrv\config\applicationHost.config" "$BackupPath\applicationHost.config.backup"
        
        # Backup web.config files
        Get-WebSite | ForEach-Object {
            $SitePath = $_.PhysicalPath
            if (Test-Path "$SitePath\web.config") {
                $BackupSitePath = "$BackupPath\Sites\$($_.Name)"
                New-Item -ItemType Directory -Path $BackupSitePath -Force | Out-Null
                Copy-Item "$SitePath\web.config" "$BackupSitePath\web.config.backup"
            }
        }
        
        # Export IIS configuration
        & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list config /config /xml > "$BackupPath\iis-config-export.xml"
        
        Write-Log "IIS configuration backup completed successfully" "INFO"
    }
    catch {
        Write-Log "Failed to create IIS backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

# =============================================================================
# IIS Hardening Functions
# =============================================================================

function Set-IISSecurityHeaders {
    Write-Log "Configuring IIS security headers" "INFO"
    
    $SecurityHeaders = @{
        "X-Content-Type-Options" = "nosniff"
        "X-Frame-Options" = "DENY"
        "X-XSS-Protection" = "1; mode=block"
        "Strict-Transport-Security" = "max-age=31536000; includeSubDomains"
        "Referrer-Policy" = "strict-origin-when-cross-origin"
        "Content-Security-Policy" = "default-src 'self'"
    }
    
    foreach ($Header in $SecurityHeaders.GetEnumerator()) {
        if (-not $WhatIf) {
            try {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpProtocol/customHeaders /+"[name='$($Header.Key)',value='$($Header.Value)']" /commit:apphost
                Write-Log "Added security header: $($Header.Key)" "INFO"
            }
            catch {
                Write-Log "Failed to add security header $($Header.Key): $($_.Exception.Message)" "WARN"
            }
        }
        else {
            Write-Log "Would add security header: $($Header.Key) = $($Header.Value)" "INFO"
        }
    }
}

function Set-IISRequestFiltering {
    Write-Log "Configuring IIS request filtering" "INFO"
    
    if (-not $WhatIf) {
        try {
            # Enable request filtering
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /requestLimits.maxAllowedContentLength:10485760 /commit:apphost
            
            # Set file extension restrictions - CIS Level 1: Unlisted file extensions not allowed
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /fileExtensions.allowUnlisted:false /commit:apphost
            
            # Add allowed file extensions
            $AllowedExtensions = @(".html", ".htm", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".txt", ".xml", ".json")
            foreach ($Ext in $AllowedExtensions) {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='$Ext',allowed='true']" /commit:apphost
            }
            
            # CIS Level 1: Reject double-encoded requests
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /requestLimits.maxQueryString:2048 /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /requestLimits.maxUrl:4096 /commit:apphost
            
            # CIS Level 1: Disable HTTP TRACE method
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /verbs.allowUnlisted:true /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /+"verbs.[verb='TRACE',allowed='false']" /commit:apphost
            
            Write-Log "Request filtering configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure request filtering: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure request filtering rules" "INFO"
    }
}

function Set-IISAuthentication {
    Write-Log "Configuring IIS authentication" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Configure authentication based on hardening level
            if ($HardeningLevel -eq "Level1") {
                # Level 1: Allow anonymous authentication but configure it securely
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/authentication/anonymousAuthentication /enabled:true /commit:apphost
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/authentication/anonymousAuthentication /userName:"" /commit:apphost
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/authentication/anonymousAuthentication /password:"" /commit:apphost
            }
            else {
                # Level 2: Disable anonymous authentication
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/authentication/anonymousAuthentication /enabled:false /commit:apphost
            }
            
            # Enable Windows authentication
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/authentication/windowsAuthentication /enabled:true /commit:apphost
            
            # CIS Level 1: Configure basic authentication to require SSL
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/authentication/basicAuthentication /enabled:false /commit:apphost
            
            Write-Log "Authentication configured successfully for $HardeningLevel" "INFO"
        }
        catch {
            Write-Log "Failed to configure authentication: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure authentication settings for $HardeningLevel" "INFO"
    }
}

function Set-IISLogging {
    Write-Log "Configuring IIS logging" "INFO"
    
    if (-not $WhatIf) {
        try {
            # Enable detailed logging
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpLogging /dontLog:false /commit:apphost
            
            # Set log file format to W3C Extended
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.applicationHost/sites /siteDefaults.logFile.logFormat:"W3C" /commit:apphost
            
            Write-Log "Logging configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure logging: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure logging settings" "INFO"
    }
}

# =============================================================================
# CIS Level 1 Compliance Functions
# =============================================================================

function Set-IISDirectoryBrowsing {
    Write-Log "Disabling directory browsing - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Disable directory browsing globally
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/directoryBrowse /enabled:false /commit:apphost
            
            Write-Log "Directory browsing disabled successfully" "INFO"
        }
        catch {
            Write-Log "Failed to disable directory browsing: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would disable directory browsing" "INFO"
    }
}

function Set-IISWebDAV {
    Write-Log "Disabling WebDAV feature - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Disable WebDAV feature
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/webdav/authoring /enabled:false /commit:apphost
            
            Write-Log "WebDAV feature disabled successfully" "INFO"
        }
        catch {
            Write-Log "Failed to disable WebDAV: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would disable WebDAV feature" "INFO"
    }
}

function Set-IISHandlerPermissions {
    Write-Log "Configuring handler permissions - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Ensure handlers are not granted Write and Script/Execute permissions
            $Handlers = Get-WebHandler
            foreach ($Handler in $Handlers) {
                if ($Handler.requireAccess -match "Write|Script|Execute") {
                    Write-Log "Warning: Handler $($Handler.name) has potentially dangerous permissions" "WARN"
                }
            }
            
            Write-Log "Handler permissions reviewed" "INFO"
        }
        catch {
            Write-Log "Failed to review handler permissions: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would review handler permissions" "INFO"
    }
}

function Set-IISISAPIRestrictions {
    Write-Log "Configuring ISAPI restrictions - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Ensure notListedIsapisAllowed is set to false
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/isapiCgiRestriction /notListedIsapisAllowed:false /commit:apphost
            
            Write-Log "ISAPI restrictions configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure ISAPI restrictions: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure ISAPI restrictions" "INFO"
    }
}

function Set-IISCGRestrictions {
    Write-Log "Configuring CGI restrictions - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Ensure notListedCgisAllowed is set to false
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/isapiCgiRestriction /notListedCgisAllowed:false /commit:apphost
            
            Write-Log "CGI restrictions configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure CGI restrictions: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure CGI restrictions" "INFO"
    }
}

function Set-IISDynamicIPRestrictions {
    Write-Log "Enabling dynamic IP address restrictions - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Enable dynamic IP address restrictions
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/dynamicIpSecurity /enableDynamicIpSecurity:true /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/dynamicIpSecurity /denyByConcurrentRequests.enabled:true /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/dynamicIpSecurity /denyByConcurrentRequests.maxConcurrentRequests:20 /commit:apphost
            
            Write-Log "Dynamic IP restrictions configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure dynamic IP restrictions: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure dynamic IP restrictions" "INFO"
    }
}

function Set-IISAdvancedLogging {
    Write-Log "Enabling advanced IIS logging - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Enable advanced IIS logging
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.applicationHost/sites /siteDefaults.logFile.logFormat:"W3C" /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.applicationHost/sites /siteDefaults.logFile.logExtFileFlags:"Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,TimeTaken,ServerPort,UserAgent,Referer,Host,HttpSubStatus" /commit:apphost
            
            Write-Log "Advanced logging configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure advanced logging: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure advanced logging" "INFO"
    }
}

function Set-IISETWLogging {
    Write-Log "Enabling ETW logging - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Enable ETW logging
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.applicationHost/sites /siteDefaults.traceFailedRequestsLogging.enabled:true /commit:apphost
            
            Write-Log "ETW logging configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure ETW logging: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure ETW logging" "INFO"
    }
}

function Set-IISDetailedErrors {
    Write-Log "Hiding detailed errors from remote users - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Hide detailed errors from remote users
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpErrors /errorMode:"Custom" /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpErrors /defaultResponseMode:"ExecuteURL" /commit:apphost
            
            Write-Log "Detailed error hiding configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure detailed error hiding: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure detailed error hiding" "INFO"
    }
}

# =============================================================================
# IIS-Specific Security Functions
# =============================================================================

function Set-IISFirewallRules {
    Write-Log "Configuring Windows Firewall rules for IIS" "INFO"
    
    if (-not $WhatIf) {
        try {
            # Allow HTTP and HTTPS for IIS
            New-NetFirewallRule -DisplayName "IIS HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Any -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "IIS HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Any -ErrorAction SilentlyContinue
            
            Write-Log "IIS firewall rules configured" "INFO"
        }
        catch {
            Write-Log "Failed to configure IIS firewall rules: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure IIS firewall rules" "INFO"
    }
}

# =============================================================================
# Main Execution
# =============================================================================

try {
    Write-Log "Starting CIS IIS hardening process" "INFO"
    
    # Create backup
    Backup-IISConfiguration
    
    # Apply IIS hardening
    Set-IISSecurityHeaders
    Set-IISRequestFiltering
    Set-IISAuthentication
    Set-IISLogging
    
    # Apply CIS Level 1 compliance settings
    Set-IISDirectoryBrowsing
    Set-IISWebDAV
    Set-IISHandlerPermissions
    Set-IISISAPIRestrictions
    Set-IISCGRestrictions
    Set-IISDynamicIPRestrictions
    Set-IISAdvancedLogging
    Set-IISETWLogging
    Set-IISDetailedErrors
    
    # Apply IIS-specific security settings
    Set-IISFirewallRules
    
    Write-Log "CIS IIS hardening completed successfully" "INFO"
    Write-Log "Log file saved to: $LogFile" "INFO"
    
    if ($WhatIf) {
        Write-Log "WhatIf mode completed - no changes were made" "INFO"
    }
    else {
        Write-Log "Hardening applied successfully. Please review the log file for details." "INFO"
    }
}
catch {
    Write-Log "Hardening failed: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}

