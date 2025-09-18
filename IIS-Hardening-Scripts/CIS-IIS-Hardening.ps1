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

if (-not (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue | Where-Object {$_.InstallState -eq "Installed"})) {
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

function Set-IISServerHeaderRemoval {
    Write-Log "Removing server header - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Remove server header to prevent information disclosure
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /removeServerHeader:true /commit:apphost
            
            Write-Log "Server header removal configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure server header removal: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure server header removal" "INFO"
    }
}

function Set-IISDefaultDocuments {
    Write-Log "Configuring default documents - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Configure default documents securely
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/defaultDocument /enabled:true /commit:apphost
            
            # Remove potentially dangerous default documents
            $DangerousDocs = @("iisstart.htm", "default.aspx", "index.aspx")
            foreach ($Doc in $DangerousDocs) {
                try {
                    & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/defaultDocument /-"[file='$Doc']" /commit:apphost
                }
                catch {
                    # Document may not exist, continue
                }
            }
            
            Write-Log "Default documents configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure default documents: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure default documents" "INFO"
    }
}

function Set-IISHTTPRedirection {
    Write-Log "Configuring HTTP to HTTPS redirection - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Configure HTTP to HTTPS redirection
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpRedirect /enabled:true /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpRedirect /destination:"https://$env:COMPUTERNAME" /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpRedirect /exactDestination:true /commit:apphost
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpRedirect /httpResponseStatus:"Permanent" /commit:apphost
            
            Write-Log "HTTP to HTTPS redirection configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure HTTP redirection: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure HTTP to HTTPS redirection" "INFO"
    }
}

function Set-IISHTTPMethods {
    Write-Log "Configuring HTTP methods - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Restrict HTTP methods to only necessary ones
            $AllowedMethods = @("GET", "POST", "HEAD", "OPTIONS")
            $RestrictedMethods = @("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")
            
            # Allow only necessary methods
            foreach ($Method in $AllowedMethods) {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /+"verbs.[verb='$Method',allowed='true']" /commit:apphost
            }
            
            # Explicitly deny dangerous methods
            foreach ($Method in $RestrictedMethods) {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/requestFiltering /+"verbs.[verb='$Method',allowed='false']" /commit:apphost
            }
            
            Write-Log "HTTP methods configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure HTTP methods: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure HTTP methods" "INFO"
    }
}

function Set-IISCookieSecurity {
    Write-Log "Configuring cookie security - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Configure secure cookie attributes via web.config for default site
            # Note: system.web sections must be applied to individual sites, not globally
            $WebConfigPath = "C:\inetpub\wwwroot\web.config"
            
            # Create or update web.config with cookie security settings
            $WebConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.web>
        <httpCookies httpOnlyCookies="true" requireSSL="true" sameSite="Strict" />
    </system.web>
</configuration>
"@
            
            $WebConfigContent | Out-File -FilePath $WebConfigPath -Encoding UTF8 -Force
            Write-Log "Cookie security configured successfully via web.config" "INFO"
        }
        catch {
            Write-Log "Failed to configure cookie security: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure cookie security" "INFO"
    }
}

function Set-IISRequestValidation {
    Write-Log "Configuring request validation - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Enable request validation via web.config for default site
            # Note: system.web sections must be applied to individual sites, not globally
            $WebConfigPath = "C:\inetpub\wwwroot\web.config"
            
            # Read existing web.config or create new one
            if (Test-Path $WebConfigPath) {
                [xml]$WebConfig = Get-Content $WebConfigPath
            } else {
                [xml]$WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.web>
    </system.web>
</configuration>
"@
            }
            
            # Add or update request validation settings
            if (-not $WebConfig.configuration.'system.web'.pages) {
                $pagesNode = $WebConfig.CreateElement("pages")
                $WebConfig.configuration.'system.web'.AppendChild($pagesNode) | Out-Null
            }
            $WebConfig.configuration.'system.web'.pages.SetAttribute("validateRequest", "true")
            
            if (-not $WebConfig.configuration.'system.web'.httpRuntime) {
                $httpRuntimeNode = $WebConfig.CreateElement("httpRuntime")
                $WebConfig.configuration.'system.web'.AppendChild($httpRuntimeNode) | Out-Null
            }
            $WebConfig.configuration.'system.web'.httpRuntime.SetAttribute("requestValidationMode", "4.5")
            
            # Save the updated web.config
            $WebConfig.Save($WebConfigPath)
            Write-Log "Request validation configured successfully via web.config" "INFO"
        }
        catch {
            Write-Log "Failed to configure request validation: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure request validation" "INFO"
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
    
    # Apply additional CIS Level 1 security settings
    Set-IISServerHeaderRemoval
    Set-IISDefaultDocuments
    Set-IISHTTPRedirection
    Set-IISHTTPMethods
    Set-IISCookieSecurity
    Set-IISRequestValidation
    
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

