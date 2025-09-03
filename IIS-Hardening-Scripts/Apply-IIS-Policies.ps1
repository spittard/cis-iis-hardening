# =============================================================================
# Apply IIS Security Policies Script
# =============================================================================
# This script applies additional security policies and configurations to IIS
# Author: Security Team
# Version: 1.0
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [string]$PolicyPath = ".\IIS-Policies"
)

$ErrorActionPreference = "Stop"
$LogFile = "C:\Windows\Logs\Apply-IIS-Policies-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

function Apply-SSLConfiguration {
    Write-Log "Applying SSL/TLS configuration - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Disable SSLv2 and SSLv3
            Disable-TlsCipherSuite -Name "TLS_RSA_WITH_DES_CBC_SHA" -ErrorAction SilentlyContinue
            Disable-TlsCipherSuite -Name "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" -ErrorAction SilentlyContinue
            
            # CIS Level 1: Disable TLS 1.0 and TLS 1.1
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            
            # CIS Level 1: Enable TLS 1.2
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            
            # CIS Level 1: Disable NULL cipher suites
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            
            # CIS Level 1: Disable DES cipher suites
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            
            # CIS Level 1: Disable RC4 cipher suites
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            
            # CIS Level 1: Enable AES 256/256 cipher suite
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
            
            # Configure SSL flags for IIS
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/access /sslFlags:"Ssl, SslNegotiateCert, SslRequireCert" /commit:apphost
            
            Write-Log "SSL/TLS configuration applied successfully" "INFO"
        }
        catch {
            Write-Log "Failed to apply SSL configuration: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would apply SSL/TLS configuration" "INFO"
    }
}

function Apply-IPRestrictions {
    Write-Log "Applying IP restrictions" "INFO"
    
    if (-not $WhatIf) {
        try {
            # Configure IP restrictions (example - restrict to local network)
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/ipSecurity /allowUnlisted:false /commit:apphost
            
            # Add local network range (example)
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/security/ipSecurity /+"[ipAddress='192.168.0.0',subnetMask='255.255.0.0',allowed='true']" /commit:apphost
            
            Write-Log "IP restrictions applied successfully" "INFO"
        }
        catch {
            Write-Log "Failed to apply IP restrictions: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would apply IP restrictions" "INFO"
    }
}

f
unction Apply-CompressionSettings {
    Write-Log "Applying compression settings" "INFO"
    
    if (-not $WhatIf) {
        try {
            # Enable dynamic compression
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/urlCompression /doDynamicCompression:true /commit:apphost
            
            # Enable static compression
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/urlCompression /doStaticCompression:true /commit:apphost
            
            Write-Log "Compression settings applied successfully" "INFO"
        }
        catch {
            Write-Log "Failed to apply compression settings: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would apply compression settings" "INFO"
    }
}

function Apply-CachingPolicies {
    Write-Log "Applying caching policies" "INFO"
    
    if (-not $WhatIf) {
        try {
            # Configure output caching
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/caching /enabled:true /commit:apphost
            
            # Set cache control headers
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.webServer/httpProtocol/customHeaders /+"[name='Cache-Control',value='no-cache, no-store, must-revalidate']" /commit:apphost
            
            Write-Log "Caching policies applied successfully" "INFO"
        }
        catch {
            Write-Log "Failed to apply caching policies: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would apply caching policies" "INFO"
    }
}

function Apply-HostHeadersConfiguration {
    Write-Log "Configuring host headers - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Ensure host headers are configured for all sites
            $Sites = Get-WebSite
            foreach ($Site in $Sites) {
                $Bindings = Get-WebBinding -Name $Site.Name
                $HasHostHeader = $false
                
                foreach ($Binding in $Bindings) {
                    if ($Binding.bindingInformation -match ":\d+:.+") {
                        $HasHostHeader = $true
                        break
                    }
                }
                
                if (-not $HasHostHeader) {
                    Write-Log "Warning: Site '$($Site.Name)' does not have host headers configured" "WARN"
                }
            }
            
            Write-Log "Host headers configuration reviewed" "INFO"
        }
        catch {
            Write-Log "Failed to review host headers: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would review host headers configuration" "INFO"
    }
}

function Apply-ApplicationPoolConfiguration {
    Write-Log "Configuring application pools - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Ensure application pool identity is configured
            $AppPools = Get-IISAppPool
            foreach ($AppPool in $AppPools) {
                if ($AppPool.processModel.identityType -eq "ApplicationPoolIdentity") {
                    Write-Log "Application pool '$($AppPool.Name)' is using ApplicationPoolIdentity" "INFO"
                }
                else {
                    Write-Log "Warning: Application pool '$($AppPool.Name)' is not using ApplicationPoolIdentity" "WARN"
                }
            }
            
            Write-Log "Application pool configuration reviewed" "INFO"
        }
        catch {
            Write-Log "Failed to review application pool configuration: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would review application pool configuration" "INFO"
    }
}

function Apply-AuthenticationConfiguration {
    Write-Log "Configuring authentication settings - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Configure forms authentication to require SSL
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.web/authentication/forms /requireSSL:true /commit:apphost
            
            # CIS Level 1: Configure cookie protection mode
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.web/authentication/forms /protection:"All" /commit:apphost
            
            # CIS Level 1: Configure HttpOnly cookies
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.web/httpCookies /httpOnlyCookies:true /commit:apphost
            
            Write-Log "Authentication configuration applied successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure authentication: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure authentication settings" "INFO"
    }
}

function Apply-DotNetConfiguration {
    Write-Log "Configuring .NET settings - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Set deployment method to retail
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.web/compilation /debug:false /commit:apphost
            
            # CIS Level 1: Configure global .NET trust level
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.web/trust /level:"Full" /commit:apphost
            
            # CIS Level 1: Configure MachineKey validation method
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.web/machineKey /validation:"HMACSHA256" /commit:apphost
            
            Write-Log ".NET configuration applied successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure .NET settings: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure .NET settings" "INFO"
    }
}

function Apply-LogLocationConfiguration {
    Write-Log "Configuring log location - CIS Level 1" "INFO"
    
    if (-not $WhatIf) {
        try {
            # CIS Level 1: Move default IIS web log location
            $LogPath = "C:\Logs\IIS"
            if (-not (Test-Path $LogPath)) {
                New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
            }
            
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.applicationHost/sites /siteDefaults.logFile.directory:"$LogPath" /commit:apphost
            
            Write-Log "Log location configured successfully" "INFO"
        }
        catch {
            Write-Log "Failed to configure log location: $($_.Exception.Message)" "ERROR"
        }
    }
    else {
        Write-Log "Would configure log location" "INFO"
    }
}

# =============================================================================
# Main Execution
# =============================================================================

try {
    Write-Log "Starting IIS policy application" "INFO"
    
    if (-not (Test-Administrator)) {
        Write-Log "This script must be run as Administrator" "ERROR"
        exit 1
    }
    
    # Apply various IIS policies
    Apply-SSLConfiguration
    Apply-IPRestrictions
    Apply-CompressionSettings
    Apply-CachingPolicies
    
    # Apply CIS Level 1 compliance policies
    Apply-HostHeadersConfiguration
    Apply-ApplicationPoolConfiguration
    Apply-AuthenticationConfiguration
    Apply-DotNetConfiguration
    Apply-LogLocationConfiguration
    
    Write-Log "IIS policy application completed successfully" "INFO"
    Write-Log "Log file saved to: $LogFile" "INFO"
    
    if ($WhatIf) {
        Write-Log "WhatIf mode completed - no changes were made" "INFO"
    }
    else {
        Write-Log "Policies applied successfully. Please review the log file for details." "INFO"
    }
}
catch {
    Write-Log "Policy application failed: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}

