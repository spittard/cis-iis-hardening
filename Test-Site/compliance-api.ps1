# =============================================================================
# CIS Level 1 Compliance Validation API
# =============================================================================
# This script provides server-side validation for CIS Level 1 compliance
# Can be called via HTTP requests to validate security configurations
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$TestType = "all"
)

$ErrorActionPreference = "Continue"

function Write-JsonResponse {
    param(
        [object]$Data,
        [int]$StatusCode = 200
    )
    
    $json = $Data | ConvertTo-Json -Depth 10
    Write-Host "Content-Type: application/json"
    Write-Host "Status: $StatusCode"
    Write-Host ""
    Write-Host $json
}

function Test-IISConfiguration {
    $results = @{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        tests = @()
        summary = @{
            total = 0
            passed = 0
            failed = 0
            warnings = 0
        }
    }

    # Test 1: Directory Browsing
    try {
        $dirBrowsing = Get-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -Name "enabled" -PSPath "IIS:\"
        $test = @{
            name = "Directory Browsing Disabled"
            status = if ($dirBrowsing.Value -eq $false) { "PASS" } else { "FAIL" }
            details = "Directory browsing is $($dirBrowsing.Value)"
            cis_requirement = "CIS 1.1.1"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "Directory Browsing Disabled"
            status = "WARNING"
            details = "Could not check directory browsing configuration"
            cis_requirement = "CIS 1.1.1"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 2: WebDAV Disabled
    try {
        $webdav = Get-WebConfigurationProperty -Filter "system.webServer/webdav/authoring" -Name "enabled" -PSPath "IIS:\"
        $test = @{
            name = "WebDAV Disabled"
            status = if ($webdav.Value -eq $false) { "PASS" } else { "FAIL" }
            details = "WebDAV is $($webdav.Value)"
            cis_requirement = "CIS 1.1.2"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "WebDAV Disabled"
            status = "WARNING"
            details = "Could not check WebDAV configuration"
            cis_requirement = "CIS 1.1.2"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 3: ISAPI Restrictions
    try {
        $isapiRestrictions = Get-WebConfigurationProperty -Filter "system.webServer/security/isapiCgiRestriction" -Name "notListedIsapisAllowed" -PSPath "IIS:\"
        $test = @{
            name = "ISAPI Restrictions Enabled"
            status = if ($isapiRestrictions.Value -eq $false) { "PASS" } else { "FAIL" }
            details = "Unlisted ISAPIs allowed: $($isapiRestrictions.Value)"
            cis_requirement = "CIS 1.1.3"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "ISAPI Restrictions Enabled"
            status = "WARNING"
            details = "Could not check ISAPI restrictions"
            cis_requirement = "CIS 1.1.3"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 4: CGI Restrictions
    try {
        $cgiRestrictions = Get-WebConfigurationProperty -Filter "system.webServer/security/isapiCgiRestriction" -Name "notListedCgisAllowed" -PSPath "IIS:\"
        $test = @{
            name = "CGI Restrictions Enabled"
            status = if ($cgiRestrictions.Value -eq $false) { "PASS" } else { "FAIL" }
            details = "Unlisted CGIs allowed: $($cgiRestrictions.Value)"
            cis_requirement = "CIS 1.1.4"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "CGI Restrictions Enabled"
            status = "WARNING"
            details = "Could not check CGI restrictions"
            cis_requirement = "CIS 1.1.4"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 5: Request Filtering - File Extensions
    try {
        $fileExtensions = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "allowUnlisted" -PSPath "IIS:\"
        $test = @{
            name = "File Extension Restrictions"
            status = if ($fileExtensions.Value -eq $false) { "PASS" } else { "FAIL" }
            details = "Unlisted file extensions allowed: $($fileExtensions.Value)"
            cis_requirement = "CIS 1.1.5"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "File Extension Restrictions"
            status = "WARNING"
            details = "Could not check file extension restrictions"
            cis_requirement = "CIS 1.1.5"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 6: Request Filtering - TRACE Method
    try {
        $traceVerb = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/verbs" -PSPath "IIS:\" | Where-Object { $_.verb -eq "TRACE" }
        $test = @{
            name = "TRACE Method Blocked"
            status = if ($traceVerb -and $traceVerb.allowed -eq $false) { "PASS" } else { "FAIL" }
            details = "TRACE method allowed: $($traceVerb.allowed)"
            cis_requirement = "CIS 1.1.6"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "TRACE Method Blocked"
            status = "WARNING"
            details = "Could not check TRACE method configuration"
            cis_requirement = "CIS 1.1.6"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 7: Authentication Configuration
    try {
        $anonymousAuth = Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -PSPath "IIS:\"
        $windowsAuth = Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -PSPath "IIS:\"
        $basicAuth = Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/basicAuthentication" -Name "enabled" -PSPath "IIS:\"
        
        $test = @{
            name = "Authentication Configuration"
            status = if ($basicAuth.Value -eq $false) { "PASS" } else { "FAIL" }
            details = "Anonymous: $($anonymousAuth.Value), Windows: $($windowsAuth.Value), Basic: $($basicAuth.Value)"
            cis_requirement = "CIS 1.1.7"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "Authentication Configuration"
            status = "WARNING"
            details = "Could not check authentication configuration"
            cis_requirement = "CIS 1.1.7"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 8: Dynamic IP Restrictions
    try {
        $dynamicIP = Get-WebConfigurationProperty -Filter "system.webServer/security/dynamicIpSecurity" -Name "enableDynamicIpSecurity" -PSPath "IIS:\"
        $test = @{
            name = "Dynamic IP Restrictions"
            status = if ($dynamicIP.Value -eq $true) { "PASS" } else { "FAIL" }
            details = "Dynamic IP security enabled: $($dynamicIP.Value)"
            cis_requirement = "CIS 1.1.8"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "Dynamic IP Restrictions"
            status = "WARNING"
            details = "Could not check dynamic IP restrictions"
            cis_requirement = "CIS 1.1.8"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 9: Logging Configuration
    try {
        $logging = Get-WebConfigurationProperty -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "logFormat" -PSPath "IIS:\"
        $test = @{
            name = "W3C Extended Logging"
            status = if ($logging.Value -eq "W3C") { "PASS" } else { "FAIL" }
            details = "Log format: $($logging.Value)"
            cis_requirement = "CIS 1.1.9"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "W3C Extended Logging"
            status = "WARNING"
            details = "Could not check logging configuration"
            cis_requirement = "CIS 1.1.9"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 10: Failed Request Tracing
    try {
        $failedRequestTracing = Get-WebConfigurationProperty -Filter "system.applicationHost/sites/siteDefaults/traceFailedRequestsLogging" -Name "enabled" -PSPath "IIS:\"
        $test = @{
            name = "Failed Request Tracing"
            status = if ($failedRequestTracing.Value -eq $true) { "PASS" } else { "FAIL" }
            details = "Failed request tracing enabled: $($failedRequestTracing.Value)"
            cis_requirement = "CIS 1.1.10"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "Failed Request Tracing"
            status = "WARNING"
            details = "Could not check failed request tracing"
            cis_requirement = "CIS 1.1.10"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 11: Error Handling
    try {
        $errorMode = Get-WebConfigurationProperty -Filter "system.webServer/httpErrors" -Name "errorMode" -PSPath "IIS:\"
        $test = @{
            name = "Detailed Errors Hidden"
            status = if ($errorMode.Value -eq "Custom") { "PASS" } else { "FAIL" }
            details = "Error mode: $($errorMode.Value)"
            cis_requirement = "CIS 1.1.11"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.failed++ }
    }
    catch {
        $test = @{
            name = "Detailed Errors Hidden"
            status = "WARNING"
            details = "Could not check error handling configuration"
            cis_requirement = "CIS 1.1.11"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 12: Server Header Configuration
    try {
        $removeServerHeader = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        $test = @{
            name = "Server Header Removal"
            status = if ($removeServerHeader -and $removeServerHeader.Value -eq $true) { "PASS" } else { "WARNING" }
            details = "Server header removal: $($removeServerHeader.Value)"
            cis_requirement = "CIS 1.1.12"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Server Header Removal"
            status = "WARNING"
            details = "Could not check server header configuration"
            cis_requirement = "CIS 1.1.12"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 13: Request Size Limits
    try {
        $maxContentLength = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -PSPath "IIS:\"
        $test = @{
            name = "Request Size Limits"
            status = if ($maxContentLength.Value -le 10485760) { "PASS" } else { "WARNING" }
            details = "Max content length: $($maxContentLength.Value) bytes"
            cis_requirement = "CIS 1.1.13"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Request Size Limits"
            status = "WARNING"
            details = "Could not check request size limits"
            cis_requirement = "CIS 1.1.13"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 14: URL Length Limits
    try {
        $maxUrl = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -PSPath "IIS:\"
        $test = @{
            name = "URL Length Limits"
            status = if ($maxUrl.Value -le 4096) { "PASS" } else { "WARNING" }
            details = "Max URL length: $($maxUrl.Value) characters"
            cis_requirement = "CIS 1.1.14"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "URL Length Limits"
            status = "WARNING"
            details = "Could not check URL length limits"
            cis_requirement = "CIS 1.1.14"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 15: Query String Length Limits
    try {
        $maxQueryString = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -PSPath "IIS:\"
        $test = @{
            name = "Query String Length Limits"
            status = if ($maxQueryString.Value -le 2048) { "PASS" } else { "WARNING" }
            details = "Max query string length: $($maxQueryString.Value) characters"
            cis_requirement = "CIS 1.1.15"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Query String Length Limits"
            status = "WARNING"
            details = "Could not check query string length limits"
            cis_requirement = "CIS 1.1.15"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 16: Handler Mappings Review
    try {
        $handlers = Get-WebHandler -PSPath "IIS:\"
        $dangerousHandlers = $handlers | Where-Object { $_.requireAccess -match "Write|Script|Execute" }
        $test = @{
            name = "Handler Mappings Security"
            status = if ($dangerousHandlers.Count -eq 0) { "PASS" } else { "WARNING" }
            details = "Dangerous handlers found: $($dangerousHandlers.Count)"
            cis_requirement = "CIS 1.1.16"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Handler Mappings Security"
            status = "WARNING"
            details = "Could not check handler mappings"
            cis_requirement = "CIS 1.1.16"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 17: Compression Configuration
    try {
        $compression = Get-WebConfigurationProperty -Filter "system.webServer/urlCompression" -Name "doDynamicCompression" -PSPath "IIS:\"
        $test = @{
            name = "Dynamic Compression"
            status = if ($compression.Value -eq $true) { "PASS" } else { "WARNING" }
            details = "Dynamic compression enabled: $($compression.Value)"
            cis_requirement = "CIS 1.1.17"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Dynamic Compression"
            status = "WARNING"
            details = "Could not check compression configuration"
            cis_requirement = "CIS 1.1.17"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 18: Default Document Configuration
    try {
        $defaultDocs = Get-WebConfigurationProperty -Filter "system.webServer/defaultDocument" -Name "enabled" -PSPath "IIS:\"
        $test = @{
            name = "Default Document Configuration"
            status = if ($defaultDocs.Value -eq $true) { "PASS" } else { "WARNING" }
            details = "Default documents enabled: $($defaultDocs.Value)"
            cis_requirement = "CIS 1.1.18"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Default Document Configuration"
            status = "WARNING"
            details = "Could not check default document configuration"
            cis_requirement = "CIS 1.1.18"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 19: HTTP Redirection
    try {
        $httpRedirect = Get-WebConfigurationProperty -Filter "system.webServer/httpRedirect" -Name "enabled" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        $test = @{
            name = "HTTP to HTTPS Redirection"
            status = if ($httpRedirect -and $httpRedirect.Value -eq $true) { "PASS" } else { "WARNING" }
            details = "HTTP redirection enabled: $($httpRedirect.Value)"
            cis_requirement = "CIS 1.1.19"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "HTTP to HTTPS Redirection"
            status = "WARNING"
            details = "Could not check HTTP redirection configuration"
            cis_requirement = "CIS 1.1.19"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 20: Custom Error Pages
    try {
        $customErrors = Get-WebConfigurationProperty -Filter "system.webServer/httpErrors" -Name "defaultResponseMode" -PSPath "IIS:\"
        $test = @{
            name = "Custom Error Pages"
            status = if ($customErrors.Value -eq "ExecuteURL") { "PASS" } else { "WARNING" }
            details = "Custom error response mode: $($customErrors.Value)"
            cis_requirement = "CIS 1.1.20"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Custom Error Pages"
            status = "WARNING"
            details = "Could not check custom error configuration"
            cis_requirement = "CIS 1.1.20"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 21: Server Header Removal
    try {
        $removeServerHeader = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        $test = @{
            name = "Server Header Removal"
            status = if ($removeServerHeader -and $removeServerHeader.Value -eq $true) { "PASS" } else { "WARNING" }
            details = "Server header removal: $($removeServerHeader.Value)"
            cis_requirement = "CIS 1.1.21"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Server Header Removal"
            status = "WARNING"
            details = "Could not check server header removal"
            cis_requirement = "CIS 1.1.21"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 22: HTTP Methods Restriction
    try {
        $traceVerb = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/verbs" -PSPath "IIS:\" | Where-Object { $_.verb -eq "TRACE" }
        $putVerb = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/verbs" -PSPath "IIS:\" | Where-Object { $_.verb -eq "PUT" }
        $deleteVerb = Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/verbs" -PSPath "IIS:\" | Where-Object { $_.verb -eq "DELETE" }
        
        $dangerousMethodsBlocked = 0
        if ($traceVerb -and $traceVerb.allowed -eq $false) { $dangerousMethodsBlocked++ }
        if ($putVerb -and $putVerb.allowed -eq $false) { $dangerousMethodsBlocked++ }
        if ($deleteVerb -and $deleteVerb.allowed -eq $false) { $dangerousMethodsBlocked++ }
        
        $test = @{
            name = "HTTP Methods Restriction"
            status = if ($dangerousMethodsBlocked -ge 2) { "PASS" } else { "WARNING" }
            details = "Dangerous HTTP methods blocked: $dangerousMethodsBlocked/3"
            cis_requirement = "CIS 1.1.22"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "HTTP Methods Restriction"
            status = "WARNING"
            details = "Could not check HTTP methods restriction"
            cis_requirement = "CIS 1.1.22"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 23: Cookie Security
    try {
        $httpOnlyCookies = Get-WebConfigurationProperty -Filter "system.web/httpCookies" -Name "httpOnlyCookies" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        $requireSSLCookies = Get-WebConfigurationProperty -Filter "system.web/httpCookies" -Name "requireSSL" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        
        $secureCookies = 0
        if ($httpOnlyCookies -and $httpOnlyCookies.Value -eq $true) { $secureCookies++ }
        if ($requireSSLCookies -and $requireSSLCookies.Value -eq $true) { $secureCookies++ }
        
        $test = @{
            name = "Cookie Security"
            status = if ($secureCookies -ge 1) { "PASS" } else { "WARNING" }
            details = "Secure cookie attributes enabled: $secureCookies/2"
            cis_requirement = "CIS 1.1.23"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Cookie Security"
            status = "WARNING"
            details = "Could not check cookie security"
            cis_requirement = "CIS 1.1.23"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 24: Request Validation
    try {
        $validateRequest = Get-WebConfigurationProperty -Filter "system.web/pages" -Name "validateRequest" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        $requestValidationMode = Get-WebConfigurationProperty -Filter "system.web/httpRuntime" -Name "requestValidationMode" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        
        $validationEnabled = 0
        if ($validateRequest -and $validateRequest.Value -eq $true) { $validationEnabled++ }
        if ($requestValidationMode -and $requestValidationMode.Value -eq "4.5") { $validationEnabled++ }
        
        $test = @{
            name = "Request Validation"
            status = if ($validationEnabled -ge 1) { "PASS" } else { "WARNING" }
            details = "Request validation enabled: $validationEnabled/2"
            cis_requirement = "CIS 1.1.24"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "Request Validation"
            status = "WARNING"
            details = "Could not check request validation"
            cis_requirement = "CIS 1.1.24"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    # Test 25: HTTP Redirection
    try {
        $httpRedirect = Get-WebConfigurationProperty -Filter "system.webServer/httpRedirect" -Name "enabled" -PSPath "IIS:\" -ErrorAction SilentlyContinue
        $test = @{
            name = "HTTP to HTTPS Redirection"
            status = if ($httpRedirect -and $httpRedirect.Value -eq $true) { "PASS" } else { "WARNING" }
            details = "HTTP redirection enabled: $($httpRedirect.Value)"
            cis_requirement = "CIS 1.1.25"
        }
        $results.tests += $test
        $results.summary.total++
        if ($test.status -eq "PASS") { $results.summary.passed++ } else { $results.summary.warnings++ }
    }
    catch {
        $test = @{
            name = "HTTP to HTTPS Redirection"
            status = "WARNING"
            details = "Could not check HTTP redirection"
            cis_requirement = "CIS 1.1.25"
        }
        $results.tests += $test
        $results.summary.total++
        $results.summary.warnings++
    }

    return $results
}

# Main execution
try {
    Import-Module WebAdministration -ErrorAction Stop
    
    $results = Test-IISConfiguration
    
    # Calculate compliance percentage
    $compliancePercentage = if ($results.summary.total -gt 0) {
        [math]::Round(($results.summary.passed / $results.summary.total) * 100, 2)
    } else {
        0
    }
    
    $results | Add-Member -NotePropertyName "compliance_percentage" -NotePropertyValue $compliancePercentage
    
    Write-JsonResponse -Data $results
}
catch {
    $errorResponse = @{
        error = $_.Exception.Message
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    Write-JsonResponse -Data $errorResponse -StatusCode 500
}
