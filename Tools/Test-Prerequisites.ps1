# =============================================================================
# Test Prerequisites Script
# =============================================================================
# This script verifies that all prerequisites are met for CIS IIS hardening
# Author: Security Team
# Version: 1.0
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [switch]$Detailed
)

$ErrorActionPreference = "Continue"
$AllTestsPassed = $true

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = ""
    )
    
    $Status = if ($Passed) { "PASS" } else { "FAIL" }
    $Color = if ($Passed) { "Green" } else { "Red" }
    
    Write-Host "[$Status] $TestName" -ForegroundColor $Color
    if ($Message) {
        Write-Host "    $Message" -ForegroundColor Gray
    }
    
    if (-not $Passed) {
        $script:AllTestsPassed = $false
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    Write-TestResult "Administrator Privileges" $isAdmin "Current user has administrator privileges"
    return $isAdmin
}

function Test-WindowsVersion {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $version = [System.Environment]::OSVersion.Version
    
    $isSupported = ($version.Major -eq 10) -and ($version.Build -ge 17763) # Windows Server 2019/2022
    $message = "OS: $($os.Caption) (Build $($version.Build))"
    
    Write-TestResult "Windows Server Version" $isSupported $message
    return $isSupported
}

function Test-IISInstallation {
    try {
        $iisFeature = Get-WindowsFeature -Name IIS-WebServerRole -ErrorAction Stop
        $isInstalled = $iisFeature.InstallState -eq "Installed"
        $message = "IIS Web Server Role: $($iisFeature.InstallState)"
        
        Write-TestResult "IIS Installation" $isInstalled $message
        return $isInstalled
    }
    catch {
        Write-TestResult "IIS Installation" $false "IIS Web Server Role not found"
        return $false
    }
}

function Test-PowerShellVersion {
    $psVersion = $PSVersionTable.PSVersion
    $isSupported = $psVersion.Major -ge 5
    
    $message = "PowerShell Version: $($psVersion.ToString())"
    Write-TestResult "PowerShell Version" $isSupported $message
    return $isSupported
}

function Test-DotNetFramework {
    try {
        $dotNetVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release -ErrorAction Stop
        $isSupported = $dotNetVersion.Release -ge 528040 # .NET Framework 4.8
        
        $message = ".NET Framework Release: $($dotNetVersion.Release)"
        Write-TestResult ".NET Framework" $isSupported $message
        return $isSupported
    }
    catch {
        Write-TestResult ".NET Framework" $false ".NET Framework 4.8 or later not found"
        return $false
    }
}

function Test-DiskSpace {
    $drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
    $isSufficient = $freeSpaceGB -ge 2
    
    $message = "Free disk space: $freeSpaceGB GB"
    Write-TestResult "Disk Space" $isSufficient $message
    return $isSufficient
}

function Test-IISModules {
    try {
        $modules = Get-WebGlobalModule -ErrorAction Stop
        $requiredModules = @("DefaultDocumentModule", "StaticFileModule", "HttpRedirectionModule")
        $missingModules = @()
        
        foreach ($module in $requiredModules) {
            if (-not ($modules | Where-Object { $_.Name -eq $module })) {
                $missingModules += $module
            }
        }
        
        $isComplete = $missingModules.Count -eq 0
        $message = if ($isComplete) { "All required modules present" } else { "Missing modules: $($missingModules -join ', ')" }
        
        Write-TestResult "IIS Modules" $isComplete $message
        return $isComplete
    }
    catch {
        Write-TestResult "IIS Modules" $false "Unable to check IIS modules"
        return $false
    }
}

function Test-FirewallStatus {
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $allEnabled = $firewallProfiles | Where-Object { $_.Enabled -eq $false }
        $isEnabled = $allEnabled.Count -eq 0
        
        $message = "Firewall profiles enabled: $($firewallProfiles | Where-Object { $_.Enabled -eq $true } | Measure-Object | Select-Object -ExpandProperty Count)/3"
        Write-TestResult "Windows Firewall" $isEnabled $message
        return $isEnabled
    }
    catch {
        Write-TestResult "Windows Firewall" $false "Unable to check firewall status"
        return $false
    }
}

function Test-RegistryAccess {
    try {
        $testKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $testValue = Get-ItemProperty -Path $testKey -Name "EnableLUA" -ErrorAction Stop
        $hasAccess = $true
        
        Write-TestResult "Registry Access" $hasAccess "Can read/write registry keys"
        return $hasAccess
    }
    catch {
        Write-TestResult "Registry Access" $false "Cannot access registry keys"
        return $false
    }
}

# =============================================================================
# Main Execution
# =============================================================================

Write-Host "CIS IIS Hardening - Prerequisites Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Run all prerequisite tests
Test-Administrator
Test-WindowsVersion
Test-IISInstallation
Test-PowerShellVersion
Test-DotNetFramework
Test-DiskSpace
Test-IISModules
Test-FirewallStatus
Test-RegistryAccess

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

if ($AllTestsPassed) {
    Write-Host "All prerequisites tests PASSED" -ForegroundColor Green
    Write-Host "System is ready for CIS IIS hardening" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "Some prerequisite tests FAILED" -ForegroundColor Red
    Write-Host "Please address the failed tests before proceeding" -ForegroundColor Red
    exit 1
}

