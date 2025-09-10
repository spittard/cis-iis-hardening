# Troubleshooting Guide

This guide provides solutions for common issues encountered during and after applying CIS IIS hardening configurations.

## Pre-Installation Issues

### Prerequisites Not Met

#### Issue: PowerShell Version Too Old
**Symptoms:**
- Script fails with version error
- PowerShell 5.1+ required message

**Solution:**
```powershell
# Check current version
$PSVersionTable.PSVersion

# Update PowerShell (if needed)
# Download from: https://github.com/PowerShell/PowerShell/releases
```

#### Issue: Insufficient Permissions
**Symptoms:**
- Access denied errors
- Script fails to modify IIS settings

**Solution:**
```powershell
# Run PowerShell as Administrator
# Verify permissions
Get-Acl "C:\inetpub" | Format-List

# Grant IIS_IUSRS permissions if needed
icacls "C:\inetpub" /grant "IIS_IUSRS:(OI)(CI)F"
```

#### Issue: IIS Not Installed
**Symptoms:**
- IIS modules not found
- Web server role missing

**Solution:**
```powershell
# Install IIS via PowerShell
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering
Enable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent
Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument
Enable-WindowsOptionalFeature -Online -FeatureName IIS-DirectoryBrowsing
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45
```

## Installation Issues

### Script Execution Errors

#### Issue: Execution Policy Restriction
**Symptoms:**
- Script execution disabled
- "execution of scripts is disabled" error

**Solution:**
```powershell
# Check current policy
Get-ExecutionPolicy

# Set execution policy (temporarily)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or run script directly
PowerShell -ExecutionPolicy Bypass -File ".\CIS-IIS-Hardening.ps1"
```

#### Issue: Module Import Failures
**Symptoms:**
- Module not found errors
- Import-Module failures

**Solution:**
```powershell
# Install required modules
Install-Module -Name WebAdministration -Force
Install-Module -Name IISAdministration -Force

# Import modules manually
Import-Module WebAdministration
Import-Module IISAdministration
```

### Backup Issues

#### Issue: Backup Creation Fails
**Symptoms:**
- Backup script fails
- Insufficient disk space

**Solution:**
```powershell
# Check available disk space
Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}}, @{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace/1GB,2)}}

# Create backup with custom path
.\Tools\Create-AdminBackup.ps1 -BackupPath "D:\Backups\IIS-Hardening-$(Get-Date -Format 'yyyyMMdd')"
```

#### Issue: Registry Backup Fails
**Symptoms:**
- Registry export errors
- Permission denied

**Solution:**
```powershell
# Run as Administrator
# Check registry permissions
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" | Format-List

# Export registry manually
reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" "C:\Backups\SCHANNEL.reg"
```

## Post-Installation Issues

### Web Application Issues

#### Issue: Web Application Not Loading
**Symptoms:**
- 500 Internal Server Error
- Application pool stopped
- Site not accessible

**Solution:**
```powershell
# Check application pool status
Get-IISAppPool | Select-Object Name, State

# Start application pool
Start-WebAppPool -Name "YourAppPoolName"

# Check site status
Get-IISSite | Select-Object Name, State

# Start site
Start-IISSite -Name "YourSiteName"

# Check event logs
Get-EventLog -LogName Application -Source "IIS*" -Newest 10
```

#### Issue: Static Content Not Loading
**Symptoms:**
- CSS/JS files return 404
- Images not displaying
- Static content blocked

**Solution:**
```powershell
# Check static content handler
Get-WebHandler -Name "StaticFile" -PSPath "IIS:\"

# Enable static content if disabled
Add-WebConfigurationProperty -Filter "system.webServer/handlers" -Name "." -Value @{name="StaticFile";path="*";verb="*";modules="StaticFileModule,DefaultDocumentModule,DirectoryListingModule";resourceType="Either";requireAccess="Read"}

# Check MIME types
Get-WebConfigurationProperty -Filter "system.webServer/staticContent" -Name "." | Select-Object fileExtension, mimeType
```

#### Issue: Authentication Failures
**Symptoms:**
- Users cannot log in
- Authentication errors
- 401 Unauthorized

**Solution:**
```powershell
# Check authentication settings
Get-WebConfigurationProperty -Filter "system.webServer/security/authentication" -Name "." | Select-Object name, enabled

# Enable Windows Authentication
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value $true

# Enable Forms Authentication
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/formsAuthentication" -Name "enabled" -Value $true

# Check user permissions
Get-Acl "C:\inetpub\wwwroot\YourApp" | Format-List
```

### SSL/TLS Issues

#### Issue: SSL Certificate Errors
**Symptoms:**
- Certificate not trusted
- SSL handshake failures
- Mixed content warnings

**Solution:**
```powershell
# Check certificate binding
Get-WebBinding -Protocol "https" | Select-Object protocol, bindingInformation, certificateHash

# Check certificate validity
Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Subject -like "*yourdomain*"} | Select-Object Subject, NotAfter, Thumbprint

# Renew certificate if expired
# Install new certificate
$cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq "YourThumbprint"}
New-WebBinding -Name "YourSite" -Protocol "https" -Port 443 -SslFlags 1
```

#### Issue: TLS Protocol Errors
**Symptoms:**
- TLS handshake failures
- Protocol not supported
- Connection refused

**Solution:**
```powershell
# Check TLS protocol settings
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled"

# Enable TLS 1.2 if disabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1

# Restart IIS
iisreset
```

### Performance Issues

#### Issue: Slow Response Times
**Symptoms:**
- High response times
- Timeout errors
- Poor performance

**Solution:**
```powershell
# Check compression settings
Get-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "." | Select-Object directory, enabled

# Enable compression
Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "enabled" -Value $true

# Check caching settings
Get-WebConfigurationProperty -Filter "system.webServer/staticContent" -Name "." | Select-Object clientCache

# Enable client caching
Set-WebConfigurationProperty -Filter "system.webServer/staticContent/clientCache" -Name "cacheControlMode" -Value "UseMaxAge"
Set-WebConfigurationProperty -Filter "system.webServer/staticContent/clientCache" -Name "cacheControlMaxAge" -Value "365.00:00:00"
```

#### Issue: High Memory Usage
**Symptoms:**
- High memory consumption
- Application pool recycling
- Out of memory errors

**Solution:**
```powershell
# Check application pool settings
Get-IISAppPool | Select-Object Name, ProcessModel, Recycling

# Adjust memory limits
Set-ItemProperty -Path "IIS:\AppPools\YourAppPool" -Name "ProcessModel.PrivateMemoryLimit" -Value 0

# Check worker process memory
Get-Process -Name "w3wp" | Select-Object ProcessName, WorkingSet, VirtualMemorySize
```

### Security Issues

#### Issue: Security Headers Not Applied
**Symptoms:**
- Security headers missing
- Compliance test failures
- Security warnings

**Solution:**
```powershell
# Check security headers
Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -Name "." | Select-Object name, value

# Add missing headers
Add-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name="X-Content-Type-Options";value="nosniff"}

# Verify headers
Invoke-WebRequest -Uri "https://yoursite.com" -UseBasicParsing | Select-Object Headers
```

#### Issue: Request Filtering Too Restrictive
**Symptoms:**
- Legitimate requests blocked
- 404 errors for valid files
- Application functionality broken

**Solution:**
```powershell
# Check request filtering settings
Get-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering" -Name "." | Select-Object fileExtensions, verbs, requestLimits

# Adjust file extension restrictions
Set-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "allowUnlisted" -Value $true

# Adjust request limits
Set-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 10485760
```

## Rollback Procedures

### Complete Rollback
```powershell
# Restore from backup
.\Tools\Restore-PreHardeningState.ps1 -BackupPath "C:\Backups\Pre-Hardening-YYYYMMDD"

# Verify restoration
Get-IISSite | Select-Object Name, State
Get-IISAppPool | Select-Object Name, State
```

### Partial Rollback
```powershell
# Restore specific configurations
# Restore IIS configuration
Import-WebConfiguration -Path "C:\Backups\Pre-Hardening-YYYYMMDD\IIS\iis-config-export.xml"

# Restore registry settings
reg import "C:\Backups\Pre-Hardening-YYYYMMDD\Registry\SCHANNEL_Ciphers.reg"
reg import "C:\Backups\Pre-Hardening-YYYYMMDD\Registry\SCHANNEL_Protocols.reg"
```

## Diagnostic Tools

### IIS Configuration Check
```powershell
# Check IIS configuration
Get-WebConfiguration -Filter "system.webServer" | Select-Object -First 10

# Check application pools
Get-IISAppPool | Format-Table Name, State, ProcessModel

# Check sites
Get-IISSite | Format-Table Name, State, Bindings
```

### Event Log Analysis
```powershell
# Check IIS logs
Get-EventLog -LogName Application -Source "IIS*" -Newest 20 | Format-Table TimeGenerated, EntryType, Message

# Check system logs
Get-EventLog -LogName System -Source "Microsoft-Windows-IIS*" -Newest 20 | Format-Table TimeGenerated, EntryType, Message
```

### Performance Analysis
```powershell
# Check performance counters
Get-Counter -Counter "\Web Service(_Total)\Current Connections" -SampleInterval 1 -MaxSamples 5

# Check memory usage
Get-Process -Name "w3wp" | Select-Object ProcessName, WorkingSet, VirtualMemorySize
```

## Common Error Codes

### HTTP Error Codes
- **400 Bad Request**: Check request filtering settings
- **401 Unauthorized**: Check authentication configuration
- **403 Forbidden**: Check file permissions and handler mappings
- **404 Not Found**: Check file extensions and handler mappings
- **500 Internal Server Error**: Check application pool and event logs

### IIS Error Codes
- **0x80070005**: Access denied - Check permissions
- **0x8007000e**: Out of memory - Check memory limits
- **0x80070032**: Not enough storage - Check disk space
- **0x80070057**: Invalid parameter - Check configuration

## Prevention

### Regular Maintenance
- Monitor event logs daily
- Check application pool health
- Verify SSL certificate expiration
- Review security configurations

### Testing Procedures
- Test in non-production first
- Verify all applications work
- Check performance impact
- Validate security compliance

### Documentation
- Keep configuration backups
- Document custom changes
- Maintain change log
- Update troubleshooting procedures

## Support Resources

### Microsoft Resources
- [IIS Troubleshooting](https://docs.microsoft.com/en-us/iis/troubleshoot/)
- [IIS Error Reference](https://docs.microsoft.com/en-us/iis/troubleshoot/diagnosing-http-errors/)
- [IIS Performance Tuning](https://docs.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/iis-performance-tuning/)

### Community Resources
- [IIS Forums](https://forums.iis.net/)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/iis)
- [Server Fault](https://serverfault.com/questions/tagged/iis)

### Log Files
- **IIS Logs**: `C:\inetpub\logs\LogFiles\`
- **Event Logs**: Event Viewer
- **Application Logs**: `C:\Windows\Logs\`
- **Hardening Logs**: `C:\Windows\Logs\CIS-IIS-Hardening-*.log`
