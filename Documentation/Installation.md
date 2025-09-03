# Installation Guide

This guide provides step-by-step instructions for installing and configuring the CIS IIS Server Hardening solution.

## Prerequisites

### System Requirements
- **Operating System**: Windows Server 2019 or Windows Server 2022
- **IIS Version**: IIS 10.0 or later
- **PowerShell**: Version 5.1 or later
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Disk Space**: At least 2GB free space for logs and backups

### Required Roles and Features
- Web Server (IIS) role
- Windows PowerShell 5.1
- .NET Framework 4.8 or later

### Permissions
- Local Administrator privileges
- IIS Manager permissions
- Registry modification rights

## Installation Steps

### 1. Download the Repository

```powershell
# Clone the repository
git clone https://github.com/spittard/cis-iis-server-hardening.git
cd cis-iis-server-hardening

# Or download as ZIP and extract
```

### 2. Verify Prerequisites

Run the prerequisite check script:

```powershell
.\Tools\Test-Prerequisites.ps1
```

This script will verify:
- Windows Server version
- IIS installation status
- PowerShell version
- Required permissions
- Available disk space

### 3. Create Backup

**Important**: Always create a backup before applying hardening:

```powershell
.\Tools\Create-Backup.ps1 -BackupPath "C:\Backups\Pre-Hardening-$(Get-Date -Format 'yyyyMMdd')"
```

### 4. Run Hardening Script

Choose your hardening level:

#### Level 1 (Recommended for most environments)
```powershell
.\IIS-Hardening-Scripts\CIS-IIS-Hardening.ps1 -HardeningLevel Level1
```

#### Level 2 (High security environments)
```powershell
.\IIS-Hardening-Scripts\CIS-IIS-Hardening.ps1 -HardeningLevel Level2
```

#### Custom Configuration
```powershell
.\IIS-Hardening-Scripts\CIS-IIS-Hardening.ps1 -HardeningLevel Custom
```

### 5. Apply Additional Policies

```powershell
.\IIS-Hardening-Scripts\Apply-IIS-Policies.ps1
```

### 6. Verify Installation

Run the compliance check:

```powershell
.\Tools\Test-Compliance.ps1
```

## Post-Installation Configuration

### 1. Review Log Files

Check the hardening logs:
- `C:\Windows\Logs\CIS-IIS-Hardening-*.log`
- `C:\Windows\Logs\Apply-IIS-Policies-*.log`

### 2. Test Web Applications

Verify that your web applications still function correctly:
- Test all web sites and applications
- Verify authentication mechanisms
- Check SSL/TLS functionality
- Test file uploads and downloads

### 3. Configure Monitoring

Set up monitoring for:
- Failed authentication attempts
- Unusual traffic patterns
- SSL/TLS certificate expiration
- Performance metrics

## Troubleshooting

### Common Issues

#### Web Application Not Loading
- Check IIS application pool status
- Verify file permissions
- Review application logs

#### SSL/TLS Issues
- Verify certificate installation
- Check SSL/TLS protocol settings
- Review security headers

#### Authentication Problems
- Verify authentication method configuration
- Check user permissions
- Review authentication logs

### Rollback Procedures

If issues occur, you can rollback changes:

```powershell
.\Tools\Rollback-Hardening.ps1 -BackupPath "C:\Backups\Pre-Hardening-YYYYMMDD"
```

## Security Considerations

### Network Security
- Ensure proper firewall rules are in place
- Use VPN or secure connections for remote administration
- Implement network segmentation

### Access Control
- Use strong passwords for all accounts
- Implement multi-factor authentication where possible
- Regularly review user permissions

### Monitoring
- Enable comprehensive logging
- Set up alerting for security events
- Regular security assessments

## Maintenance

### Regular Tasks
- Review security logs weekly
- Update SSL/TLS certificates before expiration
- Apply security updates promptly
- Regular compliance checks

### Updates
- Monitor for script updates
- Test updates in non-production first
- Maintain current backups

## Support

For issues or questions:
1. Check the troubleshooting guide
2. Review log files
3. Consult the documentation
4. Create an issue in the repository

## Next Steps

After successful installation:
1. Review the [Configuration Guide](Configuration.md)
2. Set up monitoring and alerting
3. Schedule regular compliance checks
4. Plan for regular maintenance

