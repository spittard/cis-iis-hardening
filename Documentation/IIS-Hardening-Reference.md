# IIS Hardening Reference

This document provides a comprehensive reference for all IIS hardening configurations applied by the CIS IIS Hardening scripts.

## Security Headers Configuration

### X-Content-Type-Options
- **Setting**: `nosniff`
- **Purpose**: Prevents MIME type sniffing attacks
- **Configuration**: Applied via web.config or IIS Manager

### X-Frame-Options
- **Setting**: `DENY` or `SAMEORIGIN`
- **Purpose**: Prevents clickjacking attacks
- **Configuration**: Applied to all sites and applications

### X-XSS-Protection
- **Setting**: `1; mode=block`
- **Purpose**: Enables XSS filtering in browsers
- **Configuration**: Applied via custom headers

### Strict-Transport-Security (HSTS)
- **Setting**: `max-age=31536000; includeSubDomains; preload`
- **Purpose**: Enforces HTTPS connections
- **Configuration**: Applied to HTTPS sites only

### Referrer-Policy
- **Setting**: `strict-origin-when-cross-origin`
- **Purpose**: Controls referrer information leakage
- **Configuration**: Applied via custom headers

### Content-Security-Policy
- **Setting**: `default-src 'self'; script-src 'self' 'unsafe-inline'`
- **Purpose**: Prevents XSS and code injection attacks
- **Configuration**: Customized per application requirements

## Request Filtering Configuration

### File Extension Restrictions
- **Blocked Extensions**: `.exe`, `.bat`, `.cmd`, `.com`, `.pif`, `.scr`, `.vbs`, `.js`, `.jse`
- **Configuration**: Applied via Request Filtering module
- **Purpose**: Prevents execution of dangerous file types

### HTTP Method Restrictions
- **Blocked Methods**: `TRACE`, `DEBUG`
- **Allowed Methods**: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`
- **Configuration**: Applied via Request Filtering module

### Request Size Limits
- **Maximum Request Length**: 4096 KB
- **Maximum URL Length**: 2048 characters
- **Maximum Query String Length**: 2048 characters
- **Configuration**: Applied via Request Filtering module

### URL Length Limits
- **Maximum URL Length**: 2048 characters
- **Configuration**: Applied via Request Filtering module

## Authentication Configuration

### Anonymous Authentication
- **Status**: Disabled for sensitive applications
- **Configuration**: Applied per application
- **Purpose**: Prevents unauthorized access

### Windows Authentication
- **Status**: Enabled for internal applications
- **Configuration**: Applied per application
- **Purpose**: Provides integrated authentication

### Basic Authentication
- **Status**: Disabled (insecure)
- **Configuration**: Applied globally
- **Purpose**: Prevents credential theft

### Forms Authentication
- **Status**: Enabled for web applications
- **Configuration**: Applied per application
- **Purpose**: Provides secure authentication

## Directory and File Security

### Directory Browsing
- **Status**: Disabled
- **Configuration**: Applied globally
- **Purpose**: Prevents directory enumeration

### WebDAV
- **Status**: Disabled
- **Configuration**: Applied globally
- **Purpose**: Prevents unauthorized file access

### Detailed Error Messages
- **Status**: Hidden from remote users
- **Configuration**: Applied globally
- **Purpose**: Prevents information disclosure

## ISAPI and CGI Restrictions

### ISAPI Restrictions
- **Status**: Enabled
- **Configuration**: Applied globally
- **Purpose**: Controls ISAPI extension execution

### CGI Restrictions
- **Status**: Enabled
- **Configuration**: Applied globally
- **Purpose**: Controls CGI script execution

## Logging Configuration

### IIS Logging
- **Status**: Enabled
- **Format**: W3C Extended Log Format
- **Configuration**: Applied globally
- **Purpose**: Provides comprehensive audit trail

### Failed Request Tracing
- **Status**: Enabled
- **Configuration**: Applied globally
- **Purpose**: Helps diagnose application issues

### Log File Settings
- **Location**: `C:\inetpub\logs\LogFiles\`
- **Rotation**: Daily
- **Retention**: 30 days
- **Configuration**: Applied globally

## SSL/TLS Configuration

### Protocol Versions
- **TLS 1.2**: Enabled
- **TLS 1.3**: Enabled (if available)
- **SSL 2.0**: Disabled
- **SSL 3.0**: Disabled
- **TLS 1.0**: Disabled
- **TLS 1.1**: Disabled

### Cipher Suites
- **AES 256**: Enabled
- **AES 128**: Enabled
- **3DES**: Disabled
- **RC4**: Disabled
- **NULL**: Disabled

### Certificate Configuration
- **Key Length**: Minimum 2048 bits
- **Hash Algorithm**: SHA-256 or higher
- **Configuration**: Applied per site

## Network Security

### Dynamic IP Restrictions
- **Status**: Enabled
- **Configuration**: Applied globally
- **Purpose**: Prevents brute force attacks

### Connection Limits
- **Maximum Connections**: 1000
- **Connection Timeout**: 120 seconds
- **Configuration**: Applied globally

### Rate Limiting
- **Requests per Second**: 100
- **Burst Size**: 200
- **Configuration**: Applied globally

## Content Security

### Server Header
- **Status**: Hidden
- **Configuration**: Applied globally
- **Purpose**: Prevents information disclosure

### X-Powered-By Header
- **Status**: Removed
- **Configuration**: Applied globally
- **Purpose**: Prevents information disclosure

### X-AspNet-Version Header
- **Status**: Removed
- **Configuration**: Applied globally
- **Purpose**: Prevents information disclosure

## Handler Security

### Handler Permissions
- **Read**: Enabled for static content
- **Execute**: Restricted to specific handlers
- **Configuration**: Applied per handler
- **Purpose**: Prevents unauthorized execution

### Unused Handlers
- **Status**: Disabled
- **Configuration**: Applied globally
- **Purpose**: Reduces attack surface

### Dangerous Extensions
- **Blocked**: `.exe`, `.bat`, `.cmd`, `.com`, `.pif`, `.scr`, `.vbs`
- **Configuration**: Applied via Request Filtering
- **Purpose**: Prevents code execution

## Advanced Security

### Request Validation
- **Status**: Enabled
- **Configuration**: Applied globally
- **Purpose**: Prevents injection attacks

### View State Protection
- **Status**: Enabled
- **Configuration**: Applied per application
- **Purpose**: Prevents tampering

### Session Security
- **Timeout**: 20 minutes
- **Secure Cookies**: Enabled
- **HttpOnly Cookies**: Enabled
- **Configuration**: Applied globally

### Machine Key Security
- **Validation**: SHA-256
- **Decryption**: AES-256
- **Configuration**: Applied globally

## Registry Modifications

### SCHANNEL Protocol Settings
- **Location**: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`
- **Purpose**: Disables weak SSL/TLS protocols
- **Configuration**: Applied via registry modifications

### SCHANNEL Cipher Settings
- **Location**: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers`
- **Purpose**: Disables weak cipher suites
- **Configuration**: Applied via registry modifications

## Firewall Rules

### Inbound Rules
- **HTTP**: Port 80 (if needed)
- **HTTPS**: Port 443
- **Management**: Port 8172 (Web Deploy)
- **Configuration**: Applied via Windows Firewall

### Outbound Rules
- **HTTPS**: Port 443 (for updates)
- **DNS**: Port 53
- **Configuration**: Applied via Windows Firewall

## Performance Optimizations

### Compression
- **Status**: Enabled
- **Types**: GZIP, DEFLATE
- **Configuration**: Applied globally
- **Purpose**: Improves performance

### Caching
- **Static Content**: 1 year
- **Dynamic Content**: 1 hour
- **Configuration**: Applied per content type
- **Purpose**: Improves performance

### Output Caching
- **Status**: Enabled
- **Configuration**: Applied per application
- **Purpose**: Reduces server load

## Monitoring and Alerting

### Event Log Monitoring
- **Sources**: IIS, Security, Application
- **Levels**: Error, Warning, Information
- **Configuration**: Applied via Event Log subscriptions

### Performance Monitoring
- **Metrics**: CPU, Memory, Disk, Network
- **Thresholds**: Configurable
- **Configuration**: Applied via Performance Monitor

### Security Monitoring
- **Failed Logins**: Alert after 5 attempts
- **Unusual Traffic**: Alert on spikes
- **Configuration**: Applied via custom scripts

## Compliance Verification

### CIS Benchmark Compliance
- **Level 1**: Basic security controls
- **Level 2**: Advanced security controls
- **Configuration**: Verified via compliance scripts

### Regular Audits
- **Frequency**: Monthly
- **Scope**: All security configurations
- **Configuration**: Automated via scheduled tasks

## Troubleshooting

### Common Issues
- **Web Application Errors**: Check handler mappings
- **Authentication Failures**: Verify authentication settings
- **SSL/TLS Issues**: Check certificate and protocol settings
- **Performance Issues**: Review compression and caching settings

### Diagnostic Tools
- **IIS Manager**: Configuration verification
- **Event Viewer**: Error investigation
- **Performance Monitor**: Performance analysis
- **Network Monitor**: Traffic analysis

## Maintenance

### Regular Tasks
- **Log Review**: Weekly
- **Certificate Renewal**: Before expiration
- **Security Updates**: Monthly
- **Compliance Checks**: Monthly

### Backup Procedures
- **Configuration Backup**: Before changes
- **Certificate Backup**: Before renewal
- **Log Backup**: Monthly
- **Application Backup**: As needed

## References

- [CIS IIS Benchmark](https://www.cisecurity.org/benchmark/iis)
- [Microsoft IIS Security](https://docs.microsoft.com/en-us/iis/security/)
- [OWASP Web Security](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
