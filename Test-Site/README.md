# CIS Level 1 Compliance Test Suite

This test website provides comprehensive validation for CIS Level 1 compliance on IIS Web Server.

## 🎯 Purpose

The test suite validates that your IIS installation meets CIS Level 1 security benchmarks by testing:

- Security headers configuration
- Request filtering rules
- Authentication and authorization settings
- Directory and file security
- ISAPI and CGI restrictions
- Logging and monitoring
- Network security configurations

## 🌐 Access the Test Suite

**URL:** `http://localhost:8080`

## 📋 Test Categories

### 1. Security Headers Validation (6 tests)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- Content-Security-Policy

### 2. Request Filtering Tests (4 tests)
- File extension restrictions
- HTTP TRACE method blocking
- Request size limits
- URL length limits

### 3. Authentication & Authorization (3 tests)
- Anonymous authentication status
- Windows authentication
- Basic authentication (should be disabled)

### 4. Directory & File Security (3 tests)
- Directory browsing disabled
- WebDAV disabled
- Detailed errors hidden from remote users

### 5. ISAPI & CGI Restrictions (2 tests)
- ISAPI restrictions enabled
- CGI restrictions enabled

### 6. Logging & Monitoring (3 tests)
- IIS logging enabled
- W3C Extended log format
- Failed request tracing

### 7. Network Security (8 tests)
- Dynamic IP restrictions
- Firewall rules for IIS
- IP address restrictions
- Connection limits
- Rate limiting
- Geolocation filtering
- DDoS protection
- Request throttling

### 8. SSL/TLS Security (4 tests)
- SSL/TLS configuration
- Strong cipher suites
- TLS version support
- Certificate validation

### 9. Content Security (4 tests)
- Server header disclosure
- Version information hiding
- Powered-By header removal
- X-AspNet-Version header

### 10. Handler Security (4 tests)
- Handler permissions review
- Unused handlers disabled
- Dangerous extensions blocked
- Script execution restrictions

### 11. Information Disclosure (4 tests)
- Directory listing prevention
- Source code protection
- Configuration file access
- Backup file protection

### 12. Advanced Security (5 tests)
- Request validation
- View state protection
- Session security
- Cookie security
- Machine key security

**Total: 50 comprehensive security tests**

## 🔧 Server-Side Validation

For complete server-side validation, you can run the PowerShell compliance script:

```powershell
.\compliance-api.ps1
```

This script provides detailed server-side validation of IIS configuration settings.

## 📊 Understanding Results

- **PASS** ✅: Configuration meets CIS Level 1 requirements
- **FAIL** ❌: Configuration does not meet requirements
- **WARNING** ⚠️: Potential issue or requires manual verification
- **INFO** ℹ️: Informational test that requires server-side validation

## 🎯 CIS Level 1 Requirements Covered

This test suite validates compliance with the following CIS IIS Benchmark requirements:

- **1.1.1** - Disable directory browsing
- **1.1.2** - Disable WebDAV
- **1.1.3** - Configure ISAPI restrictions
- **1.1.4** - Configure CGI restrictions
- **1.1.5** - Configure file extension restrictions
- **1.1.6** - Disable HTTP TRACE method
- **1.1.7** - Configure authentication
- **1.1.8** - Enable dynamic IP restrictions
- **1.1.9** - Configure W3C extended logging
- **1.1.10** - Enable failed request tracing
- **1.1.11** - Hide detailed errors from remote users

## 🚀 Next Steps

1. **Run the test suite** to identify current compliance status
2. **Apply CIS hardening** using the main hardening script
3. **Re-run tests** to verify compliance improvements
4. **Address any remaining issues** manually

## 📝 Notes

- Some tests require server-side validation and will show as "INFO"
- The test suite provides both client-side and server-side validation
- Results are updated in real-time when you refresh the page
- All tests are designed to be non-intrusive and safe to run

---

**Created for:** CIS IIS Hardening Project  
**Version:** 1.0  
**Last Updated:** September 2025
