# CIS IIS Hardening

A focused collection of scripts and tools for hardening Internet Information Services (IIS) according to CIS (Center for Internet Security) benchmarks and security best practices.

## 🎯 Purpose

This repository provides automated IIS hardening solutions, ensuring compliance with security best practices while maintaining operational functionality for web applications.

## 📁 Repository Structure

```
├── IIS-Hardening-Scripts/     # PowerShell scripts for IIS hardening
├── Documentation/             # Detailed guides and references
└── Tools/                     # Utility tools and analyzers
```

## 🚀 Quick Start

### Prerequisites
- Windows Server 2019/2022 with IIS installed
- PowerShell 5.1 or later
- Administrative privileges
- Internet connectivity for downloading tools

### Basic Usage

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/spittard/cis-iis-server-hardening.git
   cd cis-iis-server-hardening
   ```

2. **Run the main hardening script:**
   ```powershell
   .\IIS-Hardening-Scripts\CIS-IIS-Hardening.ps1
   ```

3. **Apply additional IIS security policies:**
   ```powershell
   .\IIS-Hardening-Scripts\Apply-IIS-Policies.ps1
   ```

## 🔧 Features

### IIS-Specific Hardening
- **Security Headers**: Configure security headers for all IIS sites
- **SSL/TLS Configuration**: Enforce strong encryption protocols
- **Request Filtering**: Implement comprehensive request filtering rules
- **Authentication**: Configure secure authentication methods
- **Logging**: Enhanced logging and monitoring configuration

### IIS Security Configuration
- **SSL/TLS Configuration**: Enforce strong encryption protocols
- **IP Restrictions**: Configure access controls and IP filtering
- **Compression Settings**: Optimize performance with secure compression
- **Caching Policies**: Implement secure caching strategies

### Automation & Monitoring
- **Automated Deployment**: One-click hardening deployment
- **Compliance Checking**: Verify hardening status
- **Rollback Capabilities**: Safe rollback procedures
- **Monitoring Scripts**: Continuous security monitoring

## 📋 Security Standards Covered

- **CIS IIS Benchmark**: Web server security configurations
- **OWASP Security Guidelines**: Web application security best practices
- **Microsoft IIS Security Recommendations**: Official Microsoft security guidance
- **NIST Cybersecurity Framework**: Security controls and guidelines

## 🛡️ Security Considerations

- All scripts include safety checks and validation
- Rollback procedures are provided for all major changes
- Scripts are designed to be idempotent (safe to run multiple times)
- Detailed logging of all changes made
- Compliance verification tools included

## 📖 Documentation

- [Installation Guide](Documentation/Installation.md)
- [IIS Hardening Reference](Documentation/IIS-Hardening-Reference.md)
- [Troubleshooting Guide](Documentation/Troubleshooting.md)
- [Security Compliance Matrix](Documentation/Security-Compliance.md)

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guidelines](Documentation/Contributing.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

These scripts modify system security settings. Always test in a non-production environment first and ensure you have proper backups before applying to production systems.

## 🔗 Related Resources

- [CIS IIS Benchmark](https://www.cisecurity.org/benchmark/iis) - Official CIS IIS documentation
- [Microsoft IIS Security](https://docs.microsoft.com/en-us/iis/security/) - Microsoft IIS security guidance
- [OWASP Web Security](https://owasp.org/www-project-web-security-testing-guide/) - Web application security testing

---

**Note**: This repository is actively maintained and updated to reflect the latest security best practices and CIS benchmark updates.